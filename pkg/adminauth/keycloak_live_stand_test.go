//go:build integration

package adminauth

// Live-IdP stand for the N04 packets: a disposable local Keycloak in Docker
// (owner decision 2026-10 — the local Keycloak stand is the approved "Real
// IdP flow" evidence for N04-P01 T02/T06 and N04-P02 T06).
//
// Isolation: one container per test binary, a pinned image, a random host
// port (testcontainers mapping) and a unique realm name per run (the realm
// template's __KC_REALM__ is rewritten before import). Nothing outside the
// container is touched; the container dies with the test process via the
// testcontainers reaper.
//
// Skip discipline: a missing Docker daemon is a clean SKIP with an explicit
// reason — never a silent pass. A started stand that fails (bad import,
// timeout, admin API error) is a hard test failure.

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
)

// kcLiveImage is pinned by digest (the 26.4.2 manifest list at validation
// time, 2026-10): a tag can be re-pointed upstream, the digest cannot, so
// every run executes the exact bits this evidence was produced against.
// 26.0.x is deliberately avoided: its bundled JDK 21.0.5+11 dies with SIGILL
// under this Docker VM's arm64 virtualization (JDK-8343123 family); 26.4.2
// (JDK 21.0.9) runs cleanly.
const kcLiveImage = "quay.io/keycloak/keycloak@sha256:3617b09bb4b7510a8d8d9b9fc5707399e2d70688dbcc2f8fb013a144829be1b9"

const (
	kcAdminUser = "admin"
	kcAdminPass = "n04-live-bootstrap"

	// The OIDC client configured by the committed realm template
	// (testdata/keycloak/n04-realm.json).
	KCLiveOIDCClientID     = "yabanin-admin"
	KCLiveOIDCClientSecret = "n04-live-admin-secret"

	// The SAML client is the only saml-protocol client in the realm; the
	// stand patches its entity ID / ACS per run (the console port is random).
	kcSAMLClientMarkerName = "yabanin admin console SAML SP (N04 live test)"
)

// KCStand is the running Keycloak container plus the admin-API surface the
// live tests need (key rotation, client patches, user/group edits).
type KCStand struct {
	Container testcontainers.Container
	BaseURL   string // http://127.0.0.1:<mapped port>
	Realm     string
	RealmURL  string // BaseURL + /realms/<realm>

	http *http.Client

	adminMu     sync.Mutex
	adminTokenV string
}

var (
	kcStandOnce   sync.Once
	kcStand       *KCStand
	kcStandErr    error
	kcStandCloser func()
)

// KeycloakLiveStand starts (once per test binary) the disposable Keycloak
// stand and imports the committed realm template under a unique realm name.
// Skips cleanly when the Docker daemon is unreachable; a stand that starts
// but fails is a hard error.
func KeycloakLiveStand(tb testing.TB) *KCStand {
	tb.Helper()
	kcStandOnce.Do(func() {
		if err := kcDockerAvailable(); err != nil {
			kcStandErr = errSkipDocker{err}
			return
		}
		st, closer, err := kcStartStand()
		if err != nil {
			kcStandErr = err
			return
		}
		kcStand, kcStandCloser = st, closer
	})
	if kcStandErr != nil {
		var skip errSkipDocker
		if errors.As(kcStandErr, &skip) {
			tb.Skipf("keycloak live stand skipped: %v", kcStandErr)
		}
		tb.Fatalf("keycloak live stand failed: %v", kcStandErr)
		return nil
	}
	// No per-test cleanup: the stand is shared across the whole test binary
	// (same discipline as testdb.Postgres) and the testcontainers reaper
	// terminates the container when the process exits. Terminating on the
	// first caller's cleanup would kill the stand under the later tests.
	return kcStand
}

// errSkipDocker marks an environment condition that warrants a clean skip.
type errSkipDocker struct{ cause error }

func (e errSkipDocker) Error() string {
	return "Docker daemon unavailable (is Docker running?): " + e.cause.Error()
}

func kcDockerAvailable() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "version", "--format", "{{.Server.Version}}")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func kcStartStand() (*KCStand, func(), error) {
	ctx := context.Background()

	realm := "n04-live-" + strings.ToLower(randomHexOrDie(4))
	realmPath, err := kcWriteRealmFile(realm)
	if err != nil {
		return nil, nil, err
	}

	req := testcontainers.ContainerRequest{
		Image:        kcLiveImage,
		ExposedPorts: []string{"8080/tcp"},
		Env: map[string]string{
			"KC_BOOTSTRAP_ADMIN_USERNAME": kcAdminUser,
			"KC_BOOTSTRAP_ADMIN_PASSWORD": kcAdminPass,
		},
		Cmd: []string{"start-dev", "--import-realm"},
		Files: []testcontainers.ContainerFile{{
			HostFilePath: realmPath,
			// Keycloak's directory import provider requires the file name to
			// be <realm>-realm.json — the unique per-run realm name.
			ContainerFilePath: "/opt/keycloak/data/import/" + realm + "-realm.json",
			FileMode:          0o644,
		}},
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("start keycloak container (image %s): %w", kcLiveImage, err)
	}
	host, err := container.Host(ctx)
	if err != nil {
		_ = container.Terminate(ctx)
		return nil, nil, err
	}
	port, err := container.MappedPort(ctx, "8080/tcp")
	if err != nil {
		_ = container.Terminate(ctx)
		return nil, nil, err
	}
	stand := &KCStand{
		Container: container,
		BaseURL:   "http://" + net.JoinHostPort(host, port.Port()),
		Realm:     realm,
		RealmURL:  "http://" + net.JoinHostPort(host, port.Port()) + "/realms/" + realm,
		http: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				// The stand talks to loopback over plain http only.
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test stand on loopback
			},
		},
	}
	if err := stand.awaitRealm(ctx, 4*time.Minute); err != nil {
		_ = container.Terminate(ctx)
		return nil, nil, err
	}
	closer := func() { _ = container.Terminate(ctx) }
	return stand, closer, nil
}

// randomHexOrDie wraps the package's crypto/rand hex helper for stand IDs.
func randomHexOrDie(n int) string {
	hex, err := randomHex(n)
	if err != nil {
		panic(err) // crypto/rand exhaustion is not a test scenario
	}
	return hex
}

// kcWriteRealmFile materializes the committed realm template with a unique
// realm name (import-time isolation) into a temp file.
func kcWriteRealmFile(realm string) (string, error) {
	raw, err := os.ReadFile(filepath.Join("testdata", "keycloak", "n04-realm.json"))
	if err != nil {
		return "", fmt.Errorf("read committed realm template: %w", err)
	}
	rewritten := strings.ReplaceAll(string(raw), "__KC_REALM__", realm)
	dir, err := os.MkdirTemp("", "n04-keycloak-realm-")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "n04-realm.json")
	if err := os.WriteFile(path, []byte(rewritten), 0o600); err != nil { //nolint:gosec // G306: realm fixture, no secrets beyond throwaway test credentials
		return "", err
	}
	return path, nil
}

func (s *KCStand) awaitRealm(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	u := s.RealmURL + "/.well-known/openid-configuration"
	for {
		resp, err := s.http.Get(u)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		if time.Now().After(deadline) {
			if err != nil {
				return fmt.Errorf("keycloak realm %s never became ready: %w", s.Realm, err)
			}
			return fmt.Errorf("keycloak realm %s never became ready (last status %d)", s.Realm, resp.StatusCode)
		}
		time.Sleep(time.Second)
	}
}

// ---- admin REST surface ------------------------------------------------------

type kcAdminCall struct {
	method      string
	path        string // absolute path on BaseURL
	body        any
	contentType string
}

func (s *KCStand) admin(ctx context.Context, call kcAdminCall) ([]byte, error) {
	for attempt := 0; attempt < 2; attempt++ {
		token, err := s.adminToken(ctx)
		if err != nil {
			return nil, err
		}
		var rdr io.Reader
		if call.body != nil {
			raw, err := json.Marshal(call.body)
			if err != nil {
				return nil, err
			}
			rdr = strings.NewReader(string(raw))
		}
		req, err := http.NewRequestWithContext(ctx, call.method, s.BaseURL+call.path, rdr)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		if call.body != nil {
			ct := call.contentType
			if ct == "" {
				ct = "application/json"
			}
			req.Header.Set("Content-Type", ct)
		}
		resp, err := s.http.Do(req)
		if err != nil {
			return nil, err
		}
		raw, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			// token expired mid-run: force a re-login and retry once
			s.adminMu.Lock()
			s.adminTokenV = ""
			s.adminMu.Unlock()
			continue
		}
		if resp.StatusCode >= 300 {
			return raw, fmt.Errorf("admin %s %s: status %d: %s", call.method, call.path, resp.StatusCode, kcTruncate(raw))
		}
		return raw, nil
	}
	return nil, fmt.Errorf("admin %s %s: unauthorized after re-login", call.method, call.path)
}

func (s *KCStand) adminToken(ctx context.Context) (string, error) {
	s.adminMu.Lock()
	defer s.adminMu.Unlock()
	if s.adminTokenV != "" {
		return s.adminTokenV, nil
	}
	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {"admin-cli"},
		"username":   {kcAdminUser},
		"password":   {kcAdminPass},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.BaseURL+"/realms/master/protocol/openid-connect/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("admin bootstrap token: status %d: %s", resp.StatusCode, kcTruncate(raw))
	}
	var parsed struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil || parsed.AccessToken == "" {
		return "", fmt.Errorf("admin bootstrap token: unparsable response")
	}
	s.adminTokenV = parsed.AccessToken
	return s.adminTokenV, nil
}

func kcTruncate(b []byte) string {
	s := string(b)
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// ---- realm key rotation (N04-P01 T02 / N04-P02 T06) ---------------------------

// KCRSAKey is one RS256 signing key of the realm as reported by the admin
// keys endpoint. ProviderID is the org.keycloak.keys.KeyProvider component
// UUID; KID is the published key id.
type KCRSAKey struct {
	KID        string
	ProviderID string
	Priority   int
	Status     string
}

// RSAKeyProviders lists the realm's active RS256 signing keys.
func (s *KCStand) RSAKeyProviders(ctx context.Context) ([]KCRSAKey, error) {
	raw, err := s.admin(ctx, kcAdminCall{method: http.MethodGet, path: "/admin/realms/" + s.Realm + "/keys"})
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Keys []struct {
			KID              string `json:"kid"`
			Algorithm        string `json:"algorithm"`
			ProviderID       string `json:"providerId"`
			ProviderPriority int    `json:"providerPriority"`
			Status           string `json:"status"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, err
	}
	var out []KCRSAKey
	for _, k := range parsed.Keys {
		if k.Algorithm != "RS256" {
			continue
		}
		out = append(out, KCRSAKey{KID: k.KID, ProviderID: k.ProviderID, Priority: k.ProviderPriority, Status: k.Status})
	}
	return out, nil
}

// PrimaryRSAPriority returns the priority of the highest-priority RS256
// signing key (the one Keycloak currently signs with).
func (s *KCStand) PrimaryRSAPriority(ctx context.Context) (int, error) {
	keys, err := s.RSAKeyProviders(ctx)
	if err != nil {
		return 0, err
	}
	if len(keys) == 0 {
		return 0, fmt.Errorf("realm %s has no RS256 signing key", s.Realm)
	}
	top := keys[0]
	for _, k := range keys[1:] {
		if k.Priority > top.Priority {
			top = k
		}
	}
	return top.Priority, nil
}

// kcKeyComponent is one org.keycloak.keys.KeyProvider component.
type kcKeyComponent struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	ProviderID string `json:"providerId"`
}

func (s *KCStand) keyComponentByName(ctx context.Context, name string) (kcKeyComponent, error) {
	raw, err := s.admin(ctx, kcAdminCall{method: http.MethodGet, path: "/admin/realms/" + s.Realm + "/components?providerType=org.keycloak.keys.KeyProvider"})
	if err != nil {
		return kcKeyComponent{}, err
	}
	var components []kcKeyComponent
	if err := json.Unmarshal(raw, &components); err != nil {
		return kcKeyComponent{}, err
	}
	for _, c := range components {
		if c.Name == name {
			return c, nil
		}
	}
	return kcKeyComponent{}, fmt.Errorf("key provider %q not found in realm %s", name, s.Realm)
}

// AddRSAKeyProvider creates a second realm RSA signing key with the given
// priority. While both providers are enabled+active, Keycloak publishes BOTH
// signing certificates (JWKS and SAML metadata) — the dual-trust window —
// and the higher-priority key does the signing.
func (s *KCStand) AddRSAKeyProvider(ctx context.Context, name string, priority int) error {
	body := map[string]any{
		"name":         name,
		"providerId":   "rsa-generated",
		"providerType": "org.keycloak.keys.KeyProvider",
		"config": map[string]any{
			"priority":  []string{fmt.Sprint(priority)},
			"enabled":   []string{"true"},
			"active":    []string{"true"},
			"keySize":   []string{"2048"},
			"algorithm": []string{"RS256"},
		},
	}
	_, err := s.admin(ctx, kcAdminCall{method: http.MethodPost, path: "/admin/realms/" + s.Realm + "/components", body: body})
	return err
}

// SetRSAKeyPriority rewrites a provider's priority (the signer is the
// highest-priority active key).
func (s *KCStand) SetRSAKeyPriority(ctx context.Context, name string, priority int) error {
	prov, err := s.keyComponentByName(ctx, name)
	if err != nil {
		return err
	}
	body := map[string]any{
		"name":         prov.Name,
		"providerId":   prov.ProviderID,
		"providerType": "org.keycloak.keys.KeyProvider",
		"config": map[string]any{
			"priority":  []string{fmt.Sprint(priority)},
			"enabled":   []string{"true"},
			"active":    []string{"true"},
			"keySize":   []string{"2048"},
			"algorithm": []string{"RS256"},
		},
	}
	_, err = s.admin(ctx, kcAdminCall{method: http.MethodPut, path: "/admin/realms/" + s.Realm + "/components/" + prov.ID, body: body})
	return err
}

// DeleteRSAKeyProvider removes a key provider — the IdP stops publishing the
// certificate (JWKS and SAML metadata) and never signs with it again.
func (s *KCStand) DeleteRSAKeyProvider(ctx context.Context, name string) error {
	prov, err := s.keyComponentByName(ctx, name)
	if err != nil {
		return err
	}
	_, err = s.admin(ctx, kcAdminCall{method: http.MethodDelete, path: "/admin/realms/" + s.Realm + "/components/" + prov.ID})
	return err
}

// JWKSKids returns the kid values the realm currently publishes (OIDC JWKS).
func (s *KCStand) JWKSKids(ctx context.Context) ([]string, error) {
	resp, err := s.http.Get(s.RealmURL + "/protocol/openid-connect/certs")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var parsed struct {
		Keys []struct {
			KID string `json:"kid"`
			Alg string `json:"alg"`
			Use string `json:"use"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}
	var kids []string
	for _, k := range parsed.Keys {
		if k.Use == "sig" || k.Use == "" {
			kids = append(kids, k.KID)
		}
	}
	return kids, nil
}

// SAMLSigningCertCount counts the signing KeyDescriptors in the realm's SAML
// metadata — during rotation Keycloak publishes BOTH certificates here.
func (s *KCStand) SAMLSigningCertCount(ctx context.Context) (int, error) {
	resp, err := s.http.Get(s.RealmURL + "/protocol/saml/descriptor")
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}
	return strings.Count(string(raw), `KeyDescriptor use="signing"`), nil
}

// ---- SAML client + user/group admin operations --------------------------------

// ConfigureSAMLClient re-points the realm's SAML client at the live console:
// entity ID (clientId) and ACS URL. Idempotent across calls.
func (s *KCStand) ConfigureSAMLClient(ctx context.Context, entityID, acsURL string) error {
	raw, err := s.admin(ctx, kcAdminCall{method: http.MethodGet, path: "/admin/realms/" + s.Realm + "/clients?max=500"})
	if err != nil {
		return err
	}
	var clients []map[string]any
	if err := json.Unmarshal(raw, &clients); err != nil {
		return err
	}
	var target map[string]any
	for _, c := range clients {
		if c["protocol"] == "saml" && c["name"] == kcSAMLClientMarkerName {
			target = c
			break
		}
	}
	if target == nil {
		return fmt.Errorf("SAML client %q not found in realm %s", kcSAMLClientMarkerName, s.Realm)
	}
	id := fmt.Sprint(target["id"])
	attrs, _ := target["attributes"].(map[string]any)
	attrs["saml_assertion_consumer_url_post"] = acsURL
	attrs["saml_assertion_consumer_url_redirect"] = acsURL
	target["clientId"] = entityID
	target["redirectUris"] = []string{acsURL}
	target["attributes"] = attrs
	_, err = s.admin(ctx, kcAdminCall{method: http.MethodPut, path: "/admin/realms/" + s.Realm + "/clients/" + id, body: target})
	return err
}

// SetSAMLSignFlags toggles the client's document/assertion signing (the
// unsigned-response negative). Restored by the caller.
func (s *KCStand) SetSAMLSignFlags(ctx context.Context, documents, assertions bool) error {
	raw, err := s.admin(ctx, kcAdminCall{method: http.MethodGet, path: "/admin/realms/" + s.Realm + "/clients?max=500"})
	if err != nil {
		return err
	}
	var clients []map[string]any
	if err := json.Unmarshal(raw, &clients); err != nil {
		return err
	}
	var target map[string]any
	for _, c := range clients {
		if c["protocol"] == "saml" && c["name"] == kcSAMLClientMarkerName {
			target = c
			break
		}
	}
	if target == nil {
		return fmt.Errorf("SAML client not found in realm %s", s.Realm)
	}
	id := fmt.Sprint(target["id"])
	attrs, _ := target["attributes"].(map[string]any)
	attrs["saml.server.signature"] = fmt.Sprint(documents)
	attrs["saml.assertion.signature"] = fmt.Sprint(assertions)
	target["attributes"] = attrs
	_, err = s.admin(ctx, kcAdminCall{method: http.MethodPut, path: "/admin/realms/" + s.Realm + "/clients/" + id, body: target})
	return err
}

// EnsureOIDCClient creates (or patches in place) a confidential
// standard-flow OIDC client in the NAMED realm. The compat suite needs a
// second per-consumer client (a distinct audience on the same realm) and a
// client in the MASTER realm (a real foreign-issuer token); the stand's own
// admin-cli login is deliberately never touched. An existing client is
// updated via PUT with the full representation, so secret and redirect URIs
// are always exactly as requested.
func (s *KCStand) EnsureOIDCClient(ctx context.Context, realm, clientID, secret string, redirectURIs []string) error {
	repr := map[string]any{
		"clientId":            clientID,
		"enabled":             true,
		"protocol":            "openid-connect",
		"publicClient":        false,
		"secret":              secret,
		"standardFlowEnabled": true,
		"redirectUris":        redirectURIs,
	}
	raw, err := s.admin(ctx, kcAdminCall{
		method: http.MethodGet,
		path:   "/admin/realms/" + realm + "/clients?clientId=" + url.QueryEscape(clientID),
	})
	if err != nil {
		return err
	}
	var found []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &found); err != nil {
		return err
	}
	if len(found) == 0 {
		_, err := s.admin(ctx, kcAdminCall{method: http.MethodPost, path: "/admin/realms/" + realm + "/clients", body: repr})
		return err
	}
	repr["id"] = found[0].ID
	_, err = s.admin(ctx, kcAdminCall{method: http.MethodPut, path: "/admin/realms/" + realm + "/clients/" + found[0].ID, body: repr})
	return err
}

// DeleteOIDCClient removes a client by clientId from the named realm
// (absent = success, so cleanup stays idempotent).
func (s *KCStand) DeleteOIDCClient(ctx context.Context, realm, clientID string) error {
	raw, err := s.admin(ctx, kcAdminCall{
		method: http.MethodGet,
		path:   "/admin/realms/" + realm + "/clients?clientId=" + url.QueryEscape(clientID),
	})
	if err != nil {
		return err
	}
	var found []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &found); err != nil {
		return err
	}
	if len(found) == 0 {
		return nil
	}
	_, err = s.admin(ctx, kcAdminCall{method: http.MethodDelete, path: "/admin/realms/" + realm + "/clients/" + found[0].ID})
	return err
}

// BootstrapAdminCredentials returns the master-realm bootstrap admin login
// (committed throwaway stand credentials). The foreign-issuer compat cell
// performs a real login for the bootstrap admin through a dedicated master
// realm client; the admin-API token path itself is never shared.
func (s *KCStand) BootstrapAdminCredentials() (username, password string) {
	return kcAdminUser, kcAdminPass
}

// EnsureRealmUser idempotently provisions a realm user with an email, a
// verified address, a display name and a password. The display name is not
// cosmetic: with the default user profile, users WITHOUT firstName/lastName
// are handed Keycloak's VERIFY_PROFILE required action on first login
// (imported users carry names and skip it), which stalls the test browsers
// mid-flow. Suites that admit developers through the portal bring their OWN
// identities: portal provisioning binds a developer row to the FIRST portal
// org that admits it (the row is global per email), so shared users must
// keep their original lifecycle semantics.
func (s *KCStand) EnsureRealmUser(ctx context.Context, username, name, email, password string) error {
	first, last := name, ""
	if i := strings.IndexByte(name, ' '); i > 0 {
		first, last = name[:i], name[i+1:]
	}
	rep := map[string]any{
		"email": email, "enabled": true, "emailVerified": true,
		"firstName": first, "lastName": last, "requiredActions": []string{},
	}
	if id, err := s.userID(ctx, username); err == nil {
		if _, err := s.admin(ctx, kcAdminCall{method: http.MethodPut, path: "/admin/realms/" + s.Realm + "/users/" + id, body: rep}); err != nil {
			return err
		}
		return s.resetUserPassword(ctx, id, password)
	}
	rep["username"] = username
	rep["credentials"] = []map[string]any{{"type": "password", "value": password, "temporary": false}}
	_, err := s.admin(ctx, kcAdminCall{method: http.MethodPost, path: "/admin/realms/" + s.Realm + "/users", body: rep})
	return err
}

func (s *KCStand) resetUserPassword(ctx context.Context, userID, password string) error {
	_, err := s.admin(ctx, kcAdminCall{method: http.MethodPut, path: "/admin/realms/" + s.Realm + "/users/" + userID + "/reset-password", body: map[string]any{
		"type": "password", "value": password, "temporary": false,
	}})
	return err
}

// AddUserToGroup / RemoveUserFromGroup edit a user's real IdP group
// memberships mid-test (the deny-wins phase changes groups between logins).
func (s *KCStand) AddUserToGroup(ctx context.Context, username, group string) error {
	return s.editUserGroup(ctx, http.MethodPut, username, group)
}

func (s *KCStand) RemoveUserFromGroup(ctx context.Context, username, group string) error {
	return s.editUserGroup(ctx, http.MethodDelete, username, group)
}

func (s *KCStand) editUserGroup(ctx context.Context, method, username, group string) error {
	userID, err := s.userID(ctx, username)
	if err != nil {
		return err
	}
	groupID, err := s.groupID(ctx, group)
	if err != nil {
		return err
	}
	_, err = s.admin(ctx, kcAdminCall{method: method, path: "/admin/realms/" + s.Realm + "/users/" + userID + "/groups/" + groupID})
	return err
}

func (s *KCStand) userID(ctx context.Context, username string) (string, error) {
	raw, err := s.admin(ctx, kcAdminCall{method: http.MethodGet, path: "/admin/realms/" + s.Realm + "/users?username=" + url.QueryEscape(username) + "&exact=true&max=2"})
	if err != nil {
		return "", err
	}
	var users []map[string]any
	if err := json.Unmarshal(raw, &users); err != nil {
		return "", err
	}
	if len(users) == 0 {
		return "", fmt.Errorf("user %q not found in realm %s", username, s.Realm)
	}
	return fmt.Sprint(users[0]["id"]), nil
}

func (s *KCStand) groupID(ctx context.Context, group string) (string, error) {
	raw, err := s.admin(ctx, kcAdminCall{method: http.MethodGet, path: "/admin/realms/" + s.Realm + "/groups?search=" + url.QueryEscape(group) + "&max=200"})
	if err != nil {
		return "", err
	}
	var groups []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Path string `json:"path"`
	}
	if err := json.Unmarshal(raw, &groups); err != nil {
		return "", err
	}
	for _, g := range groups {
		if g.Name == group || g.Path == "/"+group {
			return g.ID, nil
		}
	}
	return "", fmt.Errorf("group %q not found in realm %s", group, s.Realm)
}

// ---- browser-equivalent client -------------------------------------------------

// KCCookieJar is the localhost-trust cookie jar keyed by host:port: it
// accepts Secure cookies over plain http (browsers treat loopback as a
// trustworthy context) and keeps the Keycloak and console cookie spaces
// apart (different ports), which a hostname-only jar would merge.
type KCCookieJar struct {
	mu    sync.Mutex
	store map[string]map[string]http.Cookie // host:port -> name -> cookie
}

func NewKCCookieJar() *KCCookieJar {
	return &KCCookieJar{store: map[string]map[string]http.Cookie{}}
}

func (j *KCCookieJar) bucket(host string) map[string]http.Cookie {
	if _, ok := j.store[host]; !ok {
		j.store[host] = map[string]http.Cookie{}
	}
	return j.store[host]
}

func (j *KCCookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	b := j.bucket(u.Host)
	for _, c := range cookies {
		if c.MaxAge < 0 || c.Value == "" {
			delete(b, c.Name)
			continue
		}
		b[c.Name] = *c
	}
}

func (j *KCCookieJar) Cookies(u *url.URL) []*http.Cookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	var out []*http.Cookie
	for _, c := range j.bucket(u.Host) {
		if c.Path != "" && c.Path != "/" && !strings.HasPrefix(u.Path, c.Path) {
			continue
		}
		cp := c
		out = append(out, &cp)
	}
	return out
}

// SetInjected plants a cookie as if the browser had received it earlier.
func (j *KCCookieJar) SetInjected(u *url.URL, c http.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.bucket(u.Host)[c.Name] = c
}

// Cookie returns the named cookie for the URL's host ("" when absent).
func (j *KCCookieJar) Cookie(u *url.URL, name string) string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.bucket(u.Host)[name].Value
}

// Delete drops one cookie (used to simulate a lost flow cookie).
func (j *KCCookieJar) Delete(u *url.URL, name string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	delete(j.bucket(u.Host), name)
}

// KCBrowser is the test's stand-in for the operator's browser: hop-by-hop
// redirects, Keycloak login-form submission, and detection of the SAML
// auto-submit response form.
type KCBrowser struct {
	Client *http.Client
	Jar    *KCCookieJar
}

func NewKCBrowser() *KCBrowser {
	jar := NewKCCookieJar()
	return &KCBrowser{
		Jar: jar,
		Client: &http.Client{
			Jar: jar,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse // hop-by-hop control
			},
		},
	}
}

// KCHop is one HTTP step of a driven flow.
type KCHop struct {
	URL      string
	Status   int
	Location string
	Body     string
}

// DriveSSO walks a provider flow from startURL: follows redirects; when the
// Keycloak login form appears it submits username/password once; it stops
// (without fetching) when a redirect target starts with stopPrefix, or when
// the page carries the SAML response form. The returned hops include the
// final observed hop.
func (b *KCBrowser) DriveSSO(tb testing.TB, startURL, username, password, stopPrefix string) []KCHop {
	tb.Helper()
	var hops []KCHop
	current := startURL
	for i := 0; i < 16; i++ {
		resp, err := b.Client.Get(current)
		if err != nil {
			tb.Fatalf("drive %s: %v", current, err)
		}
		body := kcReadAll(tb, resp)
		hop := KCHop{URL: current, Status: resp.StatusCode, Location: resp.Header.Get("Location"), Body: body}
		hops = append(hops, hop)

		if hop.Status == http.StatusFound || hop.Status == http.StatusMovedPermanently || hop.Status == http.StatusSeeOther {
			next := hop.Location
			if stopPrefix != "" && strings.HasPrefix(next, stopPrefix) {
				return hops
			}
			current = next
			continue
		}
		if hop.Status == http.StatusOK && strings.Contains(hop.Body, `name="SAMLResponse"`) {
			return hops // IdP response form reached
		}
		if hop.Status == http.StatusOK && strings.Contains(hop.Body, "kc-form-login") {
			action := kcFormAction(hop.Body, "kc-form-login")
			if action == "" {
				tb.Fatalf("login form without an action at %s", current)
			}
			form := url.Values{"username": {username}, "password": {password}, "credentialId": {""}}
			resp, err := b.Client.Post(action, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
			if err != nil {
				tb.Fatalf("login form POST: %v", err)
			}
			body := kcReadAll(tb, resp)
			hop := KCHop{URL: action, Status: resp.StatusCode, Location: resp.Header.Get("Location"), Body: body}
			hops = append(hops, hop)
			if hop.Status == http.StatusFound {
				next := hop.Location
				if stopPrefix != "" && strings.HasPrefix(next, stopPrefix) {
					return hops
				}
				current = next
				continue
			}
			if hop.Status == http.StatusOK && strings.Contains(hop.Body, `name="SAMLResponse"`) {
				return hops
			}
			tb.Fatalf("credential POST at %s did not progress (status %d): %s", action, hop.Status, kcSnippet(hop.Body))
		}
		tb.Fatalf("drive stalled at %s (status %d): %s", current, hop.Status, kcSnippet(hop.Body))
	}
	tb.Fatalf("drive exceeded 16 hops starting at %s", startURL)
	return nil
}

// SAMLOffer is the IdP's auto-submitting POST-binding response form.
type SAMLOffer struct {
	PostURL      string
	SAMLResponse string // still base64-encoded, form-ready
}

// SAMLOffer extracts the response form from the last hop (must be the
// auto-submit page).
func (b *KCBrowser) SAMLOffer(tb testing.TB, hops []KCHop) SAMLOffer {
	tb.Helper()
	last := hops[len(hops)-1]
	if !strings.Contains(last.Body, `name="SAMLResponse"`) {
		tb.Fatalf("no SAML response form on the final hop (%s %d): %s", last.URL, last.Status, kcSnippet(last.Body))
	}
	action := kcFormAction(last.Body, "saml-post-binding")
	if action == "" {
		// fall back to the first form on the page
		action = kcFormAction(last.Body, "")
	}
	value := kcFormInputValue(last.Body, "SAMLResponse")
	if action == "" || value == "" {
		tb.Fatalf("SAML response form incomplete at %s", last.URL)
	}
	return SAMLOffer{PostURL: action, SAMLResponse: value}
}

func kcReadAll(tb testing.TB, resp *http.Response) string {
	tb.Helper()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		tb.Fatalf("read body: %v", err)
	}
	resp.Body.Close()
	return string(raw)
}

// kcFormAction extracts a form's action URL; formID "" picks the first form.
func kcFormAction(page, formID string) string {
	for _, f := range strings.Split(page, "<form")[1:] {
		chunk, _, _ := strings.Cut(f, "</form>")
		if formID != "" && !kcAttrIs(chunk, "id", formID) {
			continue
		}
		if a := regexp.MustCompile(`action="([^"]+)"`).FindStringSubmatch(chunk); a != nil {
			return htmlUnescapeAttr(a[1])
		}
	}
	return ""
}

// kcFormInputValue extracts a named hidden input's value (attribute order
// agnostic).
func kcFormInputValue(page, name string) string {
	for _, inp := range regexp.MustCompile(`<input[^>]*>`).FindAllString(page, -1) {
		if !kcAttrIs(inp, "name", name) {
			continue
		}
		if v := regexp.MustCompile(`value="([^"]*)"`).FindStringSubmatch(inp); v != nil {
			return htmlUnescapeAttr(v[1])
		}
	}
	return ""
}

// kcAttrIs reports whether the tag chunk carries attr="value".
func kcAttrIs(tag, attr, value string) bool {
	return regexp.MustCompile(attr + `="` + regexp.QuoteMeta(value) + `"`).MatchString(tag)
}

func htmlUnescapeAttr(s string) string {
	r := strings.NewReplacer("&amp;", "&", "&#34;", `"`, "&quot;", `"`, "&#39;", "'", "&lt;", "<", "&gt;", ">")
	return r.Replace(s)
}

func kcSnippet(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 240 {
		s = s[:240] + "…"
	}
	return s
}

// ---- live-world seeding helpers ------------------------------------------------

// KCLivePasswords are the committed throwaway realm credentials.
const (
	KCUserRoot     = "sso-root"
	KCUserDeny     = "sso-deny"
	KCUserConflict = "sso-conflict"

	KCPassRoot     = "n04-pass-root"
	KCPassDeny     = "n04-pass-deny"
	KCPassConflict = "n04-pass-conflict"
)

// KCCaptureIDToken performs a REAL authorization-code + PKCE round trip
// against the stand's OIDC client directly (no console) and returns the raw
// ID token plus its decoded claims. Used where the test needs the token
// bytes themselves (JWKS rotation evidence).
func (s *KCStand) CaptureIDToken(tb testing.TB, username, password string) (string, map[string]any) {
	tb.Helper()
	ctx := context.Background()
	flow, err := NewOIDCFlow()
	if err != nil {
		tb.Fatalf("oidc flow: %v", err)
	}
	q := url.Values{
		"client_id":             {KCLiveOIDCClientID},
		"response_type":         {"code"},
		"scope":                 {"openid email"},
		"redirect_uri":          {"http://localhost:9/auth/oidc/callback"},
		"state":                 {flow.State},
		"nonce":                 {flow.Nonce},
		"code_challenge":        {flow.PKCEChallengeS256()},
		"code_challenge_method": {"S256"},
	}
	browser := NewKCBrowser()
	callback := "http://localhost:9/auth/oidc/callback"
	hops := browser.DriveSSO(tb, s.RealmURL+"/protocol/openid-connect/auth?"+q.Encode(), username, password, callback)
	last := hops[len(hops)-1]
	if last.Status != http.StatusFound || !strings.HasPrefix(last.Location, callback) {
		tb.Fatalf("capture flow: expected redirect to %s, got %d → %q", callback, last.Status, last.Location)
	}
	code := kcQueryValue(tb, last.Location, "code")
	if flow.State != kcQueryValue(tb, last.Location, "state") {
		tb.Fatalf("capture flow: state mismatch")
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {callback},
		"code_verifier": {flow.PKCEVerifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.RealmURL+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		tb.Fatalf("token request: %v", err)
	}
	req.SetBasicAuth(KCLiveOIDCClientID, KCLiveOIDCClientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.http.Do(req)
	if err != nil {
		tb.Fatalf("token exchange: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		tb.Fatalf("token exchange: status %d: %s", resp.StatusCode, kcTruncate(raw))
	}
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(raw, &tok); err != nil || tok.IDToken == "" {
		tb.Fatalf("token exchange carried no id_token")
	}
	return tok.IDToken, kcDecodeJWTClaims(tb, tok.IDToken)
}

func kcQueryValue(tb testing.TB, rawURL, key string) string {
	tb.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		tb.Fatalf("parse %q: %v", rawURL, err)
	}
	return u.Query().Get(key)
}

func kcDecodeJWTClaims(tb testing.TB, token string) map[string]any {
	tb.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		tb.Fatalf("id_token is not a JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		tb.Fatalf("decode id_token payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		tb.Fatalf("id_token claims: %v", err)
	}
	return claims
}
