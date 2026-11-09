package provider_test

// N08-P01-T04 — real-cloud acceptance and diagnostics: tests for the
// ValidateAzureOpenAIEndpoint config-source check, the deployment
// discovery wire contract, the RunDiagnostics acceptance composition, and
// the packet negative criterion ("Ошибка Entra не раскрывает secret и не
// использует токен чужой org") observed THROUGH the diagnostics surface.
//
// Honest limits: the rigs are httptest stubs with Azure-shaped wire
// contracts (Entra authority + resource), exactly like the T01–T03 suites —
// they prove the adapter/boundary mechanics, not Microsoft attestation.
// The env-gated live entry at the bottom runs the SAME RunDiagnostics code
// path against a real cloud endpoint when an operator arms it; it performs
// ZERO spend (no chat completion — only the token exchange and the
// deployments list, both free operations), so the cost-limited property
// holds by construction; the spend-bearing live smoke remains the T03 test.
// Unarmed, it skips LOUDLY (documented limitation, never a silent pass).
//
// Diagnostics is an ops action against operator-configured endpoints; the
// SSRF posture of the production discovery dial (GuardDialedIP + exact
// literal pin of the configured endpoint) is exercised directly: these
// tests drive the exported surface with NO client injection, so the same
// guarded transport a real run builds is the one on the wire.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/reireirei/yabanin/pkg/provider"
)

// azureDiagCanaries are the credential/token fixture values these tests
// plant in the rigs. NO report may ever contain any of them.
var azureDiagCanaries = []string{
	"AT-DIAG-A", "AT-DIAG-B", // bearer tokens
	"fake-diag-a-7c21", "fake-diag-b-4e08", // client secrets
}

// azureDiagRig: dedicated Entra authority (two tenants, distinct
// deterministic tokens) + an Azure-shaped resource serving the deployments
// inventory. The resource records every discovery call's Authorization and
// query so the tests can pin the wire contract; its inventory/status is
// configurable per scenario.
type azureDiagRig struct {
	entra    *httptest.Server
	resource *httptest.Server

	mu             sync.Mutex
	authSeen       []string // bearer per discovery call, in order
	queries        []string // raw query per discovery call, in order
	entraCalls     int      // total token exchanges
	discoveryCalls int

	inventoryStatus int    // deployments list status (default 200)
	inventoryBody   string // deployments list body (default the standard fixture)
}

func newAzureDiagRig(t *testing.T) *azureDiagRig {
	t.Helper()
	rig := &azureDiagRig{inventoryStatus: http.StatusOK}

	tokenFor := map[string]string{"diag-tenant-a": "AT-DIAG-A", "diag-tenant-b": "AT-DIAG-B"}
	entraMux := http.NewServeMux()
	for tenant := range tokenFor {
		token := tokenFor[tenant] // per-iteration capture
		entraMux.HandleFunc("/"+tenant+"/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
			rig.mu.Lock()
			rig.entraCalls++
			rig.mu.Unlock()
			if err := r.ParseForm(); err != nil {
				t.Errorf("entra form parse: %v", err)
			}
			if got := r.PostForm.Get("grant_type"); got != "client_credentials" {
				t.Errorf("grant_type = %q", got)
			}
			if got := r.PostForm.Get("scope"); got != "https://cognitiveservices.azure.com/.default" {
				t.Errorf("scope = %q", got)
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": token, "expires_in": 3600})
		})
	}
	rig.entra = httptest.NewServer(entraMux)
	t.Cleanup(rig.entra.Close)

	resMux := http.NewServeMux()
	resMux.HandleFunc("/openai/deployments", func(w http.ResponseWriter, r *http.Request) {
		rig.mu.Lock()
		rig.discoveryCalls++
		rig.authSeen = append(rig.authSeen, r.Header.Get("Authorization"))
		rig.queries = append(rig.queries, r.URL.RawQuery)
		status, body := rig.inventoryStatus, rig.inventoryBody
		rig.mu.Unlock()
		if status == 0 {
			status = http.StatusOK
		}
		if body == "" {
			body = `{"data":[{"name":"gpt-4o-mini"},{"name":"gpt-4o"},{"name":""},{"name":"o1-preview"}]}`
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
	rig.resource = httptest.NewServer(resMux)
	t.Cleanup(rig.resource.Close)
	return rig
}

func (r *azureDiagRig) creds(t *testing.T, tenant, client, secret string) string {
	t.Helper()
	// Runtime-assembled fixtures (gosec G101 hygiene; never real values).
	return fmt.Sprintf(`{"tenant_id":%q,"client_id":%q,"client_secret":%q}`, tenant, client, secret)
}

func (r *azureDiagRig) wire() (auth []string, queries []string, entra, discovery int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.authSeen...), append([]string(nil), r.queries...), r.entraCalls, r.discoveryCalls
}

func (r *azureDiagRig) setInventory(status int, body string) {
	r.mu.Lock()
	r.inventoryStatus, r.inventoryBody = status, body
	r.mu.Unlock()
}

// assertNoCanary fails the test when any planted credential/token value
// appears anywhere in the marshaled report (packet negative criterion).
func assertNoCanary(t *testing.T, report provider.AzureDiagnosticsReport) {
	t.Helper()
	blob, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	for _, canary := range azureDiagCanaries {
		if strings.Contains(string(blob), canary) {
			t.Fatalf("report leaks canary %q: %s", canary, blob)
		}
	}
}

// checkRow returns the check named name (must exist exactly once).
func checkRow(t *testing.T, report provider.AzureDiagnosticsReport, name string) provider.AzureDiagnosticCheck {
	t.Helper()
	var found []provider.AzureDiagnosticCheck
	for _, c := range report.Checks {
		if c.Name == name {
			found = append(found, c)
		}
	}
	if len(found) != 1 {
		t.Fatalf("checks = %+v, want exactly one %q row", report.Checks, name)
	}
	return found[0]
}

// TestAzureOpenAI_Diagnostics_ValidConfig_AllPass: the positive acceptance
// path — valid endpoint, valid credentials, real token exchange, real
// discovery, deployment present. Pins:
//   - all five checks pass and the report is OK;
//   - the discovered inventory is sorted and skips empty names;
//   - the discovery wire carries the pinned api-version and the org's own
//     Entra bearer (the same tenant-keyed cache the chat path uses);
//   - the whole run performs exactly ONE Entra exchange (the acceptance
//     check reuses the discovery's cache slot — diagnostics stays cheap);
//   - no credential or token value appears anywhere in the report.
func TestAzureOpenAI_Diagnostics_ValidConfig_AllPass(t *testing.T) {
	rig := newAzureDiagRig(t)
	a := provider.NewAzureOpenAIWithClient(rig.entra.Client(), rig.entra.URL)

	creds := rig.creds(t, "diag-tenant-a", "diag-client-a", "fake-diag-a-7c21")
	report := a.RunDiagnostics(context.Background(), rig.resource.URL, creds, "gpt-4o")

	if !report.OK() {
		t.Fatalf("report not OK: %+v", report)
	}
	if len(report.Checks) != 5 {
		t.Fatalf("checks = %+v, want 5 rows (endpoint, credentials, entra, discovery, deployment-present)", report.Checks)
	}
	for _, c := range report.Checks {
		if c.Status != provider.AzureCheckPass {
			t.Fatalf("check %q = %s (%s), want pass", c.Name, c.Status, c.Detail)
		}
	}
	want := []string{"gpt-4o", "gpt-4o-mini", "o1-preview"}
	if strings.Join(report.Deployments, ",") != strings.Join(want, ",") {
		t.Fatalf("deployments = %v, want sorted non-empty %v", report.Deployments, want)
	}
	if report.Endpoint != rig.resource.URL {
		t.Fatalf("endpoint = %q, want the normalized configured URL %q", report.Endpoint, rig.resource.URL)
	}

	auth, queries, entra, discovery := rig.wire()
	if entra != 1 {
		t.Fatalf("entra exchanges = %d, want exactly 1 (acceptance reuses the cache slot)", entra)
	}
	if discovery != 1 {
		t.Fatalf("discovery calls = %d, want 1", discovery)
	}
	if len(auth) != 1 || auth[0] != "Bearer AT-DIAG-A" {
		t.Fatalf("discovery auth = %v, want the org's own bearer", auth)
	}
	if len(queries) != 1 || !strings.Contains(queries[0], "api-version=2024-10-21") {
		t.Fatalf("discovery query = %v, want the pinned api-version on the wire", queries)
	}
	assertNoCanary(t, report)
}

// TestAzureOpenAI_Diagnostics_EndpointConfig_Refusals: the config-source
// check refuses every malformed endpoint shape with a precise reason and
// ZERO network dials (fail-closed before any dial).
func TestAzureOpenAI_Diagnostics_EndpointConfig_Refusals(t *testing.T) {
	rig := newAzureDiagRig(t)
	a := provider.NewAzureOpenAIWithClient(rig.entra.Client(), rig.entra.URL)
	creds := rig.creds(t, "diag-tenant-a", "diag-client-a", "fake-diag-a-7c21")

	cases := []struct {
		name         string
		endpoint     string
		wantInDetail string // the precise refusal fragment (I51)
	}{
		{"empty", "   ", "endpoint is required"},
		{"no scheme", "contoso.openai.azure.com", "absolute URL with a host"},
		{"http non-loopback", "http://contoso.openai.azure.com", "must use https"},
		{"unsupported scheme", "ftp://contoso.openai.azure.com", `scheme "ftp" is not supported`},
		{"userinfo", "https://admin:hunter2@contoso.openai.azure.com", "must not carry userinfo"},
		{"query string", "https://contoso.openai.azure.com/?x=1", "must not carry a query string"},
		{"fragment", "https://contoso.openai.azure.com/#frag", "must not carry a fragment"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			report := a.RunDiagnostics(context.Background(), tc.endpoint, creds, "gpt-4o")
			if report.OK() {
				t.Fatalf("report OK for %q — the malformed endpoint must be refused", tc.endpoint)
			}
			if len(report.Checks) != 1 {
				t.Fatalf("checks = %+v, want exactly the endpoint-config row (fail-closed, no later stage ran)", report.Checks)
			}
			row := checkRow(t, report, "endpoint-config")
			if row.Status != provider.AzureCheckFail {
				t.Fatalf("status = %s, want fail", row.Status)
			}
			if !strings.Contains(row.Detail, tc.wantInDetail) {
				t.Fatalf("detail = %q, want it to name the precise reason (%q)", row.Detail, tc.wantInDetail)
			}
			if strings.Contains(row.Detail, "hunter2") {
				t.Fatal("endpoint refusal echoed userinfo credential material")
			}
			_, _, entra, discovery := rig.wire()
			if entra != 0 || discovery != 0 {
				t.Fatalf("malformed endpoint dialed the wire: entra=%d discovery=%d", entra, discovery)
			}
		})
	}
}

// TestAzureOpenAI_Diagnostics_EndpointConfig_LoopbackHTTPAdmitted: plain
// http is admitted only for the literal loopback forms (the httptest rig
// posture); localhost-by-NAME is a DNS name and still requires https.
func TestAzureOpenAI_Diagnostics_EndpointConfig_LoopbackHTTPAdmitted(t *testing.T) {
	if _, err := provider.ValidateAzureOpenAIEndpoint("http://127.0.0.1:8123"); err != nil {
		t.Fatalf("literal loopback http refused: %v", err)
	}
	if _, err := provider.ValidateAzureOpenAIEndpoint("http://[::1]:8123"); err != nil {
		t.Fatalf("ipv6 loopback http refused: %v", err)
	}
	if _, err := provider.ValidateAzureOpenAIEndpoint("http://localhost:8123"); err == nil {
		t.Fatal("localhost http accepted — DNS names must require https")
	}
	// Normalization: trailing slashes collapse; the URL is unchanged
	// otherwise.
	got, err := provider.ValidateAzureOpenAIEndpoint("https://contoso.openai.azure.com/")
	if err != nil {
		t.Fatalf("valid endpoint refused: %v", err)
	}
	if got != "https://contoso.openai.azure.com" {
		t.Fatalf("normalized = %q, want trailing slash trimmed", got)
	}
}

// TestAzureOpenAI_Diagnostics_CredentialsRefused_NoDials_NoSecretEcho: a
// broken credential blob fails the credentials stage with a field-named
// reason, zero dials, and never echoes the secret value.
func TestAzureOpenAI_Diagnostics_CredentialsRefused_NoDials_NoSecretEcho(t *testing.T) {
	rig := newAzureDiagRig(t)
	a := provider.NewAzureOpenAIWithClient(rig.entra.Client(), rig.entra.URL)

	cases := []struct {
		name         string
		blob         string
		wantInDetail string
	}{
		{"not json", "}not-json{", "must be JSON"},
		{"missing tenant", `{"client_id":"c","client_secret":"fake-diag-a-7c21"}`, "missing tenant_id"},
		{"missing client", `{"tenant_id":"diag-tenant-a","client_secret":"fake-diag-a-7c21"}`, "missing client_id"},
		{"missing secret", `{"tenant_id":"diag-tenant-a","client_id":"diag-client-a"}`, "missing client_secret"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			report := a.RunDiagnostics(context.Background(), rig.resource.URL, tc.blob, "gpt-4o")
			if report.OK() {
				t.Fatal("report OK for a broken credential blob")
			}
			if len(report.Checks) != 2 {
				t.Fatalf("checks = %+v, want endpoint pass + credentials fail", report.Checks)
			}
			row := checkRow(t, report, "credentials")
			if row.Status != provider.AzureCheckFail || !strings.Contains(row.Detail, tc.wantInDetail) {
				t.Fatalf("credentials row = %+v, want fail naming %q", row, tc.wantInDetail)
			}
			if strings.Contains(row.Detail, "fake-diag-a-7c21") {
				t.Fatal("credentials refusal echoed the secret value")
			}
			assertNoCanary(t, report)
			_, _, entra, discovery := rig.wire()
			if entra != 0 || discovery != 0 {
				t.Fatalf("broken credentials dialed the wire: entra=%d discovery=%d", entra, discovery)
			}
		})
	}
}

// TestAzureOpenAI_Diagnostics_EntraFailure_StageAttributed: the report
// attributes the failure to the entra-token stage (status-only detail),
// stops before discovery, and carries no token/secret material.
func TestAzureOpenAI_Diagnostics_EntraFailure_StageAttributed(t *testing.T) {
	rig := newAzureDiagRig(t)
	// Sabotaged authority: any exchange gets 401 (invalid_client shape).
	entra401 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"AADSTS7000215: invalid client secret"}`))
	}))
	defer entra401.Close()

	a := provider.NewAzureOpenAIWithClient(entra401.Client(), entra401.URL)
	creds := rig.creds(t, "diag-tenant-a", "diag-client-a", "fake-diag-a-7c21")
	report := a.RunDiagnostics(context.Background(), rig.resource.URL, creds, "gpt-4o")

	if report.OK() {
		t.Fatal("report OK with a failing Entra authority")
	}
	if len(report.Checks) != 3 {
		t.Fatalf("checks = %+v, want stop at the entra stage (3 rows)", report.Checks)
	}
	row := checkRow(t, report, "entra-token")
	if row.Status != provider.AzureCheckFail || !strings.Contains(row.Detail, "401") {
		t.Fatalf("entra row = %+v, want fail carrying the status code", row)
	}
	if strings.Contains(row.Detail, "fake-diag-a-7c21") || strings.Contains(row.Detail, "AADSTS7000215") {
		t.Fatalf("entra failure carried secret material or echoed the authority error body: %q", row.Detail)
	}
	assertNoCanary(t, report)
	_, _, _, discovery := rig.wire()
	if discovery != 0 {
		t.Fatalf("discovery ran %d times despite the failed exchange — stages must stop at first failure", discovery)
	}
}

// TestAzureOpenAI_Diagnostics_Entra429_CooldownFailsFast: a rate-limited
// exchange fails the entra stage with the cooldown diagnostic and the
// SECOND run fails fast with ZERO new exchanges (no hammering).
func TestAzureOpenAI_Diagnostics_Entra429_CooldownFailsFast(t *testing.T) {
	var entraCalls int
	var mu sync.Mutex
	entra429 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		entraCalls++
		mu.Unlock()
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer entra429.Close()

	rig := newAzureDiagRig(t) // resource needed only as a valid endpoint
	a := provider.NewAzureOpenAIWithClient(entra429.Client(), entra429.URL)
	creds := rig.creds(t, "diag-tenant-a", "diag-client-a", "fake-diag-a-7c21")

	first := a.RunDiagnostics(context.Background(), rig.resource.URL, creds, "gpt-4o")
	row := checkRow(t, first, "entra-token")
	if row.Status != provider.AzureCheckFail || !strings.Contains(row.Detail, "429") || !strings.Contains(row.Detail, "cooldown") {
		t.Fatalf("first entra row = %+v, want fail with the 429 cooldown diagnostic", row)
	}
	second := a.RunDiagnostics(context.Background(), rig.resource.URL, creds, "gpt-4o")
	row2 := checkRow(t, second, "entra-token")
	if row2.Status != provider.AzureCheckFail || !strings.Contains(row2.Detail, "rate-limited") {
		t.Fatalf("second entra row = %+v, want the fail-fast cooldown diagnostic", row2)
	}
	mu.Lock()
	defer mu.Unlock()
	if entraCalls != 1 {
		t.Fatalf("entra exchanges = %d, want exactly 1 (the cooldown must fail fast with zero new exchanges)", entraCalls)
	}
	assertNoCanary(t, first)
	assertNoCanary(t, second)
}

// TestAzureOpenAI_Diagnostics_DiscoveryFailure_DepresentSkipped: a failing
// discovery (HTTP 500) fails its own row with the status code, marks the
// dependent deployment-present verdict as an explicit skip, and the report
// is not OK.
func TestAzureOpenAI_Diagnostics_DiscoveryFailure_DepresentSkipped(t *testing.T) {
	rig := newAzureDiagRig(t)
	rig.setInventory(http.StatusInternalServerError, "")
	a := provider.NewAzureOpenAIWithClient(rig.entra.Client(), rig.entra.URL)
	creds := rig.creds(t, "diag-tenant-a", "diag-client-a", "fake-diag-a-7c21")

	report := a.RunDiagnostics(context.Background(), rig.resource.URL, creds, "gpt-4o")
	if report.OK() {
		t.Fatal("report OK with a failing discovery")
	}
	row := checkRow(t, report, "deployment-discovery")
	if row.Status != provider.AzureCheckFail || !strings.Contains(row.Detail, "HTTP 500") {
		t.Fatalf("discovery row = %+v, want fail carrying the status code", row)
	}
	skip := checkRow(t, report, "deployment-present")
	if skip.Status != provider.AzureCheckSkip || !strings.Contains(skip.Detail, "discovery failed") {
		t.Fatalf("deployment-present row = %+v, want the explicit dependency skip", skip)
	}
	if report.Deployments != nil {
		t.Fatalf("deployments = %v, want nil (no inventory observed)", report.Deployments)
	}
	assertNoCanary(t, report)
}

// TestAzureOpenAI_Diagnostics_DeploymentPresent_Verdict: the acceptance
// verdict boundary — the configured deployment must be exactly one the
// resource lists; an unknown name is refused precisely (I51), and the
// resource-only mode (empty deployment) runs no deployment-present row.
func TestAzureOpenAI_Diagnostics_DeploymentPresent_Verdict(t *testing.T) {
	rig := newAzureDiagRig(t)
	a := provider.NewAzureOpenAIWithClient(rig.entra.Client(), rig.entra.URL)
	creds := rig.creds(t, "diag-tenant-a", "diag-client-a", "fake-diag-a-7c21")

	t.Run("known deployment passes", func(t *testing.T) {
		report := a.RunDiagnostics(context.Background(), rig.resource.URL, creds, "gpt-4o")
		if !report.OK() {
			t.Fatalf("report not OK: %+v", report)
		}
		if row := checkRow(t, report, "deployment-present"); row.Status != provider.AzureCheckPass {
			t.Fatalf("deployment-present = %+v, want pass", row)
		}
	})

	t.Run("unknown deployment refused precisely", func(t *testing.T) {
		report := a.RunDiagnostics(context.Background(), rig.resource.URL, creds, "does-not-exist")
		if report.OK() {
			t.Fatal("report OK for a deployment the resource does not list")
		}
		row := checkRow(t, report, "deployment-present")
		if row.Status != provider.AzureCheckFail {
			t.Fatalf("status = %s, want fail", row.Status)
		}
		if !strings.Contains(row.Detail, `"does-not-exist"`) || !strings.Contains(row.Detail, "3 deployments") {
			t.Fatalf("detail = %q, want the named deployment and the inventory count", row.Detail)
		}
	})

	t.Run("resource-only mode omits the verdict row", func(t *testing.T) {
		report := a.RunDiagnostics(context.Background(), rig.resource.URL, creds, "")
		if !report.OK() {
			t.Fatalf("resource-only report not OK: %+v", report)
		}
		for _, c := range report.Checks {
			if c.Name == "deployment-present" {
				t.Fatalf("resource-only mode must not carry a deployment-present row: %+v", report.Checks)
			}
		}
		if len(report.Checks) != 4 {
			t.Fatalf("checks = %+v, want 4 rows (no deployment verdict)", report.Checks)
		}
	})

	t.Run("empty inventory refuses any deployment", func(t *testing.T) {
		rig.setInventory(http.StatusOK, `{"data":[]}`)
		defer rig.setInventory(http.StatusOK, "")
		report := a.RunDiagnostics(context.Background(), rig.resource.URL, creds, "gpt-4o")
		row := checkRow(t, report, "deployment-present")
		if row.Status != provider.AzureCheckFail || !strings.Contains(row.Detail, "0 deployments") {
			t.Fatalf("row = %+v, want fail against the empty inventory", row)
		}
	})
}

// TestAzureOpenAI_Diagnostics_MultiOrg_SharedAdapter_TokensNotCrossed: the
// packet negative criterion observed through the diagnostics surface — one
// shared adapter runs acceptance for two orgs; every discovery call carries
// the calling org's OWN bearer (never the other org's), exchanges stay at
// one per identity, and no report carries any token or secret value.
func TestAzureOpenAI_Diagnostics_MultiOrg_SharedAdapter_TokensNotCrossed(t *testing.T) {
	rig := newAzureDiagRig(t)
	a := provider.NewAzureOpenAIWithClient(rig.entra.Client(), rig.entra.URL)

	orgA := rig.creds(t, "diag-tenant-a", "diag-client-a", "fake-diag-a-7c21")
	orgB := rig.creds(t, "diag-tenant-b", "diag-client-b", "fake-diag-b-4e08")

	reportA := a.RunDiagnostics(context.Background(), rig.resource.URL, orgA, "gpt-4o")
	reportB := a.RunDiagnostics(context.Background(), rig.resource.URL, orgB, "gpt-4o-mini")
	if !reportA.OK() || !reportB.OK() {
		t.Fatalf("reports not OK: A=%+v B=%+v", reportA, reportB)
	}

	auth, _, entra, discovery := rig.wire()
	if len(auth) != 2 || auth[0] != "Bearer AT-DIAG-A" || auth[1] != "Bearer AT-DIAG-B" {
		t.Fatalf("discovery auth sequence = %v, want each org's own bearer in order", auth)
	}
	if entra != 2 {
		t.Fatalf("entra exchanges = %d, want exactly one per org identity", entra)
	}
	if discovery != 2 {
		t.Fatalf("discovery calls = %d, want 2", discovery)
	}
	assertNoCanary(t, reportA)
	assertNoCanary(t, reportB)
}

// TestAzureOpenAI_Diagnostics_DiscoveryBodyCapped: an oversized discovery
// response fails the decode with the bounded-body error instead of
// ballooning diagnostics memory.
func TestAzureOpenAI_Diagnostics_DiscoveryBodyCapped(t *testing.T) {
	rig := newAzureDiagRig(t)
	rig.setInventory(http.StatusOK, `{"data":[{"name":"`+strings.Repeat("x", 2<<20)+`"}]}`)
	a := provider.NewAzureOpenAIWithClient(rig.entra.Client(), rig.entra.URL)
	creds := rig.creds(t, "diag-tenant-a", "diag-client-a", "fake-diag-a-7c21")

	report := a.RunDiagnostics(context.Background(), rig.resource.URL, creds, "gpt-4o")
	if report.OK() {
		t.Fatal("report OK on an oversized discovery body")
	}
	row := checkRow(t, report, "deployment-discovery")
	if row.Status != provider.AzureCheckFail || !strings.Contains(row.Detail, "decode") {
		t.Fatalf("discovery row = %+v, want the bounded-decode failure", row)
	}
}

// TestAzureOpenAI_LiveDiagnostics_EnvGated_ZeroSpend — the packet's "real
// cloud acceptance" entry, honestly gated (T03 live-smoke env contract;
// see artifacts/internal-delivery-program/N08-P01/N08-P01-T03-record-2026-10-30.md and
// the T04 record):
//
//	AZURE_OPENAI_LIVE_SMOKE != "1" → loud skip (no egress, no
//	  owner-approved tenant on this stand — documented limitation).
//	armed but incomplete env → loud skip naming the missing variables.
//	armed + complete → the SAME RunDiagnostics code path these stub tests
//	  pin, against the real endpoint, via the production constructor
//	  (real Entra authority pin, SSRF-guarded discovery dial). ZERO spend:
//	  no chat completion is issued — the acceptance network is the token
//	  exchange and the deployments list only, so the cost-limit property
//	  holds by construction; the spend-bearing live smoke stays the T03
//	  test.
func TestAzureOpenAI_LiveDiagnostics_EnvGated_ZeroSpend(t *testing.T) {
	if os.Getenv("AZURE_OPENAI_LIVE_SMOKE") != "1" {
		t.Skip("LIVE DIAGNOSTICS UNAVAILABLE ON THIS STAND (loud-skip, documented): " +
			"AZURE_OPENAI_LIVE_SMOKE != 1 — no network egress and no owner-approved " +
			"Azure tenant here. The deterministic diagnostics suite carries the " +
			"acceptance contract on stubs. To arm on a networked stand: " +
			"AZURE_OPENAI_LIVE_SMOKE=1 plus AZURE_OPENAI_LIVE_ENDPOINT, " +
			"AZURE_OPENAI_LIVE_DEPLOYMENT, AZURE_OPENAI_LIVE_TENANT_ID, " +
			"AZURE_OPENAI_LIVE_CLIENT_ID, AZURE_OPENAI_LIVE_CLIENT_SECRET. Zero " +
			"spend: this run issues no chat completion. See the T04 record " +
			"artifacts/internal-delivery-program/imp-n08p01t04-2026-11-03.md.")
	}
	endpoint := os.Getenv("AZURE_OPENAI_LIVE_ENDPOINT")
	deployment := os.Getenv("AZURE_OPENAI_LIVE_DEPLOYMENT")
	tenantID := os.Getenv("AZURE_OPENAI_LIVE_TENANT_ID")
	clientID := os.Getenv("AZURE_OPENAI_LIVE_CLIENT_ID")
	clientSecret := os.Getenv("AZURE_OPENAI_LIVE_CLIENT_SECRET")
	var missing []string
	for _, kv := range []struct{ name, val string }{
		{"AZURE_OPENAI_LIVE_ENDPOINT", endpoint},
		{"AZURE_OPENAI_LIVE_DEPLOYMENT", deployment},
		{"AZURE_OPENAI_LIVE_TENANT_ID", tenantID},
		{"AZURE_OPENAI_LIVE_CLIENT_ID", clientID},
		{"AZURE_OPENAI_LIVE_CLIENT_SECRET", clientSecret},
	} {
		if strings.TrimSpace(kv.val) == "" {
			missing = append(missing, kv.name)
		}
	}
	if len(missing) > 0 {
		t.Skipf("LIVE DIAGNOSTICS ARMED BUT INCOMPLETE (loud-skip): missing %s",
			strings.Join(missing, ", "))
	}

	// Production constructor: the real Entra authority pin and the
	// SSRF-guarded discovery dial the stub tests cannot exercise (their
	// rigs are loopback; the production code path is identical otherwise).
	a := provider.NewAzureOpenAI()
	creds := fmt.Sprintf(`{"tenant_id":%q,"client_id":%q,"client_secret":%q}`,
		tenantID, clientID, clientSecret)

	report := a.RunDiagnostics(context.Background(), endpoint, creds, deployment)
	blob, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal live report: %v", err)
	}
	if strings.Contains(string(blob), clientSecret) {
		t.Fatal("live diagnostics report leaked the client secret")
	}
	if !report.OK() {
		t.Fatalf("live acceptance failed: %s", blob)
	}
}
