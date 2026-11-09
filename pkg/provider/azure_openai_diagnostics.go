package provider

// N08-P01-T04 — real-cloud acceptance and diagnostics for the Azure OpenAI
// adapter.
//
// The packet acceptance ("Поддержанные deployments проходят contract и live
// smoke при лимите затрат") needs a way to verify a REAL cloud configuration
// without spending tokens on guesses: an operator configures
// models_registry.upstream_url (the resource endpoint),
// models_registry.model_name (which doubles as the deployment name) and the
// org's Entra credential blob (org_provider_credentials.api_key_ct), and
// needs a precise answer to "will this row actually serve?" before any chat
// traffic — and an equally precise reason when it will not (I51).
//
// This file is the acceptance/diagnostics surface:
//
//   - ValidateAzureOpenAIEndpoint — the config-source check (pure, offline):
//     the endpoint must be an absolute URL with a host, https for any
//     non-loopback host (real Azure OpenAI resources are https-only), with
//     no userinfo/query/fragment (credentials live in the secret blob, and
//     the adapter pins api-version itself). Plain http is admitted ONLY for
//     the literal loopback forms 127.0.0.1/::1 — httptest-shaped rigs — the
//     same exact-literal posture as the D-4 transport pin; DNS names always
//     require https. No host allow-list is imposed: sovereign/private Azure
//     stacks are legitimate endpoints, and the SSRF boundary is enforced at
//     the dial layer (below), not by name pattern-matching.
//   - DiscoverDeployments — the deployment discovery check (network): GET
//     {endpoint}/openai/deployments?api-version=<pinned> with the tenant's
//     Entra bearer from the SAME tenant-keyed token cache the chat path
//     uses. This is the resource's own deployment inventory, so a configured
//     deployment that the cloud does not have is reported precisely instead
//     of being discovered at first-request time as a 404.
//   - RunDiagnostics — the acceptance composition: endpoint-config →
//     credentials → entra-token → deployment-discovery → deployment-present,
//     run in order and stopped at the first failure (later stages cannot
//     produce a verdict without the earlier ones; the report shows exactly
//     how far verification got). The result is a JSON-tagged report whose
//     details are secret-free by construction: field names, HTTP status
//     codes and deployment counts only — never credential or token values
//     (packet negative criterion).
//
// Security posture (go-security-analysis):
//
//   - the discovery dial uses the same SSRF-guarded transport constructor as
//     the Entra exchange (GuardDialedIP with an exact-IP-literal pin of the
//     configured endpoint only); a diagnostics run dials EXACTLY the two
//     operator-configured authorities (Entra + resource endpoint) and
//     nothing else;
//   - diagnostics performs NO chat completion: the only network is the
//     token exchange and the deployments list, both zero-spend operations —
//     the cost-limited live smoke stays the T03 machinery and composes with
//     this report at the packet level;
//   - no environment-based config source is introduced: the production
//     config sources remain models_registry.upstream_url +
//     org_provider_credentials (env vars exist only in the T03/T04 gated
//     test rigs, never as a production fallback).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/reireirei/yabanin/pkg/ssrf"
)

const (
	// azureDeploymentsListPath is the Azure OpenAI deployments inventory
	// path (the management/data-plane list operation).
	azureDeploymentsListPath = "/openai/deployments"
	// azureDiscoveryMaxBody caps the deployments-list response, mirroring
	// the token-exchange body cap (a hostile or misbehaving endpoint cannot
	// balloon diagnostics memory).
	azureDiscoveryMaxBody = 1 << 20
	// azureDiagnosticsTimeout bounds one acceptance run. Diagnostics is an
	// ops action, not the request path: one generous ceiling for the whole
	// report (token exchange + discovery) so a hung endpoint cannot park an
	// operator session.
	azureDiagnosticsTimeout = 30 * time.Second
)

// AzureCheckStatus is the verdict of one diagnostics check.
type AzureCheckStatus string

const (
	// AzureCheckPass is the verdict of a check that ran and produced a
	// positive result.
	AzureCheckPass AzureCheckStatus = "pass"
	// AzureCheckFail is the verdict of a check that ran and refused; the
	// detail names the precise reason (I51 — never a bare false).
	AzureCheckFail AzureCheckStatus = "fail"
	// AzureCheckSkip marks a check that could not produce a verdict
	// because an earlier stage failed; its detail names the dependency.
	AzureCheckSkip AzureCheckStatus = "skip"
)

// Diagnostic check names (the JSON "name" values of the report rows).
const (
	azureCheckEndpoint        = "endpoint-config"
	azureCheckCredentials     = "credentials"
	azureCheckEntraToken      = "entra-token"
	azureCheckDiscovery       = "deployment-discovery"
	azureCheckDeploymentShown = "deployment-present"
)

// AzureDiagnosticCheck is one row of the acceptance report.
type AzureDiagnosticCheck struct {
	Name   string           `json:"name"`
	Status AzureCheckStatus `json:"status"`
	// Detail carries the precise, secret-free observation (field names,
	// status codes, counts). Empty on plain passes.
	Detail string `json:"detail,omitempty"`
}

// AzureDiagnosticsReport is the real-cloud acceptance verdict for one
// configured row. JSON-tagged so admin/ops surfaces can render it verbatim
// (LocalModelStatus precedent). Credential and token values are never part
// of any field.
type AzureDiagnosticsReport struct {
	// Provider is the canonical adapter name ("azure-openai").
	Provider string `json:"provider"`
	// Endpoint is the validated, normalized resource endpoint (trailing
	// slash trimmed). Empty when the endpoint-config check failed.
	Endpoint string `json:"endpoint,omitempty"`
	// Checks is the ordered list of executed checks. RunDiagnostics stops
	// at the first failure, so the list shows exactly how far verification
	// got; the one dependent check (deployment-present after a failed
	// discovery) appears as an explicit skip row.
	Checks []AzureDiagnosticCheck `json:"checks"`
	// Deployments is the discovered, sorted deployment inventory of the
	// resource. Present only when discovery succeeded.
	Deployments []string `json:"deployments,omitempty"`
}

// OK reports the acceptance verdict: every executed check passed. A report
// with no checks (unreachable) is not OK.
func (r AzureDiagnosticsReport) OK() bool {
	if len(r.Checks) == 0 {
		return false
	}
	for _, c := range r.Checks {
		if c.Status != AzureCheckPass {
			return false
		}
	}
	return true
}

// ValidateAzureOpenAIEndpoint validates a configured Azure OpenAI resource
// endpoint (config source: models_registry.upstream_url) and returns the
// normalized form (trimmed, trailing slash removed). The error names the
// violated requirement and never echoes any userinfo the URL may have
// carried.
func ValidateAzureOpenAIEndpoint(endpoint string) (string, error) {
	trimmed := strings.TrimSpace(endpoint)
	if trimmed == "" {
		return "", errors.New("azure-openai: endpoint is required (models_registry.upstream_url)")
	}
	u, err := url.Parse(trimmed)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", errors.New("azure-openai: endpoint must be an absolute URL with a host (models_registry.upstream_url)")
	}
	switch u.Scheme {
	case "https":
	case "http":
		// Real Azure OpenAI resources are https-only. Plain http is
		// admitted ONLY for the literal loopback forms (httptest-shaped
		// rigs); a DNS name always requires https — a plain-http DNS
		// endpoint would ship the Entra bearer in cleartext.
		if host := u.Hostname(); host != "127.0.0.1" && host != "::1" {
			return "", errors.New("azure-openai: endpoint must use https (real Azure OpenAI endpoints are https-only; plain http is admitted only for the literal loopback 127.0.0.1/::1 test forms)")
		}
	default:
		return "", fmt.Errorf("azure-openai: endpoint scheme %q is not supported; use https", u.Scheme)
	}
	if u.User != nil {
		return "", errors.New("azure-openai: endpoint must not carry userinfo (credentials live in org_provider_credentials, never the URL)")
	}
	if u.RawQuery != "" {
		return "", errors.New("azure-openai: endpoint must not carry a query string (the adapter pins api-version itself)")
	}
	if u.Fragment != "" {
		return "", errors.New("azure-openai: endpoint must not carry a fragment")
	}
	return strings.TrimRight(trimmed, "/"), nil
}

// DiscoverDeployments lists the resource's deployment inventory from the
// real cloud: GET {endpoint}/openai/deployments?api-version=<pinned> with
// the credential's Entra bearer from the tenant-keyed token cache. The
// returned names are sorted and non-empty. Errors are stage-precise and
// carry status codes only — never credential or token material.
func (a *AzureOpenAI) DiscoverDeployments(ctx context.Context, baseURL, apiKey string) ([]string, error) {
	endpoint, err := ValidateAzureOpenAIEndpoint(baseURL)
	if err != nil {
		return nil, err
	}
	creds, err := ParseAzureEntraCredentials(apiKey)
	if err != nil {
		return nil, err
	}
	return a.discoverDeployments(ctx, endpoint, creds)
}

// discoverDeployments is the shared implementation for the exported
// discovery entry and RunDiagnostics (which has already validated the
// endpoint and parsed the credentials).
func (a *AzureOpenAI) discoverDeployments(ctx context.Context, endpoint string, creds AzureEntraCredentials) ([]string, error) {
	//nolint:contextcheck // the refresh deliberately runs on a detached, self-bounded context (azure_openai.go precedent) — one caller's ctx must not own the shared token exchange
	if err := a.ensureToken(creds); err != nil {
		return nil, fmt.Errorf("azure-openai: ensure token: %w", err)
	}
	full := endpoint + azureDeploymentsListPath + "?" + url.Values{"api-version": {azureOpenAIAPIVersion}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
	if err != nil {
		return nil, fmt.Errorf("build azure-openai discovery request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+a.currentToken(entraCacheKey(creds)))
	// SSRF-guarded dial pinned to exactly the configured endpoint authority
	// (D-4 exact-literal posture: httptest rigs pin 127.0.0.1; a production
	// hostname is never waived, so its resolved IPs keep the reserved-range
	// refusal and the DNS-rebinding window stays closed).
	client := newAzureEndpointHTTPClient(endpoint)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("azure-openai deployments endpoint unreachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("azure-openai deployments list HTTP %d", resp.StatusCode)
	}
	var list struct {
		Data []struct {
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, azureDiscoveryMaxBody)).Decode(&list); err != nil {
		return nil, fmt.Errorf("decode azure-openai deployments response: %w", err)
	}
	names := make([]string, 0, len(list.Data))
	for _, d := range list.Data {
		if name := strings.TrimSpace(d.Name); name != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, nil
}

// newAzureEndpointHTTPClient builds the discovery transport on the shared
// SSRF transport constructor with the same posture as the Entra exchange
// client (newAzureEntraHTTPClient), pinned to the configured resource
// endpoint. Built per diagnostics run: discovery is an ops-frequency action,
// not the request path. No http.Client.Timeout: the run is bounded by
// azureDiagnosticsTimeout on the caller's context.
func newAzureEndpointHTTPClient(endpoint string) *http.Client {
	tr := ssrf.NewTransport(ssrf.TransportOptions{
		DialTimeout:           10 * time.Second,
		KeepAlive:             30 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		GuardDialedIP:         true,
		TrustedExactHosts:     trustedExactHostPin(endpoint),
	})
	return &http.Client{Transport: tr}
}

// RunDiagnostics composes the real-cloud acceptance report for one
// configured row: endpoint (models_registry.upstream_url), credentials (the
// org's Entra blob) and the deployment to accept (models_registry
// .model_name; empty = validate the resource only, no deployment-present
// row). Checks run in order and the run stops at the first failure — the
// report shows exactly how far verification got, and every failure carries
// its precise, secret-free reason (I51). Zero spend: no chat completion is
// performed, the only network is the Entra exchange and the deployments
// list.
func (a *AzureOpenAI) RunDiagnostics(ctx context.Context, endpoint, credsBlob, deployment string) AzureDiagnosticsReport {
	report := AzureDiagnosticsReport{Provider: a.Name()}
	ctx, cancel := context.WithTimeout(ctx, azureDiagnosticsTimeout)
	defer cancel()

	// Stage 1: config source (the URL). Fail-closed: no dial on a bad URL.
	normalized, err := ValidateAzureOpenAIEndpoint(endpoint)
	if err != nil {
		report.Checks = append(report.Checks, AzureDiagnosticCheck{
			Name: azureCheckEndpoint, Status: AzureCheckFail, Detail: err.Error(),
		})
		return report
	}
	report.Endpoint = normalized
	report.Checks = append(report.Checks, AzureDiagnosticCheck{
		Name: azureCheckEndpoint, Status: AzureCheckPass,
		Detail: "endpoint accepted (https host, no userinfo/query/fragment)",
	})

	// Stage 2: credential blob. Errors name missing FIELD names only.
	creds, err := ParseAzureEntraCredentials(credsBlob)
	if err != nil {
		report.Checks = append(report.Checks, AzureDiagnosticCheck{
			Name: azureCheckCredentials, Status: AzureCheckFail, Detail: err.Error(),
		})
		return report
	}
	report.Checks = append(report.Checks, AzureDiagnosticCheck{
		Name: azureCheckCredentials, Status: AzureCheckPass,
		Detail: "Entra credential blob parsed (tenant+client identity)",
	})

	// Stage 3: Entra exchange (tenant-keyed cache; a rate-limited authority
	// fails fast per the azureRateLimitCooldown* boundaries).
	//nolint:contextcheck // detached, self-bounded refresh (azure_openai.go precedent)
	if err := a.ensureToken(creds); err != nil {
		report.Checks = append(report.Checks, AzureDiagnosticCheck{
			Name: azureCheckEntraToken, Status: AzureCheckFail, Detail: err.Error(),
		})
		return report
	}
	report.Checks = append(report.Checks, AzureDiagnosticCheck{
		Name: azureCheckEntraToken, Status: AzureCheckPass,
		Detail: "Entra bearer acquired (tenant-keyed cache)",
	})

	// Stage 4: deployment discovery (real inventory).
	deployments, err := a.discoverDeployments(ctx, normalized, creds)
	if err != nil {
		report.Checks = append(report.Checks, AzureDiagnosticCheck{
			Name: azureCheckDiscovery, Status: AzureCheckFail, Detail: err.Error(),
		})
		// The dependent verdict cannot be produced without the inventory;
		// the skip row makes the dependency explicit instead of leaving the
		// report ambiguous about whether the check was forgotten.
		report.Checks = append(report.Checks, AzureDiagnosticCheck{
			Name: azureCheckDeploymentShown, Status: AzureCheckSkip,
			Detail: "not evaluated: discovery failed",
		})
		return report
	}
	report.Deployments = deployments
	report.Checks = append(report.Checks, AzureDiagnosticCheck{
		Name: azureCheckDiscovery, Status: AzureCheckPass,
		Detail: fmt.Sprintf("resource listed %d deployments", len(deployments)),
	})

	// Stage 5: deployment-present verdict (the acceptance). The deployment
	// name is models_registry.model_name — the same value the chat path
	// sends as the deployment-qualified URL segment — so a name the cloud
	// does not have would 404 on first request; this check refuses it
	// upfront instead.
	deployment = strings.TrimSpace(deployment)
	if deployment == "" {
		// Resource-only mode: no deployment acceptance was requested.
		return report
	}
	if !slices.Contains(deployments, deployment) {
		report.Checks = append(report.Checks, AzureDiagnosticCheck{
			Name: azureCheckDeploymentShown, Status: AzureCheckFail,
			Detail: fmt.Sprintf("deployment %q is not among the %d deployments listed by the resource (models_registry.model_name must equal the cloud deployment name)", deployment, len(deployments)),
		})
		return report
	}
	report.Checks = append(report.Checks, AzureDiagnosticCheck{
		Name: azureCheckDeploymentShown, Status: AzureCheckPass,
		Detail: fmt.Sprintf("deployment %q is listed by the resource", deployment),
	})
	return report
}
