package cli

//
// docs/api/openapi.yaml is the public contract of the gateway surface: spec
// paths are relative to the /v1 server base (root servers), and /healthz
// carries its own gateway path-level servers without the /v1 suffix. This
// test walks the REAL gateway router — the same walk that pins
// testdata/routes_gateway.golden (TestGatewayRoutesGolden) — and asserts:
//
//   - forward: every /v1 operation the router serves (plus GET /healthz)
//     is documented in the public spec, with a summary;
//   - reverse: every spec operation served by the gateway servers exists
//     on the walked router — a documented-but-unserved operation is stale.
//
// Admin control-plane operations in the same file (path-level admin
// servers) are outside this gate; they are cross-checked against the admin
// router by services/admin/handlers.TestGatewayOpenAPIRoutesExist. The
// non-/v1 gateway infrastructure routes (/mcp, /api/mcp/*, /api/a2a/send
// and /api/hello) are transport surfaces outside the public REST spec and
// are skipped deliberately.

import (
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const publicOpenAPISpec = "../../docs/api/openapi.yaml"

// gatewayServerHosts are the gateway (inference) hosts named by the spec's
// server entries; anything else (admin.yabanin.io, localhost:9091) is the
// admin control plane.
var gatewayServerHosts = map[string]bool{
	"api.yabanin.io": true,
	"localhost:8082": true,
}

// publicSpecPath is one spec path item: its path-level server overrides
// plus every remaining key (get/post/...) as raw nodes.
type publicSpecPath struct {
	Servers []struct {
		URL string `yaml:"url"`
	} `yaml:"servers"`
	Operations map[string]yaml.Node `yaml:",inline"`
}

func loadPublicSpec(tb testing.TB) map[string]publicSpecPath {
	tb.Helper()
	raw, err := os.ReadFile(publicOpenAPISpec) // #nosec G304 -- compile-time spec constant
	if err != nil {
		tb.Fatalf("read public spec: %v", err)
	}
	var doc struct {
		Paths map[string]publicSpecPath `yaml:"paths"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		tb.Fatalf("parse %s: %v", publicOpenAPISpec, err)
	}
	if len(doc.Paths) == 0 {
		tb.Fatalf("no paths parsed from %s — spec parse is broken", publicOpenAPISpec)
	}
	return doc.Paths
}

// specGatewayBase reports whether the path is served by the gateway and
// the URL-path prefix the spec path is relative to: "/v1" for the root
// servers and gateway servers that carry the suffix, "" for a gateway
// server without it (/healthz).
func specGatewayBase(p publicSpecPath) (string, bool) {
	if len(p.Servers) == 0 {
		return "/v1", true
	}
	for _, s := range p.Servers {
		u, err := url.Parse(s.URL)
		if err != nil {
			continue
		}
		if gatewayServerHosts[u.Host] {
			return strings.TrimSuffix(u.Path, "/"), true
		}
	}
	return "", false
}

func specHTTPMethod(key string) bool {
	switch strings.ToUpper(key) {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	}
	return false
}

// TestGatewayOpenAPIDrift is the gateway drift gate: walked router ↔
// docs/api/openapi.yaml over the gateway-served operations.
func TestGatewayOpenAPIDrift(t *testing.T) {
	walked := goldenWalkRoutes(t)
	walkedByKey := make(map[string]bool, len(walked))
	for _, r := range walked {
		walkedByKey[r.Method+" "+r.Pattern] = true
	}
	paths := loadPublicSpec(t)

	// Forward: every walked /v1 operation (plus the health probe) must be
	// documented. Spec paths are relative to the /v1 server base.
	forward := 0
	for _, r := range walked {
		if !strings.HasPrefix(r.Pattern, "/v1/") && r.Pattern != "/healthz" {
			continue
		}
		forward++
		item, ok := paths[strings.TrimPrefix(r.Pattern, "/v1")]
		if !ok {
			t.Errorf("undocumented gateway route %s %s — add it to %s (paths are relative to the /v1 server base)",
				r.Method, r.Pattern, publicOpenAPISpec)
			continue
		}
		node, ok := item.Operations[strings.ToLower(r.Method)]
		if !ok {
			t.Errorf("undocumented gateway operation %s %s — the path exists in %s but has no %s entry",
				r.Method, r.Pattern, publicOpenAPISpec, strings.ToLower(r.Method))
			continue
		}
		var op struct {
			Summary string `yaml:"summary"`
		}
		if err := node.Decode(&op); err != nil || strings.TrimSpace(op.Summary) == "" {
			t.Errorf("%s %s: missing or undecodable summary in %s — describe the operation",
				r.Method, r.Pattern, publicOpenAPISpec)
		}
	}
	// Floor guard: a walk or filter regression must not silently empty the
	// sweep. The router currently serves 20 /v1 routes plus /healthz.
	if forward < 15 {
		t.Fatalf("forward sweep covered only %d gateway routes — the walk or the /v1 filter is broken", forward)
	}

	// Reverse: every spec operation on the gateway servers must exist on
	// the walked router.
	reverse := 0
	for specPath, item := range paths {
		base, gateway := specGatewayBase(item)
		if !gateway {
			continue
		}
		for methodKey := range item.Operations {
			if !specHTTPMethod(methodKey) {
				continue
			}
			reverse++
			key := strings.ToUpper(methodKey) + " " + base + specPath
			if !walkedByKey[key] {
				t.Errorf("stale gateway spec operation %s — documented in %s but not served by the gateway router (moved to admin? give the path admin path-level servers)",
					key, publicOpenAPISpec)
			}
		}
	}
	if reverse < 15 {
		t.Fatalf("reverse sweep checked only %d spec operations — the gateway-server classification is broken", reverse)
	}
}
