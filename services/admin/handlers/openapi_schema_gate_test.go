package handlers

//
// Schema-layer drift gates. The route-layer drift gates
// (TestAdminRoutesInventory, TestGatewayOpenAPIDrift in pkg/gateway) pin the
// operation set; the gates here pin the schema layer of both spec files so a
// spec that breaks its own consumers turns red instead of shipping broken:
//
//   - TestOpenAPISchemaRefsResolve: every $ref in either spec resolves to a
//     schema defined in the same document — a renamed or removed component
//     referenced by a live operation fails here before any generator or
//     client sees the dangling reference;
//   - TestOpenAPIDeprecationLifecycle: a deprecated operation carries the
//     full lifecycle metadata (announcement date, sunset date at least the
//     minimum notice window ahead, migration target), and the metadata never
//     outlives the deprecated flag — see docs/api/CONTRACT.md §9;
//   - TestSDKConsumedRoutesDocumented: every route an SDK ships is a
//     documented operation of the matching spec (the SDK counterpart of the
//     UI-actions inventory).
//

import (
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// specHTTPMethod reports whether a yaml key is an OpenAPI operation key.
func specHTTPMethod(key string) bool {
	switch strings.ToUpper(key) {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	}
	return false
}

// minDeprecationNotice is the minimum announcement-to-sunset window the
// deprecation lifecycle guarantees to clients (docs/api/CONTRACT.md §9).
const minDeprecationNotice = 180 * 24 * time.Hour

// specRef is one $ref found in a spec document: its JSON pointer value.
type specRef struct {
	Target string
}

// walkSpecRefs collects every $ref scalar under a yaml node.
func walkSpecRefs(node *yaml.Node, out *[]specRef) {
	if node == nil {
		return
	}
	if node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, val := node.Content[i], node.Content[i+1]
			if key.Kind == yaml.ScalarNode && key.Value == "$ref" && val.Kind == yaml.ScalarNode {
				*out = append(*out, specRef{Target: val.Value})
				continue
			}
			walkSpecRefs(val, out)
		}
		return
	}
	for _, child := range node.Content {
		walkSpecRefs(child, out)
	}
}

// loadSpecDocument parses a whole spec file into a yaml node.
func loadSpecDocument(tb testing.TB, path string) *yaml.Node {
	tb.Helper()
	raw, err := os.ReadFile(path) // #nosec G304 -- compile-time spec constant passed by the tests
	if err != nil {
		tb.Fatalf("read spec %s: %v", path, err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		tb.Fatalf("parse spec %s: %v", path, err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		tb.Fatalf("spec %s did not parse into a document", path)
	}
	return doc.Content[0]
}

// specSchemaNames returns the components.schemas key set of a spec document.
func specSchemaNames(tb testing.TB, doc *yaml.Node, path string) map[string]bool {
	tb.Helper()
	var (
		schemas *yaml.Node
		found   bool
	)
	// components: schemas: <mapping>
	if doc.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(doc.Content); i += 2 {
			if doc.Content[i].Value == "components" {
				comp := doc.Content[i+1]
				for j := 0; j+1 < len(comp.Content); j += 2 {
					if comp.Content[j].Value == "schemas" {
						schemas = comp.Content[j+1]
						found = true
					}
				}
			}
		}
	}
	if !found || schemas == nil || schemas.Kind != yaml.MappingNode || len(schemas.Content) == 0 {
		tb.Fatalf("spec %s: components.schemas missing or empty", path)
	}
	out := make(map[string]bool, len(schemas.Content)/2)
	for i := 0; i+1 < len(schemas.Content); i += 2 {
		out[schemas.Content[i].Value] = true
	}
	return out
}

// TestOpenAPISchemaRefsResolve walks every $ref of both spec files and
// requires it to name a schema defined in the same document. Ref forms other
// than #/components/schemas/<name> are rejected: the specs are
// self-contained by contract.
func TestOpenAPISchemaRefsResolve(t *testing.T) {
	floors := map[string]int{
		adminOpenAPISpec:   8,   // the spec currently carries 10 refs
		gatewayOpenAPISpec: 120, // the spec currently carries 161 refs
	}
	schemaFloors := map[string]int{
		adminOpenAPISpec:   10, // currently 11 schemas
		gatewayOpenAPISpec: 25, // currently 30 schemas
	}
	for _, spec := range []string{adminOpenAPISpec, gatewayOpenAPISpec} {
		t.Run(spec, func(t *testing.T) {
			doc := loadSpecDocument(t, spec)
			schemas := specSchemaNames(t, doc, spec)
			if len(schemas) < schemaFloors[spec] {
				t.Fatalf("spec %s: only %d component schemas, below the %d floor — parse or content rot",
					spec, len(schemas), schemaFloors[spec])
			}
			var refs []specRef
			walkSpecRefs(doc, &refs)
			if len(refs) < floors[spec] {
				t.Fatalf("spec %s: only %d $ref nodes found, below the %d floor — the ref walk is broken",
					spec, len(refs), floors[spec])
			}
			for _, ref := range refs {
				const prefix = "#/components/schemas/"
				name, ok := strings.CutPrefix(ref.Target, prefix)
				if !ok || name == "" {
					t.Errorf("unsupported $ref %q — specs reference #/components/schemas/<name> only", ref.Target)
					continue
				}
				if !schemas[name] {
					t.Errorf("dangling $ref %q in %s — no component schema %q is defined", ref.Target, spec, name)
				}
			}
		})
	}
}

// deprecationMeta is the lifecycle metadata an OpenAPI operation may carry.
type deprecationMeta struct {
	Deprecated      bool   `yaml:"deprecated"`
	DeprecatedSince string `yaml:"x-deprecated-since"`
	Sunset          string `yaml:"x-sunset"`
	Migration       string `yaml:"x-migration"`
}

// mappingHasKey reports whether a yaml mapping node carries a key directly.
func mappingHasKey(node *yaml.Node, key string) bool {
	if node == nil || node.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Kind == yaml.ScalarNode && node.Content[i].Value == key {
			return true
		}
	}
	return false
}

// walkOperations visits every path→operation pair of a spec document and
// reports the operation key, its raw node and its decoded metadata.
func walkOperations(tb testing.TB, doc *yaml.Node, path string, visit func(key string, opNode *yaml.Node, meta deprecationMeta)) {
	tb.Helper()
	var paths *yaml.Node
	if doc.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(doc.Content); i += 2 {
			if doc.Content[i].Value == "paths" {
				paths = doc.Content[i+1]
			}
		}
	}
	if paths == nil || paths.Kind != yaml.MappingNode || len(paths.Content) == 0 {
		tb.Fatalf("spec %s: paths missing or empty", path)
	}
	ops := 0
	for i := 0; i+1 < len(paths.Content); i += 2 {
		pattern := paths.Content[i].Value
		item := paths.Content[i+1]
		if item.Kind != yaml.MappingNode {
			continue
		}
		for j := 0; j+1 < len(item.Content); j += 2 {
			methodKey := item.Content[j].Value
			if !specHTTPMethod(methodKey) {
				continue
			}
			opNode := item.Content[j+1]
			ops++
			var meta deprecationMeta
			if err := opNode.Decode(&meta); err != nil {
				tb.Fatalf("spec %s: decode %s %s: %v", path, strings.ToUpper(methodKey), pattern, err)
			}
			visit(strings.ToUpper(methodKey)+" "+pattern, opNode, meta)
		}
	}
	if ops == 0 {
		tb.Fatalf("spec %s: no operations decoded — the paths walk is broken", path)
	}
}

// TestOpenAPIDeprecationLifecycle enforces docs/api/CONTRACT.md §9 on both
// spec files: a deprecated operation announces when it was deprecated, the
// earliest removal date (at least the minimum notice window later) and where
// clients migrate; lifecycle metadata without the deprecated flag is the
// inconsistent half-state and fails both directions.
func TestOpenAPIDeprecationLifecycle(t *testing.T) {
	for _, spec := range []string{adminOpenAPISpec, gatewayOpenAPISpec} {
		doc := loadSpecDocument(t, spec)
		walkOperations(t, doc, spec, func(key string, opNode *yaml.Node, meta deprecationMeta) {
			present := mappingHasKey(opNode, "x-deprecated-since") ||
				mappingHasKey(opNode, "x-sunset") || mappingHasKey(opNode, "x-migration")
			if !meta.Deprecated {
				if present {
					t.Errorf("%s in %s: carries lifecycle metadata but is not marked deprecated: true — remove the metadata or mark the operation", key, spec)
				}
				return
			}
			if meta.DeprecatedSince == "" || meta.Sunset == "" || meta.Migration == "" {
				t.Errorf("%s in %s: deprecated without full lifecycle metadata (x-deprecated-since, x-sunset, x-migration) — see docs/api/CONTRACT.md §9", key, spec)
				return
			}
			since, err := time.Parse(time.DateOnly, meta.DeprecatedSince)
			if err != nil {
				t.Errorf("%s in %s: x-deprecated-since %q is not an RFC3339 date: %v", key, spec, meta.DeprecatedSince, err)
				return
			}
			sunset, err := time.Parse(time.DateOnly, meta.Sunset)
			if err != nil {
				t.Errorf("%s in %s: x-sunset %q is not an RFC3339 date: %v", key, spec, meta.Sunset, err)
				return
			}
			if notice := sunset.Sub(since); notice < minDeprecationNotice {
				t.Errorf("%s in %s: sunset %s is only %s after deprecation %s — the lifecycle guarantees at least %s of notice",
					key, spec, meta.Sunset, notice, meta.DeprecatedSince, minDeprecationNotice)
			}
			if strings.TrimSpace(meta.Migration) == "" {
				t.Errorf("%s in %s: x-migration is blank — name the replacement route, header or document", key, spec)
			}
		})
	}
}

// sdkRoutePin is one route an SDK ships: the fragments that must appear in
// the SDK's non-test sources and the documented operation that must serve it.
type sdkRoutePin struct {
	SDK       string
	Sources   []string
	Fragments []string
	Spec      string
	DocKey    string
}

// fragmentPresent reports whether source contains fragment as a distinct
// path token: at least one occurrence must not be continued by a path-name
// character ([A-Za-z0-9_-]). A plain substring check would accept drift by
// suffix extension (a route renamed savings → savings_v2 still contains
// "savings"); the continuation test rejects that while still accepting the
// legitimate follow-ons (quote, "?", "{", "$", "/", backtick, end of line).
func fragmentPresent(source, fragment string) bool {
	for i := 0; i+len(fragment) <= len(source); {
		idx := strings.Index(source[i:], fragment)
		if idx < 0 {
			return false
		}
		i += idx
		end := i + len(fragment)
		if end == len(source) || !isPathNameChar(source[end]) {
			return true
		}
		i++
	}
	return false
}

// isPathNameChar reports whether c continues a path or identifier token.
func isPathNameChar(c byte) bool {
	return c == '_' || c == '-' || (c >= '0' && c <= '9') ||
		(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// TestFragmentPresent pins the distinct-token semantics of the probe: a
// regression to a plain strings.Contains would accept suffix drift (a route
// renamed savings → savings_v2 still contains "savings").
func TestFragmentPresent(t *testing.T) {
	for _, tc := range []struct {
		name, source, fragment string
		want                   bool
	}{
		{"exact match (EOL after fragment)", "/api/analytics/savings", "/api/analytics/savings", true},
		{"EOL after fragment in longer source", "GET /api/analytics/savings", "/api/analytics/savings", true},
		{"quote follow-on accepted", `"/api/analytics/savings"`, "/api/analytics/savings", true},
		{"query follow-on accepted", "/api/analytics/savings?days=7", "/api/analytics/savings", true},
		{"path-parameter follow-on accepted", "/api/analytics/savings{request_id}", "/api/analytics/savings", true},
		{"backtick follow-on accepted", "`/api/analytics/savings`", "/api/analytics/savings", true},
		{"underscore suffix extension rejected", "/api/analytics/savings_v2", "/api/analytics/savings", false},
		{"letter suffix extension rejected", "/api/analytics/savingsx", "/api/analytics/savings", false},
		{"absent fragment rejected", "/api/analytics/costs", "/api/analytics/savings", false},
		{"byte-walk skips drifted hit, accepts real one", "/api/analytics/savings_v2 /api/analytics/savings?", "/api/analytics/savings", true},
	} {
		if got := fragmentPresent(tc.source, tc.fragment); got != tc.want {
			t.Errorf("%s: fragmentPresent(%q, %q) = %v, want %v", tc.name, tc.source, tc.fragment, got, tc.want)
		}
	}
}

// sdkConsumedRoutes pins the SDK wire surface to the documented specs. The
// fragments are plain source-text probes: when an SDK renames a path the
// probe fails and the spec-side key must be revisited in the same change.
var sdkConsumedRoutes = []sdkRoutePin{
	{
		SDK: "go", Sources: []string{"../../../sdks/go/yabanin.go"},
		Fragments: []string{"/v1/chat/completions"},
		Spec:      gatewayOpenAPISpec, DocKey: "POST /chat/completions",
	},
	{
		SDK: "python", Sources: []string{"../../../sdks/python/tokenrouter/client.py", "../../../sdks/python/tokenrouter/lineage.py", "../../../sdks/python/tokenrouter/errors.py"},
		Fragments: []string{"/chat/completions"},
		Spec:      gatewayOpenAPISpec, DocKey: "POST /chat/completions",
	},
	{
		SDK: "python", Sources: []string{"../../../sdks/python/tokenrouter/client.py"},
		Fragments: []string{"/api/analytics/savings"},
		Spec:      adminOpenAPISpec, DocKey: "GET /api/analytics/savings",
	},
	{
		SDK: "python", Sources: []string{"../../../sdks/python/tokenrouter/lineage.py"},
		Fragments: []string{"/api/lineage/", "{request_id}"},
		Spec:      adminOpenAPISpec, DocKey: "GET /api/lineage/{request_id}",
	},
	{
		SDK: "python", Sources: []string{"../../../sdks/python/tokenrouter/lineage.py"},
		Fragments: []string{"/api/lineage/", "{request_id}", "/verify"},
		Spec:      adminOpenAPISpec, DocKey: "POST /api/lineage/{request_id}/verify",
	},
	{
		SDK: "node", Sources: []string{"../../../sdks/node/src/client.ts"},
		Fragments: []string{"/v1/chat/completions"},
		Spec:      gatewayOpenAPISpec, DocKey: "POST /chat/completions",
	},
	{
		SDK: "node", Sources: []string{"../../../sdks/node/src/client.ts"},
		Fragments: []string{"/api/analytics/savings"},
		Spec:      adminOpenAPISpec, DocKey: "GET /api/analytics/savings",
	},
	{
		SDK: "node", Sources: []string{"../../../sdks/node/src/lineage.ts"},
		Fragments: []string{"/api/lineage/"},
		Spec:      adminOpenAPISpec, DocKey: "GET /api/lineage/{request_id}",
	},
	{
		SDK: "node", Sources: []string{"../../../sdks/node/src/lineage.ts"},
		Fragments: []string{"/api/lineage/", "/verify"},
		Spec:      adminOpenAPISpec, DocKey: "POST /api/lineage/{request_id}/verify",
	},
}

// TestSDKConsumedRoutesDocumented keeps the shipped SDK surface inside the
// documented API: every SDK route must (a) still exist verbatim in the SDK's
// non-test sources and (b) resolve to a documented operation of the matching
// spec. A route renamed in an SDK without a spec update, or dropped from a
// spec while an SDK still ships it, fails here.
func TestSDKConsumedRoutesDocumented(t *testing.T) {
	adminDoc := parseOpenAPIRoutes(t, adminOpenAPISpec)
	gatewayDoc := parseOpenAPIRoutes(t, gatewayOpenAPISpec)

	for _, pin := range sdkConsumedRoutes {
		t.Run(pin.SDK+" "+pin.DocKey, func(t *testing.T) {
			var source strings.Builder
			for _, src := range pin.Sources {
				raw, err := os.ReadFile(src) // #nosec G304 -- compile-time source path from the pin table
				if err != nil {
					t.Fatalf("read SDK source %s: %v", src, err)
				}
				source.Write(raw)
			}
			for _, frag := range pin.Fragments {
				if !fragmentPresent(source.String(), frag) {
					t.Errorf("SDK %s no longer contains %q as a distinct path token — update the SDK and %s together", pin.SDK, frag, pin.Spec)
				}
			}
			var documented map[string]routeSpec
			switch pin.Spec {
			case adminOpenAPISpec:
				documented = adminDoc
			case gatewayOpenAPISpec:
				documented = gatewayDoc
			default:
				t.Fatalf("unknown spec constant %q in the pin table", pin.Spec)
			}
			if _, ok := documented[pin.DocKey]; !ok {
				t.Errorf("SDK %s route %s is not documented in %s — every SDK-shipped route must be a spec operation",
					pin.SDK, pin.DocKey, pin.Spec)
			}
		})
	}
}
