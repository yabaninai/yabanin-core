package cli

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

// FuzzEnsureStreamUsageAccounting regression-fuzzes the normal streaming
// token-accounting matrix of ensureStreamUsage:
//
//   - provider lists: nil list, empty list, nonempty list with the provider
//     enabled, nonempty list with it disabled (an empty provider name is the
//     "openai-compat" alias);
//   - stream_options.include_usage modes: stream_options absent, explicit
//     true, explicit false, stream_options present without the key;
//   - a raw fuzzed body exercising the fail-open arms: bodies that are not
//     JSON objects and bodies whose stream_options value is not a JSON
//     object must pass through byte-identically with clientRequested=true.
//
// For every combination it independently asserts the returned client
// preference (clientRequested), that the upstream body now requests usage,
// that the generated model string and sibling option values survive, that the
// whole body is otherwise semantically unchanged, and that passthrough cases
// return byte-identical bodies. Seeds are hermetic deterministic constants;
// there is no I/O, clock or randomness beyond the fuzzing engine itself.
func FuzzEnsureStreamUsageAccounting(f *testing.F) {
	// Hermetic deterministic seed corpus covering representative model and
	// provider strings, empty names, unicode, quotes and control bytes.
	// The trailing raw-body field is empty in every seed: the matrix seeds
	// stay focused on the accounting columns, and the raw fail-open case is
	// reached through fuzzing plus any raw string the engine derives.
	f.Add("case", "other-gw", "field", "one", "field", "two", `{"stream_options":[1,2]}`)
	f.Add("gpt-4o-mini", "acme-prod", "user_locale", "en-US", "cache", "on", "")
	f.Add("", "", "", "", "", "", "")
	f.Add("claude-3-5-sonnet", "openai-compat", "label", "beta", "retry", "3", "")
	f.Add("供应商-gw-model", "网关", "标签", "值", "选项", "真", "")
	f.Add("m\"q\"t", "p\\r", "k\n1", "v\t2", "sok <&>", "sov <&>", "")
	f.Add("model-éü", "", "user", " Alice ", "tol", "0.7", "")
	f.Add("", "other-gw", "", "", "", "", `[1,2,3]`)

	f.Fuzz(func(t *testing.T, model, provider, sibKeyRaw, sibVal, soSibKeyRaw, soSibVal, raw string) {
		checkStreamUsageEnabledSets(t)

		// An empty provider name resolves to the "openai-compat" alias.
		effective := provider
		if effective == "" {
			effective = "openai-compat"
		}

		// Fixed key prefixes keep fuzz-generated values clear of the
		// structural names (model, stream, stream_options, include_usage);
		// the raw fuzz strings are folded into the sibling values.
		runAccountingMatrix(t, effective, accountingInputs{
			model:    model,
			provider: provider,
			sibKey:   "sib_key",
			sibVal:   sibVal + sibKeyRaw,
			soSibKey: "opt_key",
			soSibVal: soSibVal + soSibKeyRaw,
		})
		runRawStreamUsageCase(t, raw, effective)
	})
}

// accountingInputs carries one fuzz iteration's derived request fields
// through the matrix helpers.
type accountingInputs struct {
	model    string
	provider string
	sibKey   string
	sibVal   string
	soSibKey string
	soSibVal string
}

// checkStreamUsageEnabledSets verifies the gateway provider sets keep their
// documented shape.
func checkStreamUsageEnabledSets(t *testing.T) {
	t.Helper()
	if got := streamUsageEnabled(nil); got != nil {
		t.Fatalf("streamUsageEnabled(nil) = %v, want nil", got)
	}
	if got := streamUsageEnabled([]string{}); got != nil {
		t.Fatalf("streamUsageEnabled(empty) = %v, want nil", got)
	}
	if m := streamUsageEnabled([]string{"a", "a", "b"}); m == nil || !m["a"] || !m["b"] || m["c"] {
		t.Fatalf("streamUsageEnabled(nonempty) = %v, want set {a,b}", m)
	}
}

// accountingListCase is one provider-list column of the accounting matrix.
type accountingListCase struct {
	name    string
	enabled map[string]bool
	injects bool
}

// accountingOptionCase is one stream_options.include_usage row of the matrix.
type accountingOptionCase struct {
	name    string
	mode    string
	injects bool
}

// accountingProviderLists builds the provider-list columns. The enabled and
// disabled sets are disjoint by construction and asserted to stay that way.
func accountingProviderLists(t *testing.T, effective string) []accountingListCase {
	t.Helper()
	enabled := streamUsageEnabled([]string{"other-gw", effective, "also:" + effective})
	disabled := streamUsageEnabled([]string{"disabled:" + effective})
	if !enabled[effective] {
		t.Fatalf("enabled list must contain %q", effective)
	}
	if disabled[effective] {
		t.Fatalf("disabled list must not contain %q", effective)
	}
	return []accountingListCase{
		{"nil provider list", streamUsageEnabled(nil), false},
		{"empty provider list", streamUsageEnabled([]string{}), false},
		{"nonempty enabled list", enabled, true},
		{"nonempty disabled list", disabled, false},
	}
}

// accountingOptionModes lists the stream_options.include_usage rows.
func accountingOptionModes() []accountingOptionCase {
	return []accountingOptionCase{
		{"stream_options absent", "absent", true},
		{"include_usage explicit true", "true", false},
		{"include_usage explicit false", "false", true},
		{"stream_options without include_usage", "nokey", true},
	}
}

// runAccountingMatrix walks every provider-list × stream_options combination
// and applies the per-case assertions.
func runAccountingMatrix(t *testing.T, effective string, in accountingInputs) {
	t.Helper()
	for _, list := range accountingProviderLists(t, effective) {
		for _, opt := range accountingOptionModes() {
			runAccountingCase(t, list, opt, in)
		}
	}
}

// runAccountingCase exercises one matrix cell: clientRequested must reflect
// whether injection happens, passthrough cells must be byte-identical, and
// injection cells must match the expected rewritten body.
func runAccountingCase(t *testing.T, list accountingListCase, opt accountingOptionCase, in accountingInputs) {
	t.Helper()
	body := accountingBody(t, in.model, in.sibKey, in.sibVal, in.soSibKey, in.soSibVal, opt.mode)
	out, clientRequested := ensureStreamUsage(body, in.provider, list.enabled)

	injects := list.injects && opt.injects
	if wantRequested := !injects; clientRequested != wantRequested {
		t.Fatalf("%s / %s: clientRequested = %v, want %v",
			list.name, opt.name, clientRequested, wantRequested)
	}
	if injects {
		// Injection path: the upstream must now be told to report usage
		// while everything else survives.
		assertInjectedAccounting(t, list.name, opt.name, body, out)
		return
	}
	// Disabled provider or usage already requested by the client: the body
	// must pass through byte-identically.
	assertAccountingPassthrough(t, list.name, opt.name, body, out)
}

// assertAccountingPassthrough requires the rewrite to be a byte-exact no-op.
func assertAccountingPassthrough(t *testing.T, listName, optName string, in, out []byte) {
	t.Helper()
	if !bytes.Equal(out, in) {
		t.Fatalf("%s / %s: passthrough bytes changed:\nin:  %s\nout: %s",
			listName, optName, in, out)
	}
}

// assertInjectedAccounting compares the rewritten body with one independently
// decoded expected object: the client's request with
// stream_options.include_usage explicitly set to true. reflect.DeepEqual on
// that object proves include_usage became boolean true (not a string or
// number) and that the model, extension fields and every other option are
// preserved.
func assertInjectedAccounting(t *testing.T, listName, optName string, in, out []byte) {
	t.Helper()
	want := expectedInjectedBody(t, in)
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("%s / %s: decode output body as any: %v", listName, optName, err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s / %s: body semantics changed:\nwant %#v\ngot  %#v",
			listName, optName, want, got)
	}
}

// expectedInjectedBody decodes the request the client sent and returns the
// object the upstream should receive: the same object with
// stream_options.include_usage set to true.
func expectedInjectedBody(t *testing.T, in []byte) map[string]any {
	t.Helper()
	var want map[string]any
	if err := json.Unmarshal(in, &want); err != nil {
		t.Fatalf("decode input body as any: %v", err)
	}
	want["stream_options"] = mergedStreamOptions(want["stream_options"])
	return want
}

// mergedStreamOptions keeps existing stream_options siblings and forces
// include_usage to boolean true.
func mergedStreamOptions(prev any) map[string]any {
	soWant := map[string]any{"include_usage": true}
	prevSO, ok := prev.(map[string]any)
	if !ok {
		return soWant
	}
	for k, v := range prevSO {
		if k != "include_usage" {
			soWant[k] = v
		}
	}
	return soWant
}

// accountingBody assembles a normal streaming request body in the given
// include_usage mode with the fuzz-generated model and sibling values.
func accountingBody(t *testing.T, model, sibKey, sibVal, soSibKey, soSibVal, mode string) []byte {
	t.Helper()
	root := map[string]json.RawMessage{
		"model":      jsonStr(t, model),
		"stream":     json.RawMessage("true"),
		"max_tokens": json.RawMessage("128"),
		sibKey:       jsonStr(t, sibVal),
	}
	if so := accountingStreamOptions(t, mode, soSibKey, soSibVal); so != nil {
		soBytes, err := json.Marshal(so)
		if err != nil {
			t.Fatalf("marshal stream_options: %v", err)
		}
		root["stream_options"] = soBytes
	}
	body, err := json.Marshal(root)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	return body
}

// accountingStreamOptions builds the stream_options value for the given
// include_usage mode, or nil when the mode leaves stream_options absent.
func accountingStreamOptions(t *testing.T, mode, soSibKey, soSibVal string) map[string]json.RawMessage {
	t.Helper()
	switch mode {
	case "absent":
		return nil
	case "true":
		return map[string]json.RawMessage{"include_usage": json.RawMessage("true"), soSibKey: jsonStr(t, soSibVal)}
	case "false":
		return map[string]json.RawMessage{"include_usage": json.RawMessage("false"), soSibKey: jsonStr(t, soSibVal)}
	case "nokey":
		return map[string]json.RawMessage{soSibKey: jsonStr(t, soSibVal)}
	default:
		t.Fatalf("unknown mode %q", mode)
		return nil
	}
}

// jsonStr marshals s into a quoted JSON string literal.
func jsonStr(t *testing.T, s string) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal string %q: %v", s, err)
	}
	return b
}

// runRawStreamUsageCase exercises the fail-open arms of ensureStreamUsage
// with an independently classified raw body: any body that is not a JSON
// object, and any body whose stream_options value is not a JSON object,
// must pass through byte-identically with clientRequested=true (the
// documented fail-open contract). Injectable object bodies are left to the
// accounting matrix above, which already covers them exhaustively.
func runRawStreamUsageCase(t *testing.T, raw, effective string) {
	t.Helper()
	if raw == "" {
		return
	}
	enabled := streamUsageEnabled([]string{effective})
	var root map[string]json.RawMessage
	rootErr := json.Unmarshal([]byte(raw), &root)
	isObj := rootErr == nil && root != nil
	soBroken := false
	if isObj {
		if soRaw, has := root["stream_options"]; has {
			var so map[string]json.RawMessage
			soBroken = json.Unmarshal(soRaw, &so) != nil || so == nil
		}
	}
	if isObj && !soBroken {
		return // injectable body: covered by the accounting matrix
	}
	out, requested := ensureStreamUsage([]byte(raw), effective, enabled)
	if !bytes.Equal(out, []byte(raw)) || !requested {
		t.Fatalf("raw body %q: fail-open passthrough broken: out %q requested %v",
			raw, out, requested)
	}
}
