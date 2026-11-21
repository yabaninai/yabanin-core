package cli

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"unicode/utf8"
)

// FuzzInjectReasoningEffort is a focused fuzz regression for
// injectReasoningEffort. The oracle is built independently inside this test:
// the input is re-parsed here, the expected object is derived from that parse
// plus the requested effort, and the actual output is parsed again and
// compared against it. Production code is never used to compute expectations.
//
// Invariants checked for every input:
//   - empty effort or empty body returns the input bytes unchanged;
//   - non-object or invalid JSON returns the input bytes unchanged;
//   - otherwise the output is a valid JSON object with exactly the input keys
//     plus one "reasoning_effort" string equal to the effort (override);
//   - every sibling value survives semantically unchanged with number
//     literals kept exact (integers beyond 2^53 must not be corrupted).
func FuzzInjectReasoningEffort(f *testing.F) {
	seeds := []struct {
		body   string
		effort string
	}{
		// Integer siblings beyond 2^53 must be preserved exactly.
		{`{"model":"gpt-5","max_tokens":9007199254740993,"big":123456789012345678901234567890}`, "high"},
		{`{"reasoning_effort":"low","n":9007199254740993}`, "high"}, // override + big int
		{`{"reasoning_effort":"low","model":"gpt-5"}`, "high"},      // override existing effort
		{`{"model":"gpt-5","reasoning_effort":"low"}`, ""},          // empty effort passthrough
		{"", "high"},                            // empty body passthrough
		{`{}`, "medium"},                        // empty object gains exactly the effort key
		{`[1,9007199254740993,{"a":1}]`, "low"}, // non-object array
		{`"just a string"`, "low"},              // non-object string
		{`9007199254740993`, "low"},             // non-object number
		{`true`, "low"},                         // non-object bool
		{`null`, "low"},                         // null literal (nil map)
		{`{"reasoning_effort":`, "high"},        // invalid JSON
		{`{"a":1`, "high"},                      // truncated JSON
		{`  {"ws": 1}  trailing`, "high"},       // trailing data
		// Varying UTF-8 string values, keys and efforts.
		{`{"note":"日本語のテキスト","emoji":"😀","esc":"\ud83d\ude00\u00e9"}`, "高"},
		{`{"q":"Вопрос"}`, "высокий"},
		{`{"combined":"mélange","emoji-key-🙂":9007199254740993}`, "😀"},
		// Siblings that force escape normalization on marshal.
		{`{"html":"a<b>&c","u":"\u2028\u2029"}`, "<high&>"},
		// Nested objects and arrays, with whitespace to be compacted.
		{`{"meta": { "n" : 9007199254740993 } , "a":[ 1, 2 ]}`, "medium"},
		{`{"arr":[{"z":9007199254740993},true,null,"é"]}`, "low"},
		// Duplicate keys collapse the same way encoding/json does.
		{`{"reasoning_effort":"low","reasoning_effort":"medium","x":9007199254740993}`, "high"},
	}
	for _, s := range seeds {
		f.Add([]byte(s.body), s.effort)
	}

	f.Fuzz(func(t *testing.T, body []byte, effort string) {
		got := injectReasoningEffort(body, effort)

		// Empty effort or empty body: unchanged passthrough.
		if effort == "" || len(body) == 0 {
			assertUnchangedPassthrough(t, body, got)
			return
		}

		// Independent parse of the input (test-side oracle, never the
		// production path); non-object or invalid input passes through.
		in, isObject := parseReasoningEffortTestInput(body)
		if !isObject {
			assertUnchangedPassthrough(t, body, got)
			return
		}

		assertInjectedReasoningEffortObject(t, body, effort, in, got)
	})
}

// parseReasoningEffortTestInput is the independent oracle parse of the fuzz
// input. It reports false when body is not a JSON object (including invalid
// JSON and the null literal), which must pass through unchanged.
func parseReasoningEffortTestInput(body []byte) (map[string]json.RawMessage, bool) {
	var in map[string]json.RawMessage
	if err := json.Unmarshal(body, &in); err != nil || in == nil {
		return nil, false
	}
	return in, true
}

// assertInjectedReasoningEffortObject verifies the injection path: the output
// is a valid JSON object with exactly the input keys plus one
// "reasoning_effort", every sibling preserved semantically, and the effort
// value equal to the request.
func assertInjectedReasoningEffortObject(t *testing.T, body []byte, effort string, in map[string]json.RawMessage, got []byte) {
	t.Helper()

	var out map[string]json.RawMessage
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatalf("output is not a valid JSON object: %v\n input: %s\neffort: %q\noutput: %s", err, body, effort, got)
	}

	assertReasoningEffortKeySet(t, body, in, out, got)
	assertReasoningEffortSiblings(t, body, in, out, got)
	assertReasoningEffortValue(t, body, effort, out, got)
}

// assertReasoningEffortKeySet fails unless the output object holds exactly
// the input keys plus one "reasoning_effort": no extra, no missing and no
// duplicate keys (map semantics collapse duplicates on both sides).
func assertReasoningEffortKeySet(t *testing.T, body []byte, in, out map[string]json.RawMessage, got []byte) {
	t.Helper()
	wantKeys := make(map[string]struct{}, len(in)+1)
	for k := range in {
		wantKeys[k] = struct{}{}
	}
	wantKeys["reasoning_effort"] = struct{}{}
	if len(out) != len(wantKeys) {
		t.Fatalf("output has %d keys, want %d (no extra, no missing, no duplicates)\n input: %s\noutput: %s",
			len(out), len(wantKeys), body, got)
	}
}

// assertReasoningEffortSiblings fails unless every non-effort input key is
// present in the output with a semantically identical value, keeping number
// literals exact.
func assertReasoningEffortSiblings(t *testing.T, body []byte, in, out map[string]json.RawMessage, got []byte) {
	t.Helper()
	for k, wantRaw := range in {
		if k == "reasoning_effort" {
			continue // replaced; checked separately
		}
		gotRaw, ok := out[k]
		if !ok {
			t.Fatalf("sibling key %q missing from output\n input: %s\noutput: %s", k, body, got)
		}
		if !sameJSONValue(wantRaw, gotRaw) {
			t.Fatalf("sibling %q changed\n input: %s\n want: %s\noutput: %s", k, body, wantRaw, got)
		}
	}
}

// assertReasoningEffortValue fails unless the single injected/overridden
// "reasoning_effort" key is a JSON string equal to the requested effort.
func assertReasoningEffortValue(t *testing.T, body []byte, effort string, out map[string]json.RawMessage, got []byte) {
	t.Helper()
	gotEffortRaw, ok := out["reasoning_effort"]
	if !ok {
		t.Fatalf("reasoning_effort missing from output\n input: %s\noutput: %s", body, got)
	}
	var gotEffort string
	if err := json.Unmarshal(gotEffortRaw, &gotEffort); err != nil {
		t.Fatalf("reasoning_effort is not a JSON string: %v\noutput: %s", err, got)
	}
	// encoding/json coerces invalid UTF-8 in strings, so demand exact
	// equality only for valid UTF-8 efforts.
	if utf8.ValidString(effort) && gotEffort != effort {
		t.Fatalf("reasoning_effort = %q, want %q\noutput: %s", gotEffort, effort, got)
	}
}

// assertUnchangedPassthrough fails the test unless got is byte-identical to
// the input, as required for empty effort and non-object/invalid bodies.
func assertUnchangedPassthrough(t *testing.T, input, got []byte) {
	t.Helper()
	if !bytes.Equal(input, got) {
		t.Fatalf("expected unchanged passthrough\n input: %q\noutput: %q", input, got)
	}
}

// sameJSONValue compares two raw JSON values semantically. Numbers are
// compared as json.Number, so integer literals beyond 2^53 must match
// exactly, while string escape forms ("<" vs "\u003c") compare equal.
func sameJSONValue(a, b json.RawMessage) bool {
	var av, bv interface{}
	da := json.NewDecoder(bytes.NewReader(a))
	da.UseNumber()
	db := json.NewDecoder(bytes.NewReader(b))
	db.UseNumber()
	return da.Decode(&av) == nil && db.Decode(&bv) == nil && reflect.DeepEqual(av, bv)
}

func TestInjectReasoningEffortRegression(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		effort string
		want   string
	}{
		{
			name:   "integer literals beyond 2^53 preserved exactly",
			body:   `{"max_tokens":9007199254740993,"big":123456789012345678901234567890}`,
			effort: "high",
			want:   `{"big":123456789012345678901234567890,"max_tokens":9007199254740993,"reasoning_effort":"high"}`,
		},
		{
			name:   "existing reasoning_effort overridden",
			body:   `{"reasoning_effort":"low","model":"gpt-5"}`,
			effort: "high",
			want:   `{"model":"gpt-5","reasoning_effort":"high"}`,
		},
		{
			name:   "utf-8 values and effort round-trip",
			body:   `{"note":"日本語","emoji":"😀"}`,
			effort: "высокий",
			want:   `{"emoji":"😀","note":"日本語","reasoning_effort":"высокий"}`,
		},
		{
			name:   "nested whitespace compacted, nested big int preserved",
			body:   `{"meta": { "n" : 9007199254740993 } , "a":[ 1, 2 ]}`,
			effort: "medium",
			want:   `{"a":[1,2],"meta":{"n":9007199254740993},"reasoning_effort":"medium"}`,
		},
		{
			name:   "empty effort passes through unchanged",
			body:   `{"model":"gpt-5","reasoning_effort":"low"}`,
			effort: "",
			want:   `{"model":"gpt-5","reasoning_effort":"low"}`,
		},
		{
			name:   "empty body passes through unchanged",
			body:   ``,
			effort: "high",
			want:   ``,
		},
		{
			name:   "non-object array passes through unchanged",
			body:   `[9007199254740993,"x"]`,
			effort: "high",
			want:   `[9007199254740993,"x"]`,
		},
		{
			name:   "null passes through unchanged",
			body:   `null`,
			effort: "high",
			want:   `null`,
		},
		{
			name:   "invalid json passes through unchanged",
			body:   `{"reasoning_effort":`,
			effort: "high",
			want:   `{"reasoning_effort":`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := injectReasoningEffort([]byte(tc.body), tc.effort)
			if string(got) != tc.want {
				t.Fatalf("injectReasoningEffort(%q, %q)\n got: %s\nwant: %s", tc.body, tc.effort, got, tc.want)
			}
		})
	}
}

// assertUnchangedPassthrough fails the test unless got is byte-identical to
// the input, as required for empty effort and non-object/invalid bodies.
