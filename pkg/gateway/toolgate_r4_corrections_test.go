package cli

// R4 CORRECTIONS (astra-auth-sse-r4-verdict.txt, sha256 f34dd40b…):
// the five REQUEST_CHANGES items, each with original/fixed/isolated
// evidence. This file pins the REQUIRED behavior; at the time it was
// written the production surface fails every test here (original
// evidence), because:
//
//   R4-1a a finished choice is held behind every unfinished sibling
//         (choicesComplete's len(executing)==0) and an ambiguous finish
//         releases unresolved fragments (choicesComplete returns true);
//   R4-2  the refresh and filter key off literal "tool_calls" bytes and a
//         literal "data: " prefix: `data:` without a space passes the
//         gate unfiltered and escaped member names (\u0074ool_calls)
//         never activate it;
//   R4-3  resolveIdentities mutates g.indexed while walking, so a member
//         missing its index BEFORE the first explicit index borrows a
//         sibling's key (argument merge, sticky deny) and the replay
//         after g.indexed changed cannot undo it.
//
// Events are read with r4Events — an INDEPENDENT SSE event reader that
// parses data fields with and without the optional space and decodes
// JSON member names, never literal prefixes.

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/toolexec"
	"github.com/reireirei/yabanin/pkg/toolpolicy"
)

// ---- independent event reader (R4-2: no literal prefix dependence) ----

type r4CallFrag struct {
	Index    *int `json:"index"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type r4EventDoc struct {
	Choices []struct {
		Index  *int   `json:"index"`
		Finish string `json:"finish_reason"`
		Delta  struct {
			ToolCalls []r4CallFrag `json:"tool_calls"`
		} `json:"delta"`
	} `json:"choices"`
}

// r4EventData joins the data fields of one SSE event per the spec: each
// data line contributes its value (one optional leading space removed),
// lines join with "\n".
func r4EventData(frame string) (string, bool) {
	if !strings.HasSuffix(frame, "\n\n") {
		frame += "\n"
	}
	var parts []string
	for _, line := range strings.Split(frame, "\n") {
		if line == "" {
			continue
		}
		rest, ok := strings.CutPrefix(line, "data:")
		if !ok {
			continue // event:, id:, comment — not payload
		}
		rest = strings.TrimPrefix(rest, " ")
		parts = append(parts, rest)
	}
	if len(parts) == 0 {
		return "", false
	}
	return strings.Join(parts, "\n"), true
}

// r4Events reads a whole emitted stream into decoded documents.
func r4Events(t *testing.T, stream string) []r4EventDoc {
	t.Helper()
	var docs []r4EventDoc
	for _, frame := range strings.Split(stream, "\n\n") {
		data, ok := r4EventData(frame)
		if !ok || data == "" || data == "[DONE]" {
			continue
		}
		var doc r4EventDoc
		if err := json.Unmarshal([]byte(data), &doc); err != nil {
			continue // tolerant: non-JSON data events are not tool events
		}
		docs = append(docs, doc)
	}
	return docs
}

// r4Names lists every declared tool name in the stream (any choice).
func r4Names(docs []r4EventDoc) []string {
	var names []string
	for _, d := range docs {
		for _, c := range d.Choices {
			for _, tc := range c.Delta.ToolCalls {
				if tc.Function.Name != "" {
					names = append(names, tc.Function.Name)
				}
			}
		}
	}
	return names
}

// ---- fixtures ----

// r4Loader serves fixed rows; web_fetch is denied outright, time_now is
// allowed (the benign sibling).
type r4Loader struct{ rows []toolpolicy.Policy }

func (l r4Loader) ListEnabled(context.Context, string) ([]toolpolicy.Policy, error) {
	return l.rows, nil
}

func r4EngineRows() []toolpolicy.Policy {
	return []toolpolicy.Policy{
		{ID: "d1", OrgID: "org-r4", Name: "deny-fetch", Subject: "*", Server: "*",
			Tool: toolexec.ToolWebFetch, Action: toolpolicy.ActionDeny, Enabled: true, Priority: -1},
		{ID: "a1", OrgID: "org-r4", Name: "allow-time", Subject: "*", Server: "*",
			Tool: toolexec.ToolTimeNow, Action: toolpolicy.ActionAllow, Enabled: true},
	}
}

func r4Writer(t *testing.T, rows []toolpolicy.Policy) (*sseToolGateWriter, *httptest.ResponseRecorder) {
	t.Helper()
	e := toolpolicy.NewEngine(r4Loader{rows: rows}, time.Minute)
	w := httptest.NewRecorder()
	g := newSSEToolGateWriter(context.Background(), w, e, "org-r4", "alice",
		e.HasDenyPolicies(context.Background(), "org-r4"))
	return g, w
}

// r4RawWrite writes a pre-framed SSE event (the framing is the object
// under test: with/without the optional space).
func r4RawWrite(t *testing.T, g *sseToolGateWriter, event string) {
	t.Helper()
	if _, err := g.Write([]byte(event)); err != nil {
		t.Fatalf("r4RawWrite: %v", err)
	}
}

// r4Frame marshals one data event with the given choices, canonical
// framing with space.
func r4Frame(t *testing.T, choices ...map[string]any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"choices": choices})
	if err != nil {
		t.Fatalf("r4Frame: %v", err)
	}
	return "data: " + string(b) + "\n\n"
}

func r4Call(index int, name, args string) map[string]any {
	call := map[string]any{}
	if index >= 0 {
		call["index"] = index
	}
	fn := map[string]any{}
	if name != "" {
		fn["name"] = name
	}
	if args != "" {
		fn["arguments"] = args
	}
	call["function"] = fn
	return call
}

func r4Choice(index *int, finish string, calls ...map[string]any) map[string]any {
	delta := map[string]any{}
	if len(calls) > 0 {
		delta["tool_calls"] = calls
	}
	choice := map[string]any{"delta": delta}
	if index != nil {
		choice["index"] = *index
	}
	if finish != "" {
		choice["finish_reason"] = finish
	}
	return choice
}

// ---- R4-1a: a finished choice must not wait for every sibling; release
// timing is captured BEFORE the sibling's arguments complete. ----

func r4EarlyChoiceState(docs []r4EventDoc) (args, finish, siblingVisible bool) {
	for _, doc := range docs {
		for _, choice := range doc.Choices {
			if choice.Index == nil {
				continue
			}
			switch *choice.Index {
			case 0:
				if len(choice.Delta.ToolCalls) > 0 {
					args = true
				}
				if choice.Finish != "" {
					finish = true
				}
			case 1:
				siblingVisible = true
			}
		}
	}
	return args, finish, siblingVisible
}

func TestR4_PerChoiceReleaseBeforeSiblingArgsComplete(t *testing.T) {
	zero, one := 0, 1
	g, w := r4Writer(t, r4EngineRows())
	r4RawWrite(t, g, r4Frame(t, r4Choice(&zero, "", r4Call(0, "time_now", `"{}"`))))
	r4RawWrite(t, g, r4Frame(t, r4Choice(&one, "", r4Call(0, "time_now", `"A"`))))
	r4RawWrite(t, g, r4Frame(t, r4Choice(&zero, "stop")))

	args, finish, siblingVisible := r4EarlyChoiceState(r4Events(t, w.Body.String()))
	if !args || !finish {
		t.Fatalf("R4-1a: finished choice 0 must release before the sibling completes (args=%v finish=%v, stream=%q)",
			args, finish, w.Body.String())
	}
	if siblingVisible {
		t.Fatalf("R4-1a: still-executing choice 1 must stay held (stream=%q)", w.Body.String())
	}

	r4RawWrite(t, g, r4Frame(t, r4Choice(&one, "stop")))
	r4RawWrite(t, g, "data: [DONE]\n\n")
	docs := r4Events(t, w.Body.String())
	if names := r4Names(docs); len(names) != 2 || names[0] != "time_now" || names[1] != "time_now" {
		t.Fatalf("R4-1a: both allowed calls must survive in order, names=%v", names)
	}
}

// ---- R4-1b: an ambiguous finish completes no choice and must not
// release unresolved fragments. ----

func TestR4_AmbiguousFinishReleasesNothing(t *testing.T) {
	zero, one := 0, 1
	g, w := r4Writer(t, r4EngineRows())

	// Establish an indexed stream with two executing choices.
	r4RawWrite(t, g, r4Frame(t, r4Choice(&zero, "", r4Call(0, "time_now", `"{}"`))))
	r4RawWrite(t, g, r4Frame(t, r4Choice(&one, "", r4Call(0, "time_now", `"B"`))))

	// A frame whose FIRST member is missing its index and carries a
	// finish (unattributable), plus a still-executing indexed sibling.
	r4RawWrite(t, g, r4Frame(t,
		r4Choice(nil, "stop", r4Call(0, "time_now", `"X"`)),
		r4Choice(&one, "", r4Call(0, "time_now", `"C"`))))

	if docs := r4Events(t, w.Body.String()); len(docs) != 0 {
		t.Fatalf("R4-1b: an ambiguous finish must release nothing while choice 1 is unresolved (stream=%q)", w.Body.String())
	}

	// The terminal then releases: the ambiguous member's fragments drop,
	// the two indexed allowed calls survive.
	r4RawWrite(t, g, "data: [DONE]\n\n")
	docs := r4Events(t, w.Body.String())
	names := r4Names(docs)
	if len(names) != 3 { // f1 + f2 + the released frame's c1 chunk (each carries its name)
		t.Fatalf("R4-1b: terminal must release both indexed calls (three name-bearing fragments), got %d names (stream=%q)", len(names), w.Body.String())
	}
	for _, n := range names {
		if n != "time_now" {
			t.Fatalf("R4-1b: only the allowed tool may survive, names=%v", names)
		}
	}
	for _, d := range docs {
		for _, c := range d.Choices {
			if c.Index == nil {
				for _, tc := range c.Delta.ToolCalls {
					if tc.Function.Arguments == `"X"` {
						t.Fatalf("R4-1b: the ambiguous member's fragments must drop (stream=%q)", w.Body.String())
					}
				}
			}
		}
	}
}

// ---- R4-2a: `data:` without a space is consumer-readable SSE. ----

func TestR4_DataFieldWithoutSpaceIsGated(t *testing.T) {
	zero := 0
	g, w := r4Writer(t, r4EngineRows())

	frame := r4Frame(t, r4Choice(&zero, "tool_calls", r4Call(0, toolexec.ToolWebFetch, `"{}"`)))
	noSpace := strings.Replace(frame, "data: ", "data:", 1)
	r4RawWrite(t, g, noSpace)
	r4RawWrite(t, g, "data: [DONE]\n\n")

	if names := r4Names(r4Events(t, w.Body.String())); len(names) != 0 {
		t.Fatalf("R4-2a: a denied declaration in a no-space data field must not reach the consumer, names=%v stream=%q",
			names, w.Body.String())
	}
}

// ---- R4-2b: escaped JSON member names carry declarations the literal
// byte match never sees; the gate must filter on the DECODED member. ----

func r4EscapeMember(frame string) string {
	out := strings.ReplaceAll(frame, `"tool_calls"`, `"\u0074ool_calls"`)
	if out == frame || !strings.Contains(out, `\u0074ool_calls`) {
		panic("test bug: escape not applied")
	}
	return out
}

func TestR4_EscapedMemberNameFilteredWhenActive(t *testing.T) {
	zero := 0
	g, w := r4Writer(t, r4EngineRows())

	r4RawWrite(t, g, r4EscapeMember(
		r4Frame(t, r4Choice(&zero, "tool_calls", r4Call(0, toolexec.ToolWebFetch, `"{}"`)))))
	r4RawWrite(t, g, "data: [DONE]\n\n")

	if names := r4Names(r4Events(t, w.Body.String())); len(names) != 0 {
		t.Fatalf("R4-2b(active): a denied declaration under an escaped member name must not reach the consumer, names=%v stream=%q",
			names, w.Body.String())
	}
}

func TestR4_EscapedMemberNameActivatesInactiveGate(t *testing.T) {
	e, l := newRevEngine(t)
	g, w := revWriter(t, e) // opens inactive: org has no deny rows yet

	revWrite(t, g, `{"choices":[{"index":0,"delta":{"content":"hi"}}]}`) // in flight
	l.revoke(e, "org-rev", revDenyWebFetch())
	time.Sleep(10 * time.Millisecond) // the response is genuinely in flight

	// The post-bound declaration escapes the member name: the decoded
	// member must refresh applicability and gate the revoked tool.
	r4RawWrite(t, g, r4EscapeMember(
		r4Frame(t, r4Choice(nil, "tool_calls", r4Call(0, toolexec.ToolWebFetch, `"{}"`)))))
	revDone(t, g)

	if names := r4Names(r4Events(t, w.Body.String())); len(names) != 0 {
		t.Fatalf("R4-2b(activate): the revoked declaration under an escaped member name must be gated, names=%v stream=%q",
			names, w.Body.String())
	}
}

// ---- R4-3: a member missing its index BEFORE the first explicit index
// must not borrow a valid sibling's key (original order, fresh stream). ----

func r4ArgumentSeparation(docs []r4EventDoc) (legitArgs string, sawForeign bool) {
	for _, doc := range docs {
		for _, choice := range doc.Choices {
			for _, call := range choice.Delta.ToolCalls {
				if call.Function.Name == "time_now" && call.Function.Arguments != "" {
					legitArgs += call.Function.Arguments
				}
				if strings.Contains(call.Function.Arguments, "FOREIGN") {
					sawForeign = true
				}
			}
		}
	}
	return legitArgs, sawForeign
}

func TestR4_MissingIndexBeforeFirstExplicitIndexNoBorrow(t *testing.T) {
	zero := 0
	g, w := r4Writer(t, r4EngineRows())
	r4RawWrite(t, g, r4Frame(t,
		r4Choice(nil, "", r4Call(0, "", `"{FOREIGN}"`)),
		r4Choice(&zero, "", r4Call(0, "time_now", `"{LEGIT}"`))))
	r4RawWrite(t, g, "data: [DONE]\n\n")

	legitArgs, sawForeign := r4ArgumentSeparation(r4Events(t, w.Body.String()))
	if sawForeign {
		t.Fatalf("R4-3: the ambiguous member's fragments must drop on release (stream=%q)", w.Body.String())
	}
	if legitArgs != `"{LEGIT}"` {
		t.Fatalf("R4-3: the sibling's arguments must not absorb the ambiguous member's chunks, got %q (stream=%q)",
			legitArgs, w.Body.String())
	}

	g2, w2 := r4Writer(t, r4EngineRows())
	r4RawWrite(t, g2, r4Frame(t,
		r4Choice(nil, "", r4Call(0, toolexec.ToolWebFetch, `"{X}"`)),
		r4Choice(&zero, "", r4Call(0, "time_now", `"{LEGIT}"`))))
	r4RawWrite(t, g2, "data: [DONE]\n\n")
	if names := r4Names(r4Events(t, w2.Body.String())); len(names) != 1 || names[0] != "time_now" {
		t.Fatalf("R4-3: the sibling must not inherit the ambiguous member's denied verdict, names=%v stream=%q",
			names, w2.Body.String())
	}
}
