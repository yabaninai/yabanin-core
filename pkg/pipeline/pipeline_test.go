package pipeline

import (
	"testing"
)

func TestActionRank(t *testing.T) {
	cases := []struct {
		a    Action
		want int
	}{
		{ActionAllow, 0},
		{ActionFlag, 1},
		{ActionMask, 2},
		{ActionDeny, 3},
		{Action("nuclear"), 3}, // unknown ranks as deny: fail closed
		{Action(""), 3},
	}
	for _, c := range cases {
		if got := c.a.Rank(); got != c.want {
			t.Errorf("Rank(%q) = %d, want %d", c.a, got, c.want)
		}
	}
}

func TestActionMax(t *testing.T) {
	known := []Action{ActionAllow, ActionFlag, ActionMask, ActionDeny}
	for _, a := range known {
		for _, b := range known {
			want := a
			if b.Rank() > a.Rank() {
				want = b
			}
			if got := a.Max(b); got != want {
				t.Errorf("Max(%q, %q) = %q, want %q", a, b, got, want)
			}
		}
	}
	// Unknown actions normalize to deny, never produce foreign verdicts.
	if got := Action("weird").Max(ActionAllow); got != ActionDeny {
		t.Errorf("Max(unknown, allow) = %q, want deny", got)
	}
	if got := ActionAllow.Max(Action("weird")); got != ActionDeny {
		t.Errorf("Max(allow, unknown) = %q, want deny", got)
	}
	if got := Action("weird").Max(ActionMask); got != ActionDeny {
		t.Errorf("Max(unknown, mask) = %q, want deny", got)
	}
}

func TestPayloadKindValid(t *testing.T) {
	for _, k := range []PayloadKind{
		KindRequest, KindResponse, KindStreamPrefix, KindStreamFinal, KindToolArgs, KindToolResult,
	} {
		if !k.Valid() {
			t.Errorf("kind %q should be valid", k)
		}
	}
	if PayloadKind("query").Valid() {
		t.Error("unknown kind should be invalid")
	}
}

func TestPayloadCloneDeepIndependence(t *testing.T) {
	p := &Payload{
		Kind:        KindRequest,
		Endpoint:    "chat",
		StreamChunk: "chunk",
		Messages:    []Message{{Role: "user", Content: "hi"}},
		Body:        []byte(`{"x":1}`),
		Meta: &RequestMeta{
			Org: "org-a", Key: "key-1", Model: "m", Provider: "p",
			Labels: map[string]string{"team": "core"},
			Tags:   []string{"t1"},
		},
	}
	c := p.Clone()
	if c == p {
		t.Fatal("Clone must return a new pointer")
	}
	c.Messages[0].Content = "mutated"
	c.Body[0] = 'X'
	c.StreamChunk = "mutated"
	c.Meta.Org = "org-b"
	c.Meta.Labels["team"] = "mutated"
	c.Meta.Tags[0] = "mutated"

	if p.Messages[0].Content != "hi" || string(p.Body) != `{"x":1}` ||
		p.StreamChunk != "chunk" || p.Meta.Org != "org-a" ||
		p.Meta.Labels["team"] != "core" || p.Meta.Tags[0] != "t1" {
		t.Fatalf("clone mutation leaked into original: %+v", p)
	}
}

func TestPayloadCloneNil(t *testing.T) {
	var p *Payload
	if p.Clone() != nil {
		t.Fatal("nil payload must clone to nil")
	}
}

func TestPayloadCloneMinimal(t *testing.T) {
	p := &Payload{Kind: KindResponse}
	c := p.Clone()
	if c == nil || c.Meta != nil || c.Messages != nil || c.Body != nil {
		t.Fatalf("minimal clone changed shape: %+v", c)
	}
	if c.Kind != KindResponse {
		t.Fatalf("clone lost Kind: %v", c.Kind)
	}
}

func TestPayloadEqual(t *testing.T) {
	base := &Payload{
		Kind:     KindRequest,
		Endpoint: "chat",
		Messages: []Message{{Role: "user", Content: "hi"}},
		Body:     []byte("body"),
		Meta:     &RequestMeta{Org: "o", Labels: map[string]string{"a": "b"}},
	}
	if !payloadEqual(base, base.Clone()) {
		t.Fatal("payload must equal its clone")
	}

	mut := base.Clone()
	mut.Body = []byte("BODY")
	if payloadEqual(base, mut) {
		t.Error("different Body must not be equal")
	}
	mut = base.Clone()
	mut.Messages[0].Content = "BYE"
	if payloadEqual(base, mut) {
		t.Error("different Messages must not be equal")
	}
	mut = base.Clone()
	mut.Meta.Labels["a"] = "c"
	if payloadEqual(base, mut) {
		t.Error("different Meta labels must not be equal")
	}
	mut = base.Clone()
	mut.Meta = nil
	if payloadEqual(base, mut) {
		t.Error("nil vs non-nil Meta must not be equal")
	}
	mut = base.Clone()
	mut.Kind = KindResponse
	if payloadEqual(base, mut) {
		t.Error("different Kind must not be equal")
	}

	if payloadEqual(base, nil) || payloadEqual(nil, base) {
		t.Error("nil vs non-nil must not be equal")
	}
	var nilPayload *Payload
	if !payloadEqual(nilPayload, nil) {
		t.Error("two nils must be equal")
	}
}
