package eventpublisher

import (
	"encoding/json"
	"testing"
)

func TestEventUserIDJSON(t *testing.T) {
	raw, err := json.Marshal(Event{UserID: "user-1", OrgID: "org-1"})
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(raw) {
		t.Fatal(string(raw))
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got["user_id"] != "user-1" {
		t.Fatalf("user_id: %v", got["user_id"])
	}
	raw, err = json.Marshal(Event{OrgID: "org-1"})
	if err != nil {
		t.Fatal(err)
	}
	got = map[string]any{}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if _, ok := got["user_id"]; ok {
		t.Fatal("empty user id must be omitted")
	}
}
