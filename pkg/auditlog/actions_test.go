package auditlog

import (
	"strings"
	"testing"
)

// LOGIN/CREATE_ORG call-site pattern — actor (AdminID/AdminName), IP and
// the bound request digest in Details.
func TestApprovalEntryFields(t *testing.T) {
	e := ApprovalEntry("root-1", "Root", "10.0.0.1", "req-uuid", "deadbeef")
	if e.Action != "APPROVE" {
		t.Errorf("action: got %q, want APPROVE", e.Action)
	}
	if e.Resource != ResourceJITAccess {
		t.Errorf("resource: got %q, want %q", e.Resource, ResourceJITAccess)
	}
	if e.AdminID != "root-1" || e.AdminName != "Root" || e.IP != "10.0.0.1" {
		t.Errorf("actor/ip not carried: %+v", e)
	}
	for _, want := range []string{"request=req-uuid", "digest=deadbeef"} {
		if !strings.Contains(e.Details, want) {
			t.Errorf("details %q missing %q", e.Details, want)
		}
	}
	if e.ID == "" {
		t.Error("entry id must be preset (AppendEntry inserts it verbatim)")
	}
	// No snapshots/reason payload: the row stays in the legacy v1 formula.
	if got := HashVersionFor(e.Before, e.After, e.Reason); got != HashVersionV1 {
		t.Errorf("hash version: got %d, want v1", got)
	}
}

func TestDenyEntryFields(t *testing.T) {
	e := DenyEntry("root-2", "", "10.0.0.9", "req-uuid", "feedface", "self-approval blocked")
	if e.Action != "DENY" {
		t.Errorf("action: got %q, want DENY", e.Action)
	}
	if !strings.Contains(e.Details, "reason=self-approval blocked") {
		t.Errorf("deny reason missing from details: %q", e.Details)
	}
	if e.Reason != "" {
		t.Errorf("refusal cause rides in Details, not the v2 Reason field: %q", e.Reason)
	}

	plain := DenyEntry("root-2", "", "", "req-uuid", "feedface", "")
	if strings.Contains(plain.Details, "reason=") {
		t.Errorf("empty reason must not append a reason segment: %q", plain.Details)
	}
	if plain.IP != "" {
		t.Errorf("ip not carried verbatim: %q", plain.IP)
	}
}

func TestDecisionDetailsIsStable(t *testing.T) {
	// The details payload is the machine-parsable join key between an audit
	// row and the jit_access decision it recorded.
	got := decisionDetails("r-1", "abc", "")
	if want := "request=r-1 digest=abc"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
