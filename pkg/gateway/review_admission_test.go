package cli

import (
	"errors"
	"testing"

	pub "github.com/reireirei/yabanin/pkg/eventpublisher"
)

func TestPreviewOwnerStateEdges(t *testing.T) {
	for _, name := range []string{"refused_start_latches", "pending_void_blocks_terminal", "wrong_org_rejected", "divergent_local_recommit"} {
		t.Run(name, func(t *testing.T) {
			id := newTestIdentity()
			store := &fakeInvocationStore{}
			if name == "refused_start_latches" {
				store.admitErr = errors.New("commit outcome unknown")
				if err := id.beginPaidDispatch(t.Context(), store, invocationKindChat); err == nil {
					t.Fatal("first start succeeded")
				}
				store.admitErr = nil
				if err := id.beginPaidDispatch(t.Context(), store, invocationKindStream); err == nil {
					t.Fatal("fallback on refused request got dispatch permission")
				}
				return
			}
			if err := id.beginPaidDispatch(t.Context(), store, invocationKindChat); err != nil {
				t.Fatal(err)
			}
			ev := &pub.Event{EventType: "request.completed", OrgID: "org-1", InvocationID: id.ID(), TS: 1234, TokensIn: 7, RequestID: "client-req-1"}
			switch name {
			case "pending_void_blocks_terminal":
				store.voidErr = errors.New("temporary")
				if err := id.void(t.Context(), store); err == nil {
					t.Fatal("missing void error")
				}
			case "wrong_org_rejected":
				ev.OrgID = "another-org"
			case "divergent_local_recommit":
				if err := id.commitInvocationTerminal(t.Context(), store, ev); err != nil {
					t.Fatal(err)
				}
				ev.TokensIn = 99
			}
			if err := id.commitInvocationTerminal(t.Context(), store, ev); err == nil {
				t.Fatalf("invalid terminal accepted: %+v", store.facts)
			}
		})
	}
}
