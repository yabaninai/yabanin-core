package adminstore

import (
	"math"
	"testing"
)

// shares and the honest coverage split. The SQL side (org scoping, shadow
// exclusion, window bounds) is covered by the Real-PG int test.

func TestGroupActualRouting_SharesAndCoverage(t *testing.T) {
	got := groupActualRouting([]routingActualRow{
		// 3× requested A served by A2 (rule override), 2× B→B2, 1× A served
		// by A1 (failover) — ordered by volume as SQL returns them.
		{Requested: "m-a", Used: "m-a2", Requests: 3},
		{Requested: "m-b", Used: "m-b2", Requests: 2},
		{Requested: "m-a", Used: "m-a1", Requests: 1},
		// Unattributed: no requested model on the row — counted, not dropped.
		{Requested: "", Used: "m-c", Requests: 2},
	})

	wantEdges := []RoutingActualEdge{
		{From: "m-a", To: "m-a2", Requests: 3, Share: 0.5},
		{From: "m-b", To: "m-b2", Requests: 2, Share: 1.0 / 3.0},
		{From: "m-a", To: "m-a1", Requests: 1, Share: 1.0 / 6.0},
	}
	if len(got.Edges) != len(wantEdges) {
		t.Fatalf("edges = %+v, want %d entries", got.Edges, len(wantEdges))
	}
	for i, w := range wantEdges {
		if got.Edges[i] != w {
			t.Errorf("edge[%d] = %+v, want %+v", i, got.Edges[i], w)
		}
	}

	wantCoverage := RoutingActualCoverage{
		TotalRequests:        8,
		AttributedRequests:   6,
		UnattributedRequests: 2,
		Share:                0.75,
	}
	if got.Coverage != wantCoverage {
		t.Errorf("coverage = %+v, want %+v", got.Coverage, wantCoverage)
	}

	// The edges' shares sum to 1 over the attributed traffic even though
	// the window is only partially covered.
	sum := 0.0
	for _, e := range got.Edges {
		sum += e.Share
	}
	if math.Abs(sum-1) > 1e-9 {
		t.Errorf("edge shares sum = %v, want 1", sum)
	}
}

func TestGroupActualRouting_EmptyIsHonestEmpty(t *testing.T) {
	got := groupActualRouting(nil)
	if got == nil {
		t.Fatal("grouping no rows = nil, want a value with an empty non-nil edge slice")
	}
	if got.Edges == nil || len(got.Edges) != 0 {
		t.Errorf("edges = %#v, want empty non-nil slice (JSON [], not null)", got.Edges)
	}
	if got.Coverage != (RoutingActualCoverage{}) {
		t.Errorf("coverage = %+v, want zero coverage", got.Coverage)
	}
}

func TestGroupActualRouting_FullyUnattributed(t *testing.T) {
	got := groupActualRouting([]routingActualRow{{Requested: "", Used: "m-c", Requests: 4}})
	if len(got.Edges) != 0 {
		t.Errorf("edges = %+v, want none (unattributed rows form no from-edge)", got.Edges)
	}
	want := RoutingActualCoverage{
		TotalRequests:        4,
		AttributedRequests:   0,
		UnattributedRequests: 4,
		Share:                0,
	}
	if got.Coverage != want {
		t.Errorf("coverage = %+v, want %+v", got.Coverage, want)
	}
}
