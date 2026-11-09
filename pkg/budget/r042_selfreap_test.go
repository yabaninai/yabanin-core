package budget

import "testing"

// (owner decisions 2026-10-18: D1 automatic at replica start, D2 own
// replica only, D3 safety window unchanged).

func TestSelfReapPrefix(t *testing.T) {
	cases := []struct {
		name      string
		replicaID string
		want      string
	}{
		{"gateway shape host-pid-nanos", "k8s-pod-abc-4242-1699999999999999999", "k8s-pod-abc"},
		{"plain host", "gwbox-4242-1699999999999999999", "gwbox"},
		{"dashed host keeps dashes", "gw-a-b-c-1-2", "gw-a-b-c"},
		{"missing nanos", "gwbox-4242", ""},
		{"non-numeric tail", "gwbox-4242-notanos", ""},
		{"non-numeric pid", "gwbox-pid-1699999999999999999", ""},
		{"no separators", "gwbox", ""},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := selfReapPrefix(tc.replicaID); got != tc.want {
				t.Fatalf("selfReapPrefix(%q) = %q, want %q", tc.replicaID, got, tc.want)
			}
		})
	}
}

func TestEscapeRegex(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain-host", "plain-host"},
		{`dot.host`, `dot\.host`},
		{"star*plus+", `star\*plus\+`},
		{"brack[et]{ brace }", `brack\[et\]\{ brace \}`},
		{"caret^dollar$", `caret\^dollar\$`},
		{"quest?pipe|paren(", `quest\?pipe\|paren\(`},
		{`back\slash`, `back\\slash`},
		{"percent%under_score", "percent%under_score"},
	}
	for _, tc := range cases {
		if got := escapeRegex(tc.in); got != tc.want {
			t.Fatalf("escapeRegex(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
