package sovereign

import "testing"

func TestRank_Ordering(t *testing.T) {
	if Rank(TierForeign) >= Rank(TierPartial) {
		t.Fatal("foreign must rank below partial")
	}
	if Rank(TierPartial) >= Rank(TierOpenWeights) {
		t.Fatal("partial must rank below open_weights")
	}
	if Rank(TierOpenWeights) >= Rank(TierFull) {
		t.Fatal("open_weights must rank below full")
	}
}

func TestRank_UnknownTier_Zero(t *testing.T) {
	if got := Rank(Tier("bogus")); got != 0 {
		t.Fatalf("unknown tier rank = %d, want 0", got)
	}
}
