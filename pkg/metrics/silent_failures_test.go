package metrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/reireirei/yabanin/pkg/labels"
)

// registered (place, reason) pair is exposed on /metrics from process start
// and its increments are observable; unknown pairs panic so a typo cannot
// silently grow cardinality.

func TestSilentFailureMap_AllRegisteredPairsPresentAndIncrementVisible(t *testing.T) {
	for place, reasons := range silentFailurePlaces {
		for _, reason := range reasons {
			t.Run(place+"/"+reason, func(t *testing.T) {
				name := place + "\x00" + reason
				if _, ok := silentFailureCounter[name]; !ok {
					t.Fatalf("pair place=%q reason=%q is listed in silentFailurePlaces but has no counter child", place, reason)
				}
				// Present with value 0 before any increment (pre-created child).
				before := testutil.ToFloat64(SilentFailuresTotal.WithLabelValues(place, reason))
				SilentFailure(place, reason)
				after := testutil.ToFloat64(SilentFailuresTotal.WithLabelValues(place, reason))
				if after != before+1 {
					t.Fatalf("increment not visible for place=%q reason=%q: before=%v after=%v", place, reason, before, after)
				}
			})
		}
	}
}

func TestSilentFailureMap_UnknownPairPanics(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("SilentFailure with an unregistered pair must panic (closed label set)")
		}
		msg, ok := r.(string)
		if !ok || !strings.Contains(msg, "unregistered silent-failure pair") {
			t.Fatalf("unexpected panic value: %v", r)
		}
	}()
	SilentFailure("apiformat_request_parse", "not_a_registered_reason")
}

func TestSilentFailureMap_ExposedOnDefaultRegistry(t *testing.T) {
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	var seriesCount int
	seen := map[string]bool{}
	for _, mf := range families {
		if mf.GetName() != "gateway_silent_failures_total" {
			continue
		}
		seriesCount = len(mf.GetMetric())
		for _, m := range mf.GetMetric() {
			var place, reason string
			for _, lp := range m.GetLabel() {
				switch lp.GetName() {
				case "place":
					place = lp.GetValue()
				case "reason":
					reason = lp.GetValue()
				}
			}
			seen[place+"\x00"+reason] = true
		}
	}
	if seriesCount == 0 {
		t.Fatal("gateway_silent_failures_total not exposed on the default registry")
	}
	want := len(silentFailurePairs())
	if seriesCount != want {
		t.Fatalf("series count = %d, want exactly %d (closed map)", seriesCount, want)
	}
	for _, pair := range silentFailurePairs() {
		if !seen[pair] {
			t.Errorf("declared pair %q missing from gathered series", strings.ReplaceAll(pair, "\x00", "/"))
		}
	}
}

// silentFailurePairs flattens the registry to "place\x00reason" keys.
func silentFailurePairs() []string {
	var out []string
	for place, reasons := range silentFailurePlaces {
		for _, reason := range reasons {
			out = append(out, place+"\x00"+reason)
		}
	}
	return out
}

// TestSilentFailureMap_LegacyCountersPresent pins the pkg/metrics-resident
// legacy entries of the map: names, labels and visible increments. The
// foreign entries (credit_audit_dropped_total, cache_write_queue_drops_total)
func TestSilentFailureMap_LegacyCountersPresent(t *testing.T) {
	before := testutil.ToFloat64(LeaderFnFailedTotal)
	LeaderFnFailedTotal.Inc()
	if after := testutil.ToFloat64(LeaderFnFailedTotal); after != before+1 {
		t.Fatalf("leader_fn_failed_total increment not visible: before=%v after=%v", before, after)
	}

	for _, op := range []string{"set", "del"} {
		before := testutil.ToFloat64(RegionCacheInvalidateFailedTotal.WithLabelValues(op))
		RegionCacheInvalidateFailedTotal.WithLabelValues(op).Inc()
		if after := testutil.ToFloat64(RegionCacheInvalidateFailedTotal.WithLabelValues(op)); after != before+1 {
			t.Fatalf("region_cache_invalidate_failed_total op=%s increment not visible: before=%v after=%v", op, before, after)
		}
	}

	want := map[string][]string{
		"gateway_silent_failures_total":        {"place", "reason"},
		"leader_fn_failed_total":               nil,
		"region_cache_invalidate_failed_total": {"op"},
		"credit_audit_dropped_total":           nil,
		"cache_write_queue_drops_total":        nil,
	}
	seen := map[string][]string{}
	for _, e := range SilentFailureMap {
		if _, dup := seen[e.Name]; dup {
			t.Errorf("duplicate map entry for %s", e.Name)
		}
		seen[e.Name] = e.Labels
		if e.Owner == "" || e.Note == "" {
			t.Errorf("map entry %s must document owner and meaning", e.Name)
		}
	}
	for name, wantLabels := range want {
		gotLabels, ok := seen[name]
		if !ok {
			t.Errorf("silent-failure map is missing counter %s", name)
			continue
		}
		if len(gotLabels) != len(wantLabels) {
			t.Errorf("counter %s labels = %v, want %v", name, gotLabels, wantLabels)
			continue
		}
		for i := range wantLabels {
			if gotLabels[i] != wantLabels[i] {
				t.Errorf("counter %s label[%d] = %q, want %q", name, i, gotLabels[i], wantLabels[i])
			}
		}
	}
}

// TestSilentFailureMap_LabelValuesBounded pins the cardinality contract:
// reason values are schema/enum names, never request identifiers.
func TestSilentFailureMap_LabelValuesBounded(t *testing.T) {
	total := 0
	for place, reasons := range silentFailurePlaces {
		if place == "" {
			t.Error("empty place in the silent-failure registry")
		}
		for _, reason := range reasons {
			total++
			// A bounded enum value is a short fixed token; identifiers
			// (uuids, org/model names) would be longer and variable.
			if reason == "" || len(reason) > 32 {
				t.Errorf("reason %q for place %q looks unbounded", reason, place)
			}
			if _, ok := labels.NormalizeKey(reason); !ok {
				t.Errorf("reason %q is not a valid bounded label token", reason)
			}
		}
	}
	if total == 0 {
		t.Fatal("silent-failure registry is empty")
	}
}
