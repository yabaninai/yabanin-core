package cli

import (
	"encoding/json"
	"math"

	"github.com/reireirei/yabanin/pkg/budget"
	"github.com/reireirei/yabanin/pkg/pricing"
)

// T02 unit pricing (N06-P07): non-token metering for audio and image
// workloads. Reservation bounds and settlement costs resolve rates from an
// operator-supplied unit pricer. No unit price dataset is bundled. A missing
// non-token rate stays unpriced and keeps the fail-closed behavior; no rate
// is invented from token prices.

// unitPrice resolves a non-token metering rate. Fail-closed: an unwired
// pricer, an unknown model, a unit-kind mismatch or a non-finite/negative
// rate all report unpriced — never a zero-cost bypass.
func (gw *gateway) unitPrice(providerName, modelName, unit string) (pricing.UnitEntry, bool) {
	if gw.unitPricer == nil {
		return pricing.UnitEntry{}, false
	}
	entry, ok := gw.unitPricer.LookupUnit(providerName, modelName)
	if !ok || entry.Unit != unit {
		return pricing.UnitEntry{}, false
	}
	if math.IsNaN(entry.Rate) || math.IsInf(entry.Rate, 0) || entry.Rate < 0 {
		return pricing.UnitEntry{}, false
	}
	return entry, true
}

// withUnitDemand marks a reservation request as unit-metered (estimator T02
// branch): the bound is unit rate × qty instead of the token estimate.
// qty must be the CONSERVATIVE upper quantity (audio seconds, input
// characters, requested image count) so the reserve can only over-cover.
func withUnitDemand(req budget.Request, unit string, qty float64) budget.Request {
	req.UnitKind = unit
	req.UnitQty = &qty
	return req
}

// audioBytesPerSecond is the size→duration assumption for the per-second
// reservation bound: 8 kbit/s, the low end of common speech codecs. Slower
// (more compressed) audio means MORE seconds per byte, so the bound can only
// over-cover the upstream bill, never under-cover it.
const audioBytesPerSecond = 1000

// transcriptionReservationSeconds derives the conservative per-second
// reservation quantity from the audio payload size, rounding up.
func transcriptionReservationSeconds(sizeBytes int) float64 {
	return float64((sizeBytes + audioBytesPerSecond - 1) / audioBytesPerSecond)
}

// transcriptionResponseDuration parses "duration" (seconds) out of a
// verbose_json transcription response. ok=false when absent or malformed:
// plain text/JSON responses carry no duration and stay on the legacy
// no-usage settlement (the size-derived bound is never reused for billing —
// settlement bills actuals only).
func transcriptionResponseDuration(body []byte) (float64, bool) {
	var parsed struct {
		Duration *float64 `json:"duration"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || parsed.Duration == nil {
		return 0, false
	}
	d := *parsed.Duration
	if math.IsNaN(d) || math.IsInf(d, 0) || d < 0 {
		return 0, false
	}
	return d, true
}

// imagesRequestCount resolves the requested image count "n" (OpenAI images
// API): absent or non-positive values default to 1, mirroring the upstream
// API's own default. Only positive requests raise the billable quantity.
func imagesRequestCount(n *int64) float64 {
	if n == nil || *n < 1 {
		return 1
	}
	return float64(*n)
}
