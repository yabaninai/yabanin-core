package config_test

// N12-P01-T02 pairing pin: the gateway's history-admission probe depth
// default must equal the loggerd consumer's durable-buffer bound, so both
// sides declare stream saturation at the same depth without extra
// coordination (the probe's XLen check is the second line of defense behind
// loggerd's admission signal). Lives in an external test package because
// services/loggerd/consumer imports pkg/config — an internal test file
// would form an import cycle.

import (
	"testing"

	"github.com/reireirei/yabanin/pkg/config"
	"github.com/reireirei/yabanin/services/loggerd/consumer"
)

func TestDefaultHistoryProbeMaxEntriesMatchesConsumer(t *testing.T) {
	got := config.DefaultGateway().HistoryProbeMaxEntries
	want := int64(consumer.DefaultHistoryBufferMaxEntries)
	if got != want {
		t.Fatalf("gateway history probe default %d != loggerd buffer bound %d — keep the pairing, or change both sides deliberately and document the split",
			got, want)
	}
}
