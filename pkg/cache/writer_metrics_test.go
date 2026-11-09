package cache

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// N2 regression: the cache-write metric must distinguish the three real
// outcomes — "queued" (accepted by the worker pool at submit time), "written"
// (a job actually persisted, emitted by the worker), and "dropped" (queue full
// / writer stopped). The v5 bug counted a submit as "written"; this test pins
// that "queued" is its own counter and that errored jobs never become "written".
func TestWriteMetric_QueuedIsDistinctFromWritten(t *testing.T) {
	beforeQueued := testutil.ToFloat64(CacheWritesTotal.WithLabelValues("queued"))
	beforeWritten := testutil.ToFloat64(CacheWritesTotal.WithLabelValues("written"))

	// Simulate what CacheService.Write does on a successful submit: record "queued".
	RecordWrite("queued")
	afterQueued := testutil.ToFloat64(CacheWritesTotal.WithLabelValues("queued"))
	if afterQueued != beforeQueued+1 {
		t.Errorf("queued: got %v, want %v (submit must count as queued, +1)", afterQueued, beforeQueued+1)
	}

	// A submit must NOT touch the "written" counter.
	afterWritten := testutil.ToFloat64(CacheWritesTotal.WithLabelValues("written"))
	if afterWritten != beforeWritten {
		t.Errorf("written: got %v, want %v (a queued submit must not be counted as written)", afterWritten, beforeWritten)
	}
}

// The worker records "written" only for jobs it successfully persists. With a
// nil store every write errors, so a full drain must leave "written" unchanged.
func TestWriteMetric_WorkerWrittenOnlyOnSuccess(t *testing.T) {
	before := testutil.ToFloat64(CacheWritesTotal.WithLabelValues("written"))
	w := NewWriter(context.Background(), nil, nil, nil)
	for i := 0; i < 4; i++ {
		if !w.Submit(writerJob{orgID: "test"}) {
			t.Fatalf("Submit %d failed", i)
		}
	}
	w.Stop() // drains all 4; nil store -> every write errors

	if _, _, written := w.Stats(); written != 0 {
		t.Errorf("internal written = %d, want 0 (nil store errors every write)", written)
	}
	after := testutil.ToFloat64(CacheWritesTotal.WithLabelValues("written"))
	if after != before {
		t.Errorf("written metric %v -> %v after errored drain; must be unchanged", before, after)
	}
}
