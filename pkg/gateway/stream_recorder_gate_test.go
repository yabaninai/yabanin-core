package cli

// STREAM-01 regressions (DEEP-AUDIT 2026-10-31): the stream-cache recorder
// must not exist when the cache cannot use it, and must not grow without
// bound when it does. wrapWriters allocated the RecordingWriter from
// `cache != nil && orgID != "" && !cacheDisabled` alone — the
// cache.stream_enabled kill-switch was only consulted after the stream
// finished (writeStreamCacheAsync) — so every killed-switch stream carried a
// full passenger copy of the response for nothing, and an enabled stream
// retained every frame of an arbitrarily long upstream response in memory.

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/cache"
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/resolver"
)

// hand-built streamRun touching only the fields wrapWriters consumes; the
// policy seam and tool gate stay off (nil runtime / nil toolPolicies on the
// test gateway), so the recorder layer is the one under test.
func stream01Run(gw *gateway) *streamRun {
	return &streamRun{
		gw:    gw,
		w:     httptest.NewRecorder(),
		orgID: "org-a",
	}
}

func TestSTREAM01_RecorderNotAllocatedWhenStreamCacheDisabled(t *testing.T) {
	up := newRT02Upstream(t)
	gw := streamTestGateway(up.srv.URL)
	gw.cache = newRT05Cache()
	require.False(t, gw.cfg.CacheStreamEnabled,
		"the kill-switch defaults off; the test pins the default-off behavior")

	r := stream01Run(gw)
	r.wrapWriters()

	assert.Nil(t, r.rec,
		"cache.stream_enabled off must not allocate the recorder: the killed-switch path has no cache consumer, so the copy is a pure memory leak")
}

func TestSTREAM01_RecorderAllocatedWhenStreamCacheEnabled(t *testing.T) {
	up := newRT02Upstream(t)
	gw := streamTestGateway(up.srv.URL)
	gw.cfg.CacheStreamEnabled = true
	gw.cache = newRT05Cache()

	r := stream01Run(gw)
	r.wrapWriters()

	assert.NotNil(t, r.rec,
		"with the kill-switch on and caching eligible, the recorder must exist (guards against over-gating)")
}

func TestSTREAM01_RecorderNotAllocatedWhenNoStore(t *testing.T) {
	up := newRT02Upstream(t)
	gw := streamTestGateway(up.srv.URL)
	gw.cfg.CacheStreamEnabled = true
	gw.cache = newRT05Cache()

	r := stream01Run(gw)
	r.cacheDisabled = true
	r.wrapWriters()

	assert.Nil(t, r.rec, "a no-store request must not record (RT-07, unchanged)")
}

func TestSTREAM01_RecorderNotAllocatedWithoutCache(t *testing.T) {
	up := newRT02Upstream(t)
	gw := streamTestGateway(up.srv.URL)
	gw.cfg.CacheStreamEnabled = true // switch on, but no cache backend at all

	r := stream01Run(gw)
	r.wrapWriters()

	assert.Nil(t, r.rec, "no cache backend means no recorder")
}

// TestSTREAM01_OverflowRefusesCacheWrite pins the no-partial-entry contract:
// a bounded capture that overflowed is a PREFIX of the real stream; writing
// it would store a truncated answer that replays as if complete. The same
// frames within caps DO write (control), so the refusal is provably the
// overflow branch, not a dead path.
func TestSTREAM01_OverflowRefusesCacheWrite(t *testing.T) {
	frames := [][]byte{
		[]byte(`data: {"id":"c1","choices":[{"index":0,"delta":{"role":"assistant"}}]}` + "\n\n"),
		[]byte(`data: {"id":"c1","choices":[{"index":0,"delta":{"content":"Hello "}}]}` + "\n\n"),
		[]byte(`data: {"id":"c1","choices":[{"index":0,"delta":{"content":"world"}}]}` + "\n\n"),
	}

	newRun := func(gw *gateway, rec *cache.RecordingWriter) *streamRun {
		return &streamRun{
			gw:        gw,
			orgID:     "org-a",
			body:      []byte(`{"model":"m","messages":[{"role":"user","content":"stream01-overflow"}]}`),
			rec:       rec,
			finalInfo: resolver.ModelInfo{ModelName: "m-1"},
		}
	}

	t.Run("overflowed capture is refused", func(t *testing.T) {
		up := newRT02Upstream(t)
		gw := streamTestGateway(up.srv.URL)
		gw.cfg.CacheStreamEnabled = true
		c := newRT05Cache()
		gw.cache = c

		rec := cache.NewRecordingWriterCapped(httptest.NewRecorder(), 256, streamCacheRecordMaxFrames)
		for _, f := range frames {
			_, err := rec.Write(f)
			require.NoError(t, err)
		}
		require.NotEmpty(t, rec.Chunks(),
			"test setup: the refusal must be exercised with a NON-empty overflowed capture")
		_, err := rec.Write([]byte("data: {\"chunk\":" + strings.Repeat("\"x\"", 200) + "}\n\n"))
		require.NoError(t, err)
		require.True(t, rec.Overflowed(), "test setup: the oversized frame must latch the overflow")

		r := newRun(gw, rec)
		r.writeStreamCacheAsync(provider.Usage{})

		require.Never(t, func() bool { return c.writeCount() > 0 },
			400*time.Millisecond, 10*time.Millisecond,
			"a truncated capture must never become a cache entry that replays as if complete")
	})

	t.Run("within-caps capture writes normally", func(t *testing.T) {
		up := newRT02Upstream(t)
		gw := streamTestGateway(up.srv.URL)
		gw.cfg.CacheStreamEnabled = true
		c := newRT05Cache()
		gw.cache = c

		rec := cache.NewRecordingWriterCapped(httptest.NewRecorder(), streamCacheRecordMaxBytes, streamCacheRecordMaxFrames)
		for _, f := range frames {
			_, err := rec.Write(f)
			require.NoError(t, err)
		}
		require.False(t, rec.Overflowed())

		r := newRun(gw, rec)
		r.writeStreamCacheAsync(provider.Usage{})

		require.Eventually(t, func() bool { return c.writeCount() == 1 },
			2*time.Second, 10*time.Millisecond,
			"the control proves the refusal above is the overflow branch, not a dead write path")
	})
}
