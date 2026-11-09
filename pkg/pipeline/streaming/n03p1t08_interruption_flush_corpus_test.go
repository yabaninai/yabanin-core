package streaming

// N03P1T08: interruption / retry / resume corpus at the FrameProcessor seam
// — the middleware boundary the gateway mounts before the cache
// RecordingWriter (client and semantic cache observe the same bytes). The
// gateway corpus pins end-to-end drain/retry behavior; this corpus pins the
// processor's own no-duplicate/no-loss laws when a stream is interrupted:
//
//   - FR-01 interrupt-then-flush: whatever the text carry still holds when
//     the stream aborts is released exactly once by FlushFrame, with the
//     mutation applied; a second FlushFrame emits nothing — the tail can
//     never be duplicated even though both the [DONE] path and the
//     finishStream path call it (the writer chain relies on this).
//   - FR-02 fresh-processor resume: a retried request starts a new
//     processor; its emission is independent of the aborted attempt's held
//     state — no cross-request carry, no reconstruction of the aborted
//     stream's pattern from the resumed fragment.
//
// Existing coverage cited instead of duplicated: CRLF / passthrough /
// mutation-rebuild boundaries (N03P1T07-FR-*), prefix hold + late-error
// release-once at the gateway writer (T02/T04), end-to-end drain (T06/T08
// gateway corpus).
//
// Stable IDs: N03P1T08-FR-*.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// n03p1t08SplitTriggerEvent builds one content event whose text ends inside
// the secret trigger after off bytes of it (the interruption boundary).
func n03p1t08SplitTriggerEvent(t *testing.T, id, before string, triggerOff int) []byte {
	t.Helper()
	require.Positive(t, triggerOff)
	require.Less(t, triggerOff, len(testSecretTrigger))
	return chunkFrame(t, id, before+testSecretTrigger[:triggerOff])
}

// TestN03P1T08_InterruptedStream_FlushEmitsHeldTailOnce: a committed match
// is masked during the live stream; the abort lands while the carry still
// holds an incomplete pattern prefix. The flush releases that held tail
// exactly once — verbatim, because no match ever completed — so the client
// loses nothing and can never see the tail twice.
func TestN03P1T08_InterruptedStream_FlushEmitsHeldTailOnce(t *testing.T) {
	cp, err := NewChunkProcessor(map[string]string{testSecretTrigger: testSecretMask})
	require.NoError(t, err)
	fp := NewFrameProcessor(cp)

	// Event 1 carries a complete trigger: masked and emitted in-stream.
	out1 := fp.ProcessFrame(chunkFrame(t, "c1", "x "+testSecretTrigger+" y"))
	content1, ok := parseContent(t, out1)
	require.True(t, ok)
	assert.Equal(t, "x "+testSecretMask+" y", content1, "the committed match is masked in-stream")

	// Event 2 ends mid-trigger: "z " + the first half of the secret.
	ev2 := n03p1t08SplitTriggerEvent(t, "c2", "z ", len(testSecretTrigger)/2)
	out2 := fp.ProcessFrame(ev2)
	content2, ok := parseContent(t, out2)
	require.True(t, ok)
	assert.Equal(t, "z ", content2,
		"the pattern prefix is held back — nothing of the candidate match is committed")
	assert.Equal(t, len(testSecretTrigger)/2, cp.Held(),
		"the prefix sits in the carry while the stream is live")

	// Interruption: the stream ends without [DONE]; the writer chain's
	// finishStream flushes the held tail exactly once.
	tail := fp.FlushFrame("c2", "m")
	require.NotNil(t, tail, "the held tail must be released on the interrupted flush — no loss")
	tailContent, ok := parseContent(t, tail)
	require.True(t, ok)
	assert.Equal(t, testSecretTrigger[:len(testSecretTrigger)/2], tailContent,
		"an uncompleted prefix is released verbatim — masking without a match would corrupt text")
	assert.Equal(t, 0, cp.Held(), "the carry is empty after the flush")

	// A second flush (the [DONE] path racing finishStream) emits nothing.
	assert.Nil(t, fp.FlushFrame("c2", "m"),
		"the tail must never be emitted twice — FlushFrame is once-only")
}

// TestN03P1T08_InterruptedStream_FlushReleasesLiteralTailOnce: the abort
// lands while only an ordinary (non-pattern) literal suffix is held because
// it could still complete a pattern. The flush releases it masked-free and
// exactly once.
func TestN03P1T08_InterruptedStream_FlushReleasesLiteralTailOnce(t *testing.T) {
	cp, err := NewChunkProcessor(map[string]string{testSecretTrigger: testSecretMask})
	require.NoError(t, err)
	fp := NewFrameProcessor(cp)

	// "super-secret" is a proper prefix of the trigger — it must be held
	// on the live stream, then released verbatim (no match, no mask) once.
	ev := chunkFrame(t, "c1", "value: super-secret")
	out := fp.ProcessFrame(ev)
	content, ok := parseContent(t, out)
	require.True(t, ok)
	assert.Equal(t, "value: ", content, "only the potential pattern prefix is held")

	tail := fp.FlushFrame("c1", "m")
	require.NotNil(t, tail, "the held literal is released on abort — no loss")
	tailContent, ok := parseContent(t, tail)
	require.True(t, ok)
	assert.Equal(t, "super-secret", tailContent,
		"an aborted non-match is emitted verbatim, never masked, never duplicated")
	assert.Nil(t, fp.FlushFrame("c1", "m"), "a repeated flush emits nothing")
}

// TestN03P1T08_Resume_NewProcessorIndependentOfAbortedState: the resumed
// request (fresh processor) fed the continuation fragment emits it as its
// own text — the aborted attempt's held state neither merges into it nor
// reconstructs the pattern from the resumed bytes.
func TestN03P1T08_Resume_NewProcessorIndependentOfAbortedState(t *testing.T) {
	// Aborted attempt: holds the first half of the trigger forever.
	aborted, err := NewChunkProcessor(map[string]string{testSecretTrigger: testSecretMask})
	require.NoError(t, err)
	abortedFP := NewFrameProcessor(aborted)
	out := abortedFP.ProcessFrame(n03p1t08SplitTriggerEvent(t, "c1", "", len(testSecretTrigger)/2))
	_, ok := parseContent(t, out)
	require.True(t, ok)
	require.Positive(t, aborted.Held(), "precondition: the aborted attempt holds state")

	// Resumed attempt: a NEW processor (the gateway builds one per request).
	resumed, err := NewChunkProcessor(map[string]string{testSecretTrigger: testSecretMask})
	require.NoError(t, err)
	resumedFP := NewFrameProcessor(resumed)
	out2 := resumedFP.ProcessFrame(chunkFrame(t, "c2", testSecretTrigger[len(testSecretTrigger)/2:]))
	content, ok := parseContent(t, out2)
	require.True(t, ok)
	assert.Equal(t, testSecretTrigger[len(testSecretTrigger)/2:], content,
		"the resumed fragment is emitted as-is — no cross-request carry, no pattern reconstruction")
	assert.Equal(t, 0, resumed.Held(), "the fresh processor holds nothing from the aborted stream")
	assert.Positive(t, aborted.Held(),
		"the aborted processor's state is untouched by the resumed request until its own flush")
}
