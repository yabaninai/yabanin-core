package provider

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOpenAIStreamMultilineUsage(t *testing.T) {
	const frame = "event: usage\ndata: {\"choices\":[],\ndata\ndata: \"usage\":{\"prompt_tokens\":7,\"completion_tokens\":3,\"total_tokens\":10}}\n\n"
	const terminal = "data: [DONE]\n\n"
	for _, tc := range []struct {
		name    string
		lineEnd string
		hide    bool
		want    string
	}{
		{"LF", "\n", false, frame + terminal},
		{"CR", "\r", false, frame + terminal},
		{"CRLF", "\r\n", false, frame + terminal},
		{"suppress usage", "\n", true, terminal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := strings.ReplaceAll(frame+terminal, "\n", tc.lineEnd)
			h := NewStreamHandlerWithOptions("openai", "m", StreamOptions{SuppressUsageOnlyChunk: tc.hide})
			u, buf, err := h3HandleStream(t, h, []byte(body))
			require.NoError(t, err)
			require.Equal(t, tc.want, buf.String())
			require.Equal(t, int64(7), u.PromptTokens)
			require.Equal(t, int64(3), u.CompletionTokens)
		})
	}
}

type shortStreamRecorder struct{ *recorderFlusher }

func (w shortStreamRecorder) Write(p []byte) (int, error) {
	return w.recorderFlusher.Write(p[:len(p)-1])
}

func TestOpenAIStreamReportsShortWrite(t *testing.T) {
	rec, _ := newRecorder()
	w := shortStreamRecorder{rec}
	resp := newSSEResponse("data: [DONE]\n\n")
	defer resp.Body.Close()
	_, err := NewStreamHandler("openai", "m").HandleStream(t.Context(), w, w, resp)
	require.ErrorIs(t, err, io.ErrShortWrite)
}

type frameReadFunc func([]byte) (int, error)

func (f frameReadFunc) Read(p []byte) (int, error) { return f(p) }

func TestOpenAIStreamFlushesBeforeNextRead(t *testing.T) {
	for _, pair := range []struct{ upstream, delivered string }{
		{": keepalive\n", ": keepalive\n"},
		{"data: {}\r\r", "data: {}\n\n"},
	} {
		w, buf := newRecorder()
		firstRead := true
		body := frameReadFunc(func(dst []byte) (int, error) {
			if firstRead {
				firstRead = false
				return copy(dst, pair.upstream), nil
			}
			require.Equal(t, pair.delivered, buf.String())
			return 0, io.EOF
		})
		resp := &http.Response{Body: io.NopCloser(body)}
		_, err := NewStreamHandler("openai", "m").HandleStream(t.Context(), w, w, resp)
		require.ErrorIs(t, err, ErrStreamIncomplete)
	}
}

func TestOpenAIStreamTerminalAtReadFailure(t *testing.T) {
	for _, tc := range []struct {
		name    string
		wire    string
		cancel  bool
		readErr error
		wantErr error
	}{
		{"transport", "data: [DONE]\ndat", false, io.ErrUnexpectedEOF, io.ErrUnexpectedEOF},
		{"cancelled final read", "data: [DONE]\n", true, io.EOF, context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			firstRead := true
			body := frameReadFunc(func(p []byte) (int, error) {
				if firstRead {
					firstRead = false
					return copy(p, tc.wire), nil
				}
				if tc.cancel {
					cancel()
				}
				return 0, tc.readErr
			})
			w, buf := newRecorder()
			resp := &http.Response{Body: io.NopCloser(body)}
			_, err := NewStreamHandler("openai", "m").HandleStream(ctx, w, w, resp)
			require.ErrorIs(t, err, tc.wantErr)
			require.Empty(t, buf.String())
		})
	}
}

func TestOpenAIStreamPreservesProviderErrorWithUsage(t *testing.T) {
	const frame = "data:{\"error\":{\"message\":\"quota\"},\"usage\":{\"total_tokens\":7}}\n\n"
	const terminal = "data: [DONE]\n\n"
	w := NewStreamHandlerWithOptions("openai", "m", StreamOptions{SuppressUsageOnlyChunk: true})
	usage, out, err := h3HandleStream(t, w, []byte(frame+terminal))
	require.NoError(t, err)
	require.Equal(t, frame+terminal, out.String())
	require.Equal(t, int64(7), usage.TotalTokens)
}

func TestOpenAIStreamRecognizesInitialBOM(t *testing.T) {
	_, out, err := h3HandleStream(t, NewStreamHandler("openai", "m"), []byte("\xef\xbb\xbfdata: [DONE]\n"))
	require.NoError(t, err)
	require.Equal(t, "data: [DONE]\n\n", out.String())
}

type cancelStreamFlusher struct{ cancel context.CancelFunc }

func (f cancelStreamFlusher) Flush() { f.cancel() }

func TestOpenAIStreamCancellationInTrailingFlush(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	w, buf := newRecorder()
	resp := newSSEResponse("data: [DONE]\n")
	defer resp.Body.Close()
	_, err := NewStreamHandler("openai", "m").HandleStream(ctx, w, cancelStreamFlusher{cancel}, resp)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, "data: [DONE]\n\n", buf.String())
}

func TestOpenAIStreamSuppressesUsageWithNullError(t *testing.T) {
	const frame = "data: {\"choices\":[],\"usage\":{\"total_tokens\":7},\"error\":null}\n\n"
	const terminal = "data: [DONE]\n\n"
	h := NewStreamHandlerWithOptions("openai", "m", StreamOptions{SuppressUsageOnlyChunk: true})
	u, out, err := h3HandleStream(t, h, []byte(frame+terminal))
	require.NoError(t, err)
	require.Equal(t, terminal, out.String())
	require.Equal(t, int64(7), u.TotalTokens)
}
