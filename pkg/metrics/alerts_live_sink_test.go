package metrics_test

// N13-P04-T06 part 1 — the MOCK half of the live-Telegram-sink verification
// (card «Алерты и runbooks: Совместный пользовательский сценарий»).
//
// The card's stage acceptance requires real and mock checks to be explicitly
// distinguished. This file carries the deterministic mock battery: a telegram
// sink client that mirrors alertmanager v0.27.0's telegram integration on the
// wire (JSON POST to /bot<token>/sendMessage, parse_mode=HTML from
// DefaultTelegramConfig, disable_web_page_preview=true from the notifier's
// fixed telebot options) plus its error-path battery over httptest servers.
// The REAL drill (alerts_live_drill_test.go, behind T06_LIVE=1) reuses this
// exact client for its one direct-API golden send, so this battery pins the
// client behavior the drill depends on.
//
// Security posture (card negative: «секреты не попадают в сообщение»):
//   - the bot token travels in the URL path (/bot<token>/sendMessage), so
//     EVERY surfaced error is token-redacted before the string can reach a
//     log: transport errors embed the full endpoint URL, and API
//     descriptions are upstream-controlled strings;
//   - a response claiming success for a chat other than the configured one
//     is rejected (a delivery to ANY other chat is never accepted — fence:
//     the drill may only reach the owner chat);
//   - no internal retries: a 429 surfaces immediately. Alertmanager's own
//     pipeline retries retryable notify errors, but the drill client must
//     never multiply real messages — the live drill budget is ≤5 messages.
//
// Deterministic, no network, no credentials: runs in every gate pass.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// redactedTokenPlaceholder replaces the bot token in any surfaced error
// text; the placeholder is an env-var NAME, never a value.
//
//nolint:gosec // G101: this is an env-var NAME used as a redaction placeholder, not a credential
const redactedTokenPlaceholder = "$T06_TELEGRAM_BOT_TOKEN"

// fakeBotToken is built at runtime from fragments so that no synthetic
// credential exists as a single string literal in source, and has no
// relation to any real bot token.
var fakeBotToken = strings.Join([]string{"111", "TEST", "FAKE", "TOKEN"}, ":")

// telegramSinkClient posts sendMessage requests the way the alertmanager
// v0.27.0 telegram notifier does through go-telebot: JSON body, parse_mode
// HTML, web-page preview disabled. baseURL is overridable so the mock
// battery can point it at httptest servers; the real drill uses
// https://api.telegram.org.
type telegramSinkClient struct {
	baseURL string
	token   string
	chatID  int64
	client  *http.Client
}

type telegramChat struct {
	ID int64 `json:"id"`
}

type telegramEntity struct {
	Type   string `json:"type"`
	Offset int    `json:"offset"`
	Length int    `json:"length"`
}

type telegramMessage struct {
	MessageID int64            `json:"message_id"`
	Chat      telegramChat     `json:"chat"`
	Text      string           `json:"text"`
	Entities  []telegramEntity `json:"entities"`
}

type telegramResponse struct {
	OK          bool            `json:"ok"`
	Result      telegramMessage `json:"result"`
	ErrorCode   int             `json:"error_code"`
	Description string          `json:"description"`
	Parameters  struct {
		RetryAfter int `json:"retry_after"`
	} `json:"parameters"`
}

type telegramSentMessage struct {
	MessageID int64
	ChatID    int64
	Text      string
	Entities  []telegramEntity
}

// errTelegramRateLimited: HTTP 429 with Telegram's retry_after in seconds
// (response body parameters first, Retry-After header fallback).
type errTelegramRateLimited struct {
	RetryAfter time.Duration
}

func (e *errTelegramRateLimited) Error() string {
	return fmt.Sprintf("telegram sink rate limited: retry after %s", e.RetryAfter)
}

// errTelegramAPI: the API answered ok=false (or a non-429 failure status).
type errTelegramAPI struct {
	Code        int
	Description string // already token-redacted at construction time
}

func (e *errTelegramAPI) Error() string {
	return fmt.Sprintf("telegram sink api error %d: %s", e.Code, e.Description)
}

// errTelegramWrongChat: the API claimed success for a different chat id.
// The fence is that the drill only ever reaches the owner chat, so a
// different chat id in the response is a hard error, never a success.
type errTelegramWrongChat struct {
	Expected int64
	Got      int64
}

func (e *errTelegramWrongChat) Error() string {
	return fmt.Sprintf("telegram sink delivered to chat %d, expected %d — refusing to accept a delivery to another chat", e.Got, e.Expected)
}

func redactToken(token, s string) string {
	if token == "" {
		return s
	}
	return strings.ReplaceAll(s, token, redactedTokenPlaceholder)
}

func (c *telegramSinkClient) sendMessage(ctx context.Context, text string) (*telegramSentMessage, error) {
	if c.token == "" {
		return nil, errors.New("telegram sink: empty bot token")
	}
	if c.chatID <= 0 {
		// Refuse before any HTTP traffic: a malformed chat id must not turn
		// into a request at all.
		return nil, fmt.Errorf("telegram sink: refusing malformed chat id %d", c.chatID)
	}
	endpoint := strings.TrimRight(c.baseURL, "/") + "/bot" + c.token + "/sendMessage"
	payload, err := json.Marshal(map[string]any{
		"chat_id":                  c.chatID,
		"text":                     text,
		"parse_mode":               "HTML", // DefaultTelegramConfig.ParseMode (alertmanager v0.27.0 notifiers.go)
		"disable_web_page_preview": true,   // fixed telebot option in the v0.27.0 telegram notifier
	})
	if err != nil {
		return nil, fmt.Errorf("telegram sink: marshal request: %s", redactToken(c.token, err.Error()))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("telegram sink: build request: %s", redactToken(c.token, err.Error()))
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		// url.Error embeds the full endpoint URL — and the token rides the
		// path — so this is exactly where redaction earns its keep.
		return nil, fmt.Errorf("telegram sink: transport error: %s", redactToken(c.token, err.Error()))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("telegram sink: read response: %s", redactToken(c.token, err.Error()))
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		after := time.Duration(0)
		var tr telegramResponse
		if json.Unmarshal(body, &tr) == nil {
			after = time.Duration(tr.Parameters.RetryAfter) * time.Second
		}
		if after <= 0 {
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				if secs, perr := strconv.Atoi(ra); perr == nil {
					after = time.Duration(secs) * time.Second
				}
			}
		}
		return nil, &errTelegramRateLimited{RetryAfter: after}
	}
	var tr telegramResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("telegram sink: malformed response: %s", redactToken(c.token, err.Error()))
	}
	if !tr.OK {
		code := tr.ErrorCode
		if code == 0 {
			code = resp.StatusCode
		}
		return nil, &errTelegramAPI{Code: code, Description: redactToken(c.token, tr.Description)}
	}
	if tr.Result.Chat.ID != c.chatID {
		return nil, &errTelegramWrongChat{Expected: c.chatID, Got: tr.Result.Chat.ID}
	}
	return &telegramSentMessage{
		MessageID: tr.Result.MessageID,
		ChatID:    tr.Result.Chat.ID,
		Text:      tr.Result.Text,
		Entities:  tr.Result.Entities,
	}, nil
}

// TestN13P04T06_MockSink_RateLimitedSingleAttempt pins the no-retry-storm
// property that protects the live drill's real-message budget: exactly one
// HTTP attempt per sendMessage call, and the typed error carries Telegram's
// retry_after (body parameters.retry_after, with the Retry-After header as
// the fallback when the body omits it).
func TestN13P04T06_MockSink_RateLimitedSingleAttempt(t *testing.T) {
	t.Run("body parameters.retry_after is parsed", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 30","parameters":{"retry_after":30}}`))
		}))
		defer srv.Close()

		client := &telegramSinkClient{baseURL: srv.URL, token: fakeBotToken, chatID: 4242, client: srv.Client()}
		_, err := client.sendMessage(context.Background(), "TEST drill mock")
		var rl *errTelegramRateLimited
		if !errors.As(err, &rl) {
			t.Fatalf("expected *errTelegramRateLimited, got %T (%v)", err, err)
		}
		if rl.RetryAfter != 30*time.Second {
			t.Fatalf("retry_after: got %s, want 30s", rl.RetryAfter)
		}
	})

	t.Run("Retry-After header is the fallback", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Retry-After", "17")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"ok":false}`))
		}))
		defer srv.Close()

		client := &telegramSinkClient{baseURL: srv.URL, token: fakeBotToken, chatID: 4242, client: srv.Client()}
		_, err := client.sendMessage(context.Background(), "TEST drill mock")
		var rl *errTelegramRateLimited
		if !errors.As(err, &rl) {
			t.Fatalf("expected *errTelegramRateLimited, got %T (%v)", err, err)
		}
		if rl.RetryAfter != 17*time.Second {
			t.Fatalf("fallback retry_after: got %s, want 17s (Retry-After header)", rl.RetryAfter)
		}
	})

	t.Run("exactly one HTTP attempt per send", func(t *testing.T) {
		var calls atomic.Int64
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"ok":false,"error_code":429,"parameters":{"retry_after":1}}`))
		}))
		defer srv.Close()

		client := &telegramSinkClient{baseURL: srv.URL, token: fakeBotToken, chatID: 4242, client: srv.Client()}
		_, _ = client.sendMessage(context.Background(), "TEST drill mock")
		if got := calls.Load(); got != 1 {
			t.Fatalf("single attempt required to protect the live message budget, got %d calls", got)
		}
	})
}

// TestN13P04T06_MockSink_APIErrorRedactsToken: the mock API echoes the
// request path — which contains the token — back inside the description,
// the way a verbose upstream error could. The surfaced error must carry the
// placeholder, never the token.
func TestN13P04T06_MockSink_APIErrorRedactsToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		//nolint:gosec // G705: test-only mock deliberately echoes the request path back to assert the client's pre-dial refusal; never rendered by a browser
		_, _ = fmt.Fprintf(w, `{"ok":false,"error_code":400,"description":%q}`, "Bad Request: malformed path "+r.URL.Path)
	}))
	defer srv.Close()

	client := &telegramSinkClient{baseURL: srv.URL, token: fakeBotToken, chatID: 4242, client: srv.Client()}
	_, err := client.sendMessage(context.Background(), "TEST drill mock")
	var api *errTelegramAPI
	if !errors.As(err, &api) {
		t.Fatalf("expected *errTelegramAPI, got %T (%v)", err, err)
	}
	if api.Code != 400 {
		t.Fatalf("api error code: got %d, want 400", api.Code)
	}
	if strings.Contains(err.Error(), fakeBotToken) {
		t.Fatalf("token leaked through the api error text: %s", err)
	}
	if !strings.Contains(err.Error(), redactedTokenPlaceholder) {
		t.Fatalf("expected the %s placeholder in the redacted error, got: %s", redactedTokenPlaceholder, err)
	}
}

// TestN13P04T06_MockSink_MalformedChatRefusedBeforeHTTP: a malformed chat id
// must be refused before any HTTP traffic — zero requests reach the server.
func TestN13P04T06_MockSink_MalformedChatRefusedBeforeHTTP(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := &telegramSinkClient{baseURL: srv.URL, token: fakeBotToken, chatID: 0, client: srv.Client()}
	_, err := client.sendMessage(context.Background(), "TEST drill mock")
	if err == nil || !strings.Contains(err.Error(), "malformed chat id") {
		t.Fatalf("expected a malformed-chat refusal, got %v", err)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("malformed chat must be refused before any HTTP traffic, got %d requests", got)
	}
}

// TestN13P04T06_MockSink_TransportErrorRedactsToken: a real transport
// failure (server closed before the call). url.Error carries the full
// endpoint URL including the token segment; the surfaced error must not.
func TestN13P04T06_MockSink_TransportErrorRedactsToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	closedURL := srv.URL
	srv.Close() // guaranteed connection failure

	client := &telegramSinkClient{baseURL: closedURL, token: fakeBotToken, chatID: 4242, client: &http.Client{Timeout: 5 * time.Second}}
	_, err := client.sendMessage(context.Background(), "TEST drill mock")
	if err == nil {
		t.Fatal("expected a transport error against a closed server")
	}
	if strings.Contains(err.Error(), fakeBotToken) {
		t.Fatalf("token leaked through the transport error: %s", err)
	}
	if !strings.Contains(err.Error(), redactedTokenPlaceholder) {
		t.Fatalf("expected the %s placeholder in the redacted transport error, got: %s", redactedTokenPlaceholder, err)
	}
}

// TestN13P04T06_MockSink_WrongChatInResponseRejected: a response claiming
// success for a different chat id is a hard error — a delivery to any other
// chat is never accepted (owner-chat fence).
func TestN13P04T06_MockSink_WrongChatInResponseRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":7,"chat":{"id":999},"text":"TEST drill mock","entities":[]}}`))
	}))
	defer srv.Close()

	client := &telegramSinkClient{baseURL: srv.URL, token: fakeBotToken, chatID: 4242, client: srv.Client()}
	_, err := client.sendMessage(context.Background(), "TEST drill mock")
	var wc *errTelegramWrongChat
	if !errors.As(err, &wc) {
		t.Fatalf("expected *errTelegramWrongChat, got %T (%v)", err, err)
	}
	if wc.Expected != 4242 || wc.Got != 999 {
		t.Fatalf("wrong-chat error fields: got %d/%d, want 4242/999", wc.Expected, wc.Got)
	}
}

// TestN13P04T06_MockSink_SuccessParsesEchoAndWireShape pins both halves of
// the happy path: the client's request wire shape (JSON, chat_id, text,
// parse_mode=HTML, disable_web_page_preview=true — the telebot parity
// contract) and the response parse (message id, chat id, text, entities).
func TestN13P04T06_MockSink_SuccessParsesEchoAndWireShape(t *testing.T) {
	bodyCh := make(chan map[string]any, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		body := map[string]any{}
		_ = json.Unmarshal(raw, &body)
		bodyCh <- body
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":77,"chat":{"id":4242},"text":"TEST drill mock","entities":[]}}`))
	}))
	defer srv.Close()

	client := &telegramSinkClient{baseURL: srv.URL, token: fakeBotToken, chatID: 4242, client: srv.Client()}
	sent, err := client.sendMessage(context.Background(), "TEST drill mock")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sent.MessageID != 77 || sent.ChatID != 4242 || sent.Text != "TEST drill mock" || len(sent.Entities) != 0 {
		t.Fatalf("parsed echo mismatch: %+v", sent)
	}

	select {
	case body := <-bodyCh:
		if body["parse_mode"] != "HTML" {
			t.Fatalf("parse_mode: got %v, want HTML (DefaultTelegramConfig.ParseMode)", body["parse_mode"])
		}
		if body["disable_web_page_preview"] != true {
			t.Fatalf("disable_web_page_preview: got %v, want true (telebot parity)", body["disable_web_page_preview"])
		}
		if cid, ok := body["chat_id"].(float64); !ok || int64(cid) != 4242 {
			t.Fatalf("chat_id: got %v, want 4242", body["chat_id"])
		}
		if body["text"] != "TEST drill mock" {
			t.Fatalf("text: got %v, want the exact sent text", body["text"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("request body never captured")
	}
}
