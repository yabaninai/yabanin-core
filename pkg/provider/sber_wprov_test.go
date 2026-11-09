package provider

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeSberKeypair generates a self-signed ECDSA P-256 keypair and writes the
// PEM paths. It stands in for the production mTLS material.
func writeSberKeypair(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sber-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	dir := t.TempDir()
	certPath = filepath.Join(dir, "client.crt")
	keyPath = filepath.Join(dir, "client.key")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(
		&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))
	return certPath, keyPath
}

// TestSber_NoClientTimeout pins the W-PROV stream-safety invariant:
// http.Client.Timeout bounds response-body reads and would kill streams, so
// no Sber-constructed client may carry one — on either construction path.
func TestSber_NoClientTimeout(t *testing.T) {
	t.Run("dev mode (no certs)", func(t *testing.T) {
		t.Setenv("SBER_CLIENT_CERT", "")
		t.Setenv("SBER_CLIENT_KEY", "")
		s, err := NewSber()
		require.NoError(t, err)
		assert.Zero(t, s.httpClient.Timeout, "no http.Client.Timeout anywhere on the stream path")
		assert.Nil(t, s.TLSConfig())
		assert.Nil(t, s.HTTPClient(), "production sber must not override the pool client")
	})
	t.Run("mTLS mode (certs set)", func(t *testing.T) {
		certPath, keyPath := writeSberKeypair(t)
		t.Setenv("SBER_CLIENT_CERT", certPath)
		t.Setenv("SBER_CLIENT_KEY", keyPath)
		s, err := NewSber()
		require.NoError(t, err)
		assert.Zero(t, s.httpClient.Timeout, "no http.Client.Timeout anywhere on the stream path")
		require.NotNil(t, s.TLSConfig(), "mTLS keypair must be exposed to the pool via TLSConfigProvider")
		assert.Len(t, s.TLSConfig().Certificates, 1)
		assert.Nil(t, s.HTTPClient(), "production sber must not override the pool client (SSRF guard survives)")
	})
	t.Run("nil test-hook client gets no timeout either", func(t *testing.T) {
		s := NewSberWithClient(nil)
		require.NotNil(t, s.HTTPClient())
		assert.Zero(t, s.HTTPClient().Timeout)
	})
}

// TestSber_TokenRefreshSingleFlight: N concurrent cold callers share exactly
// one token exchange (singleflight, not N mutex-serialised exchanges).
func TestSber_TokenRefreshSingleFlight(t *testing.T) {
	var tokenCalls int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/oauth", func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&tokenCalls, 1)
		time.Sleep(20 * time.Millisecond) // widen the race window
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "AT-SF",
			"expires_at":   time.Now().Add(30 * time.Minute).UnixMilli(),
		})
	})
	mux.HandleFunc("/api/v1/chat/completions", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	s := NewSberWithClient(srv.Client())
	const n = 16
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			_, err := s.PrepareRequest(context.Background(), srv.URL, sberChatPath, []byte(`{}`), "secret", false)
			errs <- err
		}()
	}
	for i := 0; i < n; i++ {
		require.NoError(t, <-errs)
	}
	assert.EqualValues(t, 1, atomic.LoadInt32(&tokenCalls), "concurrent cold callers must share one refresh")
}

// TestSber_TokenRefreshDetachedFromCallerContext pins the W-PROV invariant:
// the exchange runs on a detached, self-bounded context — the first caller
// cancelling mid-refresh must not abort the shared refresh.
func TestSber_TokenRefreshDetachedFromCallerContext(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var tokenCalls int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/oauth", func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&tokenCalls, 1)
		close(entered)
		<-release
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "AT-DETACHED",
			"expires_at":   time.Now().Add(30 * time.Minute).UnixMilli(),
		})
	})
	mux.HandleFunc("/api/v1/chat/completions", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	s := NewSberWithClient(srv.Client())
	ctx, cancel := context.WithCancel(context.Background())
	type result struct {
		req *http.Request
		err error
	}
	done := make(chan result, 1)
	go func() {
		req, err := s.PrepareRequest(ctx, srv.URL, sberChatPath, []byte(`{}`), "secret", false)
		done <- result{req, err}
	}()

	<-entered // refresh is in flight
	cancel()  // the first caller gives up...

	close(release) // ...but the shared refresh completes anyway
	res := <-done
	require.NoError(t, res.err, "refresh must be detached from the first caller's request context")
	require.NotNil(t, res.req)
	assert.Equal(t, "Bearer AT-DETACHED", res.req.Header.Get("Authorization"))
	assert.EqualValues(t, 1, atomic.LoadInt32(&tokenCalls))
}
