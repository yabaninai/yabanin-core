package upstream

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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeSberTestKeypair generates a self-signed ECDSA P-256 keypair and writes
// the PEM paths (production mTLS material stand-in).
func writeSberTestKeypair(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "sber-mtls-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	dir := t.TempDir()
	certPath = filepath.Join(dir, "c.crt")
	keyPath = filepath.Join(dir, "c.key")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))
	return certPath, keyPath
}

// TestSberAdapter_MTLSOverGuardedTransport runs the REAL sber adapter
// (factory path, mTLS env) through the pool: the pool-built transport
// survives (no wholesale client substitution — ForceAttemptHTTP2 is only set
// by the shared constructor) with the mTLS config layered on top, and no
// http.Client.Timeout exists on the stream path.
func TestSberAdapter_MTLSOverGuardedTransport(t *testing.T) {
	certPath, keyPath := writeSberTestKeypair(t)
	t.Setenv("SBER_CLIENT_CERT", certPath)
	t.Setenv("SBER_CLIENT_KEY", keyPath)

	c, err := newTestClientWithAdapter(Options{BaseURL: "https://gigachat.devices.sberbank.ru", ProviderName: "sber"})
	require.NoError(t, err)
	require.Zero(t, c.client.Timeout, "no http.Client.Timeout on the sber stream path")

	tr, ok := c.client.Transport.(*http.Transport)
	require.True(t, ok, "sber must NOT replace the pool client — only its TLS config")
	require.NotNil(t, tr.TLSClientConfig, "mTLS config composed on top of the pool transport")
	require.Len(t, tr.TLSClientConfig.Certificates, 1)
	assert.True(t, tr.ForceAttemptHTTP2,
		"transport must be the pool-built shared transport, not one substituted by the adapter")
}

// TestSberAdapter_StreamChunksNoClientTimeout pins the stream-liveness
// invariant end-to-end: chunked SSE delivery through the sber adapter works
// and the pool client carries no wall-clock timeout that would truncate it
// (the former 30s http.Client.Timeout killed streams mid-body).
func TestSberAdapter_StreamChunksNoClientTimeout(t *testing.T) {
	t.Setenv("SBER_CLIENT_CERT", "")
	t.Setenv("SBER_CLIENT_KEY", "")
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/oauth", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "AT-STREAM",
			"expires_at":   time.Now().Add(30 * time.Minute).UnixMilli(),
		})
	})
	mux.HandleFunc("/api/v1/chat/completions", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		for i := 0; i < 3; i++ {
			_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"x\"}}]}\n\n"))
			flusher.Flush()
			time.Sleep(10 * time.Millisecond)
		}
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
		flusher.Flush()
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := newTestClientWithAdapter(Options{BaseURL: srv.URL, ProviderName: "sber"})
	require.NoError(t, err)
	require.Zero(t, c.client.Timeout, "stream path must not carry a client-wide timeout")

	resp, err := c.Stream(context.Background(), []byte(`{"model":"gigachat","stream":true}`), "secret")
	require.NoError(t, err)
	defer resp.Body.Close()
	var sb strings.Builder
	buf := make([]byte, 1024)
	for {
		n, rerr := resp.Body.Read(buf)
		sb.Write(buf[:n])
		if rerr != nil {
			break
		}
	}
	assert.Contains(t, sb.String(), "[DONE]", "the chunked stream must be drained to completion")
}
