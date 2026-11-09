package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func generateSelfSignedCert(t *testing.T, dir string) (string, string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPath := dir + "/cert.pem"
	certFile, err := os.Create(certPath) //nolint:gosec // G304: test fixture path from t.TempDir()
	if err != nil {
		t.Fatalf("failed to create cert file: %v", err)
	}
	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	_ = certFile.Close()
	if err != nil {
		t.Fatalf("failed to encode cert: %v", err)
	}

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}

	keyPath := dir + "/key.pem"
	keyFile, err := os.Create(keyPath) //nolint:gosec // G304: test fixture path from t.TempDir()
	if err != nil {
		t.Fatalf("failed to create key file: %v", err)
	}
	err = pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	_ = keyFile.Close()
	if err != nil {
		t.Fatalf("failed to encode key: %v", err)
	}

	return certPath, keyPath
}

func TestDefaultTLSServer(t *testing.T) {
	cfg := DefaultTLSServer()
	if cfg.Enabled {
		t.Error("expected Enabled to be false by default")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("expected MinVersion %d, got %d", tls.VersionTLS12, cfg.MinVersion)
	}
}

func TestTLSServerConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     TLSServerConfig
		wantErr bool
		errSub  string
	}{
		{
			name:    "disabled returns nil",
			cfg:     DefaultTLSServer(),
			wantErr: false,
		},
		{
			name:    "enabled with cert but no key",
			cfg:     TLSServerConfig{Enabled: true, CertFile: "/tmp/cert.pem"},
			wantErr: true,
			errSub:  "key_file is empty",
		},
		{
			name:    "enabled with key but no cert",
			cfg:     TLSServerConfig{Enabled: true, KeyFile: "/tmp/key.pem"},
			wantErr: true,
			errSub:  "cert_file is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errSub != "" {
				if !strings.Contains(err.Error(), tt.errSub) {
					t.Errorf("Validate() error = %q, want substring %q", err, tt.errSub)
				}
			}
		})
	}
}

func TestTLSServerConfig_TLSConfig(t *testing.T) {
	tests := []struct {
		name     string
		cfg      TLSServerConfig
		wantNil  bool // want result to be nil (both config and error)
		wantErr  bool
		errSub   string
		certFile string
		keyFile  string
	}{
		{
			name:    "disabled returns nil, nil",
			cfg:     DefaultTLSServer(),
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCfg, err := tt.cfg.TLSConfig()
			if tt.wantNil {
				if gotCfg != nil || err != nil {
					t.Errorf("TLSConfig() = (%v, %v), want (nil, nil)", gotCfg, err)
				}
				return
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("TLSConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.errSub != "" && err != nil {
				if !strings.Contains(err.Error(), tt.errSub) {
					t.Errorf("TLSConfig() error = %q, want substring %q", err, tt.errSub)
				}
			}
			if !tt.wantNil && gotCfg == nil {
				t.Error("expected non-nil *tls.Config")
			}
		})
	}

	t.Run("valid cert+key returns config with correct settings", func(t *testing.T) {
		dir := t.TempDir()
		certPath, keyPath := generateSelfSignedCert(t, dir)

		cfg := TLSServerConfig{
			Enabled:    true,
			CertFile:   certPath,
			KeyFile:    keyPath,
			MinVersion: tls.VersionTLS12,
		}

		tlsCfg, err := cfg.TLSConfig()
		if err != nil {
			t.Fatalf("TLSConfig() unexpected error: %v", err)
		}
		if tlsCfg == nil {
			t.Fatal("expected non-nil *tls.Config")
		}
		if len(tlsCfg.Certificates) != 1 {
			t.Errorf("expected 1 certificate, got %d", len(tlsCfg.Certificates))
		}
		if tlsCfg.MinVersion != tls.VersionTLS12 {
			t.Errorf("expected MinVersion %d, got %d", tls.VersionTLS12, tlsCfg.MinVersion)
		}
		//nolint:staticcheck // PreferServerCipherSuites is deprecated but we still verify the value for backwards compatibility
		if !tlsCfg.PreferServerCipherSuites {
			t.Error("expected PreferServerCipherSuites to be true")
		}
		if len(tlsCfg.CipherSuites) == 0 {
			t.Error("expected non-empty cipher suites list")
		}

		expectedCiphers := []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		}
		if len(tlsCfg.CipherSuites) != len(expectedCiphers) {
			t.Errorf("expected %d cipher suites, got %d", len(expectedCiphers), len(tlsCfg.CipherSuites))
		}
		for i, expected := range expectedCiphers {
			if i >= len(tlsCfg.CipherSuites) || tlsCfg.CipherSuites[i] != expected {
				t.Errorf("cipher suite[%d]: expected %d, got %v", i, expected, tlsCfg.CipherSuites)
			}
		}
	})

	t.Run("valid cert+key with custom cipher suites", func(t *testing.T) {
		dir := t.TempDir()
		certPath, keyPath := generateSelfSignedCert(t, dir)

		cfg := TLSServerConfig{
			Enabled:    true,
			CertFile:   certPath,
			KeyFile:    keyPath,
			MinVersion: tls.VersionTLS12,
			CipherSuites: []string{
				"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
			},
		}

		tlsCfg, err := cfg.TLSConfig()
		if err != nil {
			t.Fatalf("TLSConfig() unexpected error: %v", err)
		}
		if tlsCfg == nil {
			t.Fatal("expected non-nil *tls.Config")
		}
		if len(tlsCfg.CipherSuites) != 1 {
			t.Errorf("expected 1 custom cipher suite, got %d", len(tlsCfg.CipherSuites))
		}
		if tlsCfg.CipherSuites[0] != tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305 {
			t.Errorf("expected cipher TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, got %d", tlsCfg.CipherSuites[0])
		}
	})

	t.Run("unsupported cipher suite returns error", func(t *testing.T) {
		dir := t.TempDir()
		certPath, keyPath := generateSelfSignedCert(t, dir)

		cfg := TLSServerConfig{
			Enabled:      true,
			CertFile:     certPath,
			KeyFile:      keyPath,
			CipherSuites: []string{"TLS_INVALID_CIPHER"},
		}

		_, err := cfg.TLSConfig()
		if err == nil {
			t.Fatal("expected error for unsupported cipher suite")
		}
		if !strings.Contains(err.Error(), "unsupported cipher suite") {
			t.Errorf("expected error about unsupported cipher suite, got: %v", err)
		}
	})

	t.Run("missing cert file returns error", func(t *testing.T) {
		dir := t.TempDir()
		keyPath := dir + "/key.pem"
		f, _ := os.Create(keyPath) //nolint:gosec // G304: test fixture path from t.TempDir()
		_ = f.Close()

		cfg := TLSServerConfig{
			Enabled:    true,
			CertFile:   dir + "/nonexistent.pem",
			KeyFile:    keyPath,
			MinVersion: tls.VersionTLS12,
		}

		_, err := cfg.TLSConfig()
		if err == nil {
			t.Fatal("expected error for missing cert file")
		}
	})
}

func TestListenDuration(t *testing.T) {
	cases := []struct {
		name string
		val  string
		def  time.Duration
		want time.Duration
	}{
		{"valid", "15s", 10 * time.Second, 15 * time.Second},
		{"empty keeps default", "", 10 * time.Second, 10 * time.Second},
		{"garbage keeps default", "soon", 10 * time.Second, 10 * time.Second},
		{"zero keeps default", "0", 10 * time.Second, 10 * time.Second},
		{"negative allowed", "-5s", 10 * time.Second, -5 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ListenDuration(tc.val, tc.def); got != tc.want {
				t.Errorf("ListenDuration(%q, %v) = %v, want %v", tc.val, tc.def, got, tc.want)
			}
		})
	}
}

// ServeWithTLS must surface config problems on the listenErr channel instead
// of panicking or silently not listening.
func TestServeWithTLSReportsConfigErrors(t *testing.T) {
	t.Run("invalid tls config", func(t *testing.T) {
		errCh := make(chan error, 1)
		ServeWithTLS(&http.Server{Addr: "127.0.0.1:0", ReadHeaderTimeout: 5 * time.Second}, TLSServerConfig{Enabled: true}, errCh)
		err := <-errCh
		if err == nil || !strings.Contains(err.Error(), "TLS config invalid") {
			t.Errorf("err = %v, want TLS config invalid", err)
		}
	})
	t.Run("unparseable cert pair", func(t *testing.T) {
		dir := t.TempDir()
		cert, key := dir+"/cert.pem", dir+"/key.pem"
		for _, p := range []string{cert, key} {
			if err := os.WriteFile(p, []byte("not a pem"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		errCh := make(chan error, 1)
		ServeWithTLS(&http.Server{Addr: "127.0.0.1:0", ReadHeaderTimeout: 5 * time.Second}, TLSServerConfig{Enabled: true, CertFile: cert, KeyFile: key}, errCh)
		err := <-errCh
		if err == nil || !strings.Contains(err.Error(), "build TLS config") {
			t.Errorf("err = %v, want build TLS config failure", err)
		}
	})
	t.Run("plain listen failure surfaces", func(t *testing.T) {
		errCh := make(chan error, 1)
		ServeWithTLS(&http.Server{Addr: "256.256.256.256:1", ReadHeaderTimeout: 5 * time.Second}, TLSServerConfig{}, errCh)
		err := <-errCh
		if err == nil || !strings.Contains(err.Error(), "listen failed") {
			t.Errorf("err = %v, want listen failed", err)
		}
	})
}
