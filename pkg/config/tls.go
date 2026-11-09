package config

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"time"
)

// TLSServerConfig holds TLS configuration for a service that can optionally
// listen with HTTPS/TLS. It is used by the gateway, admin, and any other
// HTTP server in the project.
type TLSServerConfig struct {
	Enabled      bool
	CertFile     string
	KeyFile      string
	MinVersion   uint16
	CipherSuites []string // empty = Go defaults (safe for TLS 1.2+)
}

// DefaultTLSServer returns a disabled-by-default TLS config. TLS must be
// explicitly enabled via configuration or environment variables.
func DefaultTLSServer() TLSServerConfig {
	return TLSServerConfig{
		Enabled:    false,
		CertFile:   env("YABANIN_TLS_CERT_FILE", ""),
		KeyFile:    env("YABANIN_TLS_KEY_FILE", ""),
		MinVersion: tls.VersionTLS12, // minimum TLS 1.2 for all services
	}
}

// Validate checks that the TLS configuration is internally consistent.
// Returns nil when TLS is disabled or when cert+key are both present.
func (c TLSServerConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.CertFile == "" {
		return fmt.Errorf("TLS enabled but cert_file is empty")
	}
	if c.KeyFile == "" {
		return fmt.Errorf("TLS enabled but key_file is empty")
	}
	// Check files exist before starting the server.
	if _, err := os.Stat(c.CertFile); err != nil {
		return fmt.Errorf("TLS cert file not found: %w", err)
	}
	if _, err := os.Stat(c.KeyFile); err != nil {
		return fmt.Errorf("TLS key file not found: %w", err)
	}
	return nil
}

// TLSConfig returns a *tls.Config suitable for http.Server.TLSConfig.
func (c TLSServerConfig) TLSConfig() (*tls.Config, error) {
	if !c.Enabled {
		return nil, nil //nolint:nilnil // documented: TLS disabled means no TLS config, not an error
	}
	cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS cert+key: %w", err)
	}
	minVer := c.MinVersion
	if minVer == 0 {
		minVer = tls.VersionTLS12 // default to TLS 1.2 if not explicitly set
	}
	if minVer < tls.VersionTLS12 {
		minVer = tls.VersionTLS12 // enforce minimum TLS 1.2
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   minVer,
	}
	if len(c.CipherSuites) > 0 {
		cfg.CipherSuites = make([]uint16, 0, len(c.CipherSuites))
		for _, name := range c.CipherSuites {
			switch name {
			case "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":
				cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
			case "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":
				cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305)
			case "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":
				cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
			case "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":
				cfg.CipherSuites = append(cfg.CipherSuites, tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305)
			default:
				return nil, fmt.Errorf("unsupported cipher suite: %s", name)
			}
		}
	} else {
		// Use Go's safe defaults (no weak ciphers when MinVersion >= 1.2).
		cfg.CipherSuites = []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		}
	}
	//nolint:staticcheck // PreferServerCipherSuites is deprecated but setting it has no side effects
	cfg.PreferServerCipherSuites = true
	return cfg, nil
}

// ServeWithTLS starts an http.Server with TLS if configured, otherwise uses
// plain ListenAndServe. The server is started in a goroutine and the error
// channel receives either the server error or nil on clean shutdown.
func ServeWithTLS(srv *http.Server, tlsCfg TLSServerConfig, listenErr chan<- error) {
	go func() {
		if err := tlsCfg.Validate(); err != nil {
			listenErr <- fmt.Errorf("TLS config invalid: %w", err)
			return
		}
		if tlsCfg.Enabled {
			tlsConf, err := tlsCfg.TLSConfig()
			if err != nil {
				listenErr <- fmt.Errorf("build TLS config: %w", err)
				return
			}
			srv.TLSConfig = tlsConf
			if err := srv.ListenAndServeTLS("", ""); err != nil && err.Error() != "http: Server closed" {
				listenErr <- fmt.Errorf("TLS listen failed: %w", err)
			}
		} else {
			if err := srv.ListenAndServe(); err != nil && err.Error() != "http: Server closed" {
				listenErr <- fmt.Errorf("listen failed: %w", err)
			}
		}
	}()
}

// ListenDuration returns a parsed duration for server timeouts with a default.
func ListenDuration(val string, def time.Duration) time.Duration {
	d, err := time.ParseDuration(val)
	if err != nil || d == 0 {
		return def
	}
	return d
}
