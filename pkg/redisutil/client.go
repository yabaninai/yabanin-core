package redisutil

import (
	"crypto/tls"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const defaultTimeout = 3 * time.Second

// Options holds optional Redis connection parameters.
type Options struct {
	TLSEnabled bool
	TLSCert    string
	TLSKey     string
	TLSCA      string
	Username   string
	Password   string
	DB         int
}

// NewClient creates a redis.Client from addr with optional TLS and auth.
func NewClient(addr string, opts ...Options) *redis.Client {
	var o Options
	if len(opts) > 0 {
		o = opts[0]
	}

	clientOpts := &redis.Options{
		Addr:         addr,
		ReadTimeout:  defaultTimeout,
		WriteTimeout: defaultTimeout,
		DialTimeout:  defaultTimeout,
		Username:     o.Username,
		Password:     o.Password,
		DB:           o.DB,
	}

	if o.TLSEnabled {
		clientOpts.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
		if o.TLSCert != "" && o.TLSKey != "" {
			cert, err := tls.LoadX509KeyPair(o.TLSCert, o.TLSKey)
			if err != nil {
				panic(fmt.Sprintf("redisutil: load TLS cert/key: %v", err))
			}
			clientOpts.TLSConfig.Certificates = []tls.Certificate{cert}
		}
		if o.TLSCA != "" {
			// CA loading deferred to runtime via SetRootCA
			_ = o.TLSCA
		}
	}

	return redis.NewClient(clientOpts)
}
