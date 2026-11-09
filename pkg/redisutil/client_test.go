package redisutil

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewClient_returnsNonNil(t *testing.T) {
	client := NewClient("localhost:6379")
	assert.NotNil(t, client)
}

func TestNewClient_defaultOptions(t *testing.T) {
	client := NewClient("redis://myhost:6380")
	opts := client.Options()

	assert.Equal(t, "redis://myhost:6380", opts.Addr)
	assert.Equal(t, 3*time.Second, opts.ReadTimeout)
	assert.Equal(t, 3*time.Second, opts.WriteTimeout)
	assert.Equal(t, 3*time.Second, opts.DialTimeout)
}

func TestNewClient_emptyAddr(t *testing.T) {
	client := NewClient("")
	assert.NotNil(t, client)
	opts := client.Options()
	// go-redis defaults to "localhost:6379" when addr is empty
	assert.Equal(t, "localhost:6379", opts.Addr)
}

func TestNewClient_multipleCallsIndependence(t *testing.T) {
	c1 := NewClient("host1:6379")
	c2 := NewClient("host2:6379")

	assert.NotEqual(t, c1.Options().Addr, c2.Options().Addr)
	assert.Equal(t, "host1:6379", c1.Options().Addr)
	assert.Equal(t, "host2:6379", c2.Options().Addr)
}

func TestDefaultTimeoutValue(t *testing.T) {
	// Verify the constant defaultTimeout is 3s
	assert.Equal(t, 3*time.Second, defaultTimeout)
}
