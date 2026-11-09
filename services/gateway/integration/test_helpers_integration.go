//go:build integration

package integration

import (
	"context"
	"fmt"
	"testing"

	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/modules/redis"
)

func setupPostgres(t *testing.T) *postgres.PostgresContainer {
	ctx := context.Background()

	container, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpass"),
	)
	if err != nil {
		t.Fatalf("failed to start postgres container: %v", err)
	}

	t.Cleanup(func() {
		_ = container.Terminate(ctx)
	})

	return container
}

func setupRedis(t *testing.T) *redis.RedisContainer {
	ctx := context.Background()

	container, err := redis.Run(ctx, "redis:7-alpine")
	if err != nil {
		t.Fatalf("failed to start redis container: %v", err)
	}

	t.Cleanup(func() {
		_ = container.Terminate(ctx)
	})

	return container
}

// GetPostgresConnection returns the connection URI and address for the test postgres container.
func GetPostgresConnection(t *testing.T) (string, string) {
	container := setupPostgres(t)

	ctx := context.Background()
	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("failed to get postgres host: %v", err)
	}

	port, err := container.MappedPort(ctx, "5432")
	if err != nil {
		t.Fatalf("failed to get postgres port: %v", err)
	}

	addr := fmt.Sprintf("%s:%s", host, port.String())
	return addr, addr
}

// GetRedisConnection returns the address for the test redis container.
func GetRedisConnection(t *testing.T) string {
	container := setupRedis(t)

	ctx := context.Background()
	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("failed to get redis host: %v", err)
	}

	port, err := container.MappedPort(ctx, "6379")
	if err != nil {
		t.Fatalf("failed to get redis port: %v", err)
	}

	return fmt.Sprintf("%s:%s", host, port.String())
}
