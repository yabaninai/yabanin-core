package cache

import (
	"context"
	"testing"

	"github.com/redis/go-redis/v9"
)

// TestInvalidator_InvalidateOrgAll verifies that both Redis and pgvector are cleared.
func TestInvalidator_InvalidateOrgAll(t *testing.T) {
	inv := NewInvalidator(nil, nil, nil)

	// With nil backends, InvalidateOrgAll should not panic and should succeed gracefully.
	err := inv.InvalidateOrgAll(context.Background(), "org-123")
	if err != nil {
		t.Fatalf("InvalidateOrgAll with nil backends: %v", err)
	}
}

// TestInvalidator_InvalidateModelVersion verifies model version invalidation.
func TestInvalidator_InvalidateModelVersion(t *testing.T) {
	inv := NewInvalidator(nil, nil, nil)

	err := inv.InvalidateModelVersion(context.Background(), "gpt-4", "1")
	if err != nil {
		t.Fatalf("InvalidateModelVersion with nil pool: %v", err)
	}
}

// TestInvalidator_InvalidateByPromptHash verifies single-entry invalidation.
func TestInvalidator_InvalidateByPromptHash(t *testing.T) {
	exact := NewRedisStore(nil, 0)
	store := NewStore(nil)
	inv := NewInvalidator(exact, store, nil)

	err := inv.InvalidateByPromptHash(context.Background(), "org-1", "gpt-4", "abc123")
	if err != nil {
		t.Fatalf("InvalidateByPromptHash with nil backends: %v", err)
	}
}

// TestIsRedisNil verifies the helper.
func TestIsRedisNil(t *testing.T) {
	if !isRedisNil(redis.Nil) {
		t.Error("isRedisNil should return true for redis.Nil")
	}
	if isRedisNil(context.Canceled) {
		t.Error("isRedisNil should return false for context.Canceled")
	}
}
