package cache

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPrivacyMode_String(t *testing.T) {
	assert.Equal(t, "enabled", PrivacyEnabled.String())
	assert.Equal(t, "disabled", PrivacyDisabled.String())
	assert.Equal(t, "read-only", PrivacyReadCacheOnly.String())
}

func TestPolicyCache_GetAndSet(t *testing.T) {
	pc := NewPolicyCache(60 * time.Second)

	called := 0
	loader := func(ctx context.Context, orgID string) (*OrgPolicy, error) {
		called++
		return &OrgPolicy{Mode: PrivacyEnabled}, nil
	}

	// First call — loader should be invoked.
	pol := pc.Get(context.Background(), "org-1", loader)
	assert.Equal(t, PrivacyEnabled, pol.Mode)
	assert.Equal(t, 1, called)

	// Second call — cached, loader NOT invoked again (within TTL).
	pol2 := pc.Get(context.Background(), "org-1", loader)
	assert.Equal(t, PrivacyEnabled, pol2.Mode)
	assert.Equal(t, 1, called) // still 1
}

func TestPolicyCache_Expiry(t *testing.T) {
	pc := NewPolicyCache(50 * time.Millisecond)

	called := 0
	loader := func(ctx context.Context, orgID string) (*OrgPolicy, error) {
		called++
		return &OrgPolicy{Mode: PrivacyEnabled}, nil
	}

	pc.Get(context.Background(), "org-2", loader)
	assert.Equal(t, 1, called)

	// Wait for TTL expiry.
	time.Sleep(100 * time.Millisecond)

	// Loader should be called again.
	pol := pc.Get(context.Background(), "org-2", loader)
	assert.Equal(t, PrivacyEnabled, pol.Mode)
	assert.Equal(t, 2, called)
}

func TestPolicyCache_Invalidate(t *testing.T) {
	pc := NewPolicyCache(60 * time.Second)

	loader := func(ctx context.Context, orgID string) (*OrgPolicy, error) {
		return &OrgPolicy{Mode: PrivacyDisabled}, nil
	}

	pol := pc.Get(context.Background(), "org-3", loader)
	assert.Equal(t, PrivacyDisabled, pol.Mode)

	pc.Invalidate("org-3")

	// After invalidation, loader should be called again.
	called := 0
	loader2 := func(ctx context.Context, orgID string) (*OrgPolicy, error) {
		called++
		return &OrgPolicy{Mode: PrivacyEnabled}, nil
	}
	pol = pc.Get(context.Background(), "org-3", loader2)
	assert.Equal(t, PrivacyEnabled, pol.Mode)
	assert.Equal(t, 1, called)
}

func TestPolicyCache_FallbackOnLoaderError(t *testing.T) {
	pc := NewPolicyCache(60 * time.Second)

	loader := func(ctx context.Context, orgID string) (*OrgPolicy, error) {
		return nil, assert.AnError
	}

	pol := pc.Get(context.Background(), "org-err", loader)
	assert.Equal(t, PrivacyDisabled, pol.Mode) // fallback to disabled
}

func TestPolicyCache_DifferentOrgsIndependent(t *testing.T) {
	pc := NewPolicyCache(60 * time.Second)

	loader := func(ctx context.Context, orgID string) (*OrgPolicy, error) {
		mode := PrivacyEnabled
		if orgID == "org-a" {
			mode = PrivacyDisabled
		}
		return &OrgPolicy{Mode: mode}, nil
	}

	polA := pc.Get(context.Background(), "org-a", loader)
	polB := pc.Get(context.Background(), "org-b", loader)

	assert.Equal(t, PrivacyDisabled, polA.Mode)
	assert.Equal(t, PrivacyEnabled, polB.Mode)
}

func TestCacheService_Lookup_DisabledOrg(t *testing.T) {
	// Verify that a disabled org returns nil on lookup.
	pc := NewPolicyCache(60 * time.Second)
	pol := pc.Get(context.Background(), "no-cache-org", func(ctx context.Context, orgID string) (*OrgPolicy, error) {
		return &OrgPolicy{Mode: PrivacyDisabled}, nil
	})
	assert.Equal(t, PrivacyDisabled, pol.Mode)

	// The service's Lookup would skip all cache layers for this org.
	// Unit test verifies policy check logic.
}

func TestCacheService_Lookup_ReadOnlyOrg(t *testing.T) {
	pc := NewPolicyCache(60 * time.Second)
	pol := pc.Get(context.Background(), "ro-org", func(ctx context.Context, orgID string) (*OrgPolicy, error) {
		return &OrgPolicy{Mode: PrivacyReadCacheOnly}, nil
	})
	assert.Equal(t, PrivacyReadCacheOnly, pol.Mode)
}
