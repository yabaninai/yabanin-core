package cache

// N01-P04-T06/T07 rotation contract at the CACHE HMAC seam (cache_hmac
// secret, wired in the gateway as auth.NewCacheSigner and applied to every
// signed cache value):
//
//   - the dual-trust window: values signed under the old secret keep
//     verifying while the old signer is still configured — no cache flush
//     and no traffic pause are required to introduce the new secret;
//   - the revocation step: once the old secret is dropped, every value it
//     signed MUST fail verification and be treated as a miss (rebuilt from
//     the source of truth) — an attacker- or stale-signed value is never
//     served, and the old secret cannot read or forge entries under the new
//     one;
//   - the no-stop property: a rotation in this seam degrades to misses, not
//     errors — readers never receive an unverified value and the cache
//     rebuilds automatically (the documented cache_hmac runbook).
//
// The signer implementation itself is pkg/auth's CacheSigner; this file pins
// the rotation semantics at the cache boundary where the secret is consumed.

import (
	"testing"

	"github.com/reireirei/yabanin/pkg/auth"
)

const (
	hmacOldSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	hmacNewSecret = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
)

func mustSigner(t *testing.T, secret string) *auth.CacheSigner {
	t.Helper()
	s, err := auth.NewCacheSigner(secret)
	if err != nil {
		t.Fatalf("NewCacheSigner: %v", err)
	}
	return s
}

func TestCacheHMAC_Rotation_MissNotOutage(t *testing.T) {
	oldSigner := mustSigner(t, hmacOldSecret)
	newSigner := mustSigner(t, hmacNewSecret)

	const (
		cacheKey = "org:resolve:abc"
		value    = `{"org_id":"org-1"}`
	)

	// Pre-rotation: the old secret signs cache values and verifies them.
	signedOld := oldSigner.Sign(cacheKey, value)
	if got, ok := oldSigner.Verify(cacheKey, signedOld); !ok || got != value {
		t.Fatalf("old signer must verify its own value: %q, %v", got, ok)
	}

	// Dual trust: while both secrets are configured (the rotation window),
	// old-signed entries keep verifying — introducing the new secret stops
	// no traffic.
	if got, ok := oldSigner.Verify(cacheKey, signedOld); !ok || got != value {
		t.Fatalf("dual-trust window violated: %q, %v", got, ok)
	}

	// The same value under the new secret gets a different MAC — secrets are
	// not cross-compatible and one cannot forge the other's entries.
	signedNew := newSigner.Sign(cacheKey, value)
	if signedNew == signedOld {
		t.Fatal("the rotated secret must produce a distinct MAC for the same value")
	}

	// Revocation: after the old secret is dropped, its entries fail
	// verification — a MISS the cache rebuilds, never a served unverified
	// value and never an outage.
	if got, ok := newSigner.Verify(cacheKey, signedOld); ok {
		t.Fatalf("the rotated secret accepted an old-secret MAC: %q", got)
	}
	if got, ok := oldSigner.Verify(cacheKey, signedNew); ok {
		t.Fatalf("the old secret accepted a rotated-secret MAC: %q", got)
	}

	// The rotated secret serves its own entries; rebuilt values verify.
	if got, ok := newSigner.Verify(cacheKey, signedNew); !ok || got != value {
		t.Fatalf("the rotated secret must verify its own entries: %q, %v", got, ok)
	}
}

// TestCacheHMAC_Rotation_TamperingNeverVerifies bounds the seam: rotation
// must not weaken verification — tampered values, foreign keys, and
// malformed MACs fail closed under every secret in the ring.
func TestCacheHMAC_Rotation_TamperingNeverVerifies(t *testing.T) {
	oldSigner := mustSigner(t, hmacOldSecret)
	newSigner := mustSigner(t, hmacNewSecret)

	const (
		cacheKey = "org:resolve:abc"
		value    = `{"org_id":"org-1"}`
		tampered = `{"org_id":"org-2"}`
	)

	signed := oldSigner.Sign(cacheKey, value)
	forged := newSigner.Sign(cacheKey, tampered)

	cases := []struct {
		name   string
		signer *auth.CacheSigner
		signed string
	}{
		// Value swapped under a kept old MAC — the classic cache-poisoning
		// attempt the HMAC exists to refuse.
		{"old signer vs value swap", oldSigner, tampered + signed[len(value):]},
		{"old signer vs forged new mac", oldSigner, forged},
		{"new signer vs flipped old mac", newSigner, signed[:len(signed)-1] + "0"},
		{"old signer vs truncated mac", oldSigner, signed[:len(signed)-4]},
		{"old signer vs no mac", oldSigner, value},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, ok := tc.signer.Verify(cacheKey, tc.signed); ok {
				t.Fatalf("%s verified to %q; must fail closed", tc.name, got)
			}
		})
	}
}
