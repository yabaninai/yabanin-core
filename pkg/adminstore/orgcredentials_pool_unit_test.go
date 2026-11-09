package adminstore

import (
	"context"
	"testing"
	"time"
)

// (the DB paths live in orgcredentials_pool_int_test.go under the
// integration tag; these pin the guards that must never reach SQL).
func TestOrgCredentialPool_UnitGuards(t *testing.T) {
	s := &Store{} // db == nil

	if _, err := s.ListActiveOrgCredentials(context.Background(), "org", "openai", "https://x"); err == nil {
		t.Fatal("no db must fail closed")
	}
	if err := s.QuarantineOrgCredential(context.Background(), "org", "cred", time.Now().Add(time.Hour)); err == nil {
		t.Fatal("no db must fail closed")
	}

	calls := 0
	rec := func() *mockDB {
		return &mockDB{
			beginAuditTxFn: func(ctx context.Context) (auditTx, error) {
				calls++
				return nil, errTestAbort
			},
		}
	}
	s2 := newForTest(rec(), newTestLogger(), nil)

	if _, err := s2.ListActiveOrgCredentials(context.Background(), "", "openai", "https://x"); err != nil {
		t.Fatalf("empty org must be a silent empty result, got %v", err)
	}
	if _, err := s2.ListActiveOrgCredentials(context.Background(), "org", "", "https://x"); err != nil {
		t.Fatalf("empty provider must be a silent empty result, got %v", err)
	}
	for _, tc := range []struct {
		org, cred string
		until     time.Time
	}{
		{"", "cred", time.Now()},
		{"org", "", time.Now()},
		{"org", "cred", time.Time{}},
	} {
		if err := s2.QuarantineOrgCredential(context.Background(), tc.org, tc.cred, tc.until); err == nil {
			t.Fatalf("validation must refuse org=%q cred=%q zero-until=%v", tc.org, tc.cred, tc.until.IsZero())
		}
	}
	if calls != 0 {
		t.Fatalf("validation early-returns must not open a transaction, got %d", calls)
	}

	// Non-empty inputs reach the transaction; the failing BeginAuditTx
	// surfaces as an error (fail-closed, never a silent empty pool).
	if err := s2.QuarantineOrgCredential(context.Background(), "org", "cred", time.Now().Add(time.Hour)); err == nil {
		t.Fatal("tx failure must surface")
	}
}

var errTestAbort = &testAbortError{}

type testAbortError struct{}

func (*testAbortError) Error() string { return "abort" }
