package adminstore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/reireirei/yabanin/pkg/encryption"
)

// modelRow13 builds a mock RETURNING row for models_registry matching the
// P3.3 column list used by modelColumns / scanModel.
func modelRow13(id, modelName, storedKey string) []interface{} {
	timeout := 0
	return []interface{}{
		id, modelName, modelName, "smart", nil, storedKey,
		"openai-compat", nil, []string{}, []string{}, &timeout, true, time.Now(),
	}
}

func rowWithData(rows [][]interface{}) pgx.Rows {
	return &mockPGXRows{data: rows}
}

// encryptor must fail the operation instead of silently storing plaintext.
func TestCreateModel_PlaintextKeyRefusedInProduction(t *testing.T) {
	restore := encryption.SetPlaintextPolicyForTest(func() bool { return false })
	defer restore()

	execCalled := false
	db := &mockDB{execFn: func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
		execCalled = true
		return pgconn.NewCommandTag("INSERT 0 1"), nil
	}}
	s := newForTest(db, newTestLogger(), nil)

	key := "sk-super-secret"
	_, err := s.CreateModelWithParams(context.Background(), CreateModelParams{
		ModelName:      "gpt-x",
		DisplayName:    "GPT X",
		UpstreamAPIKey: &key,
	})
	if err == nil {
		t.Fatal("expected error when writing provider key without encryptor in production, got nil")
	}
	if !strings.Contains(err.Error(), "plaintext") {
		t.Errorf("expected 'plaintext' in error, got: %v", err)
	}
	if execCalled {
		t.Error("no SQL must run when the write is refused")
	}
}

func TestUpdateModel_PlaintextKeyRefusedInProduction(t *testing.T) {
	restore := encryption.SetPlaintextPolicyForTest(func() bool { return false })
	defer restore()

	execCalled := false
	db := &mockDB{execFn: func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
		execCalled = true
		return pgconn.NewCommandTag("UPDATE 1"), nil
	}}
	s := newForTest(db, newTestLogger(), nil)

	key := "sk-super-secret"
	if err := s.UpdateModel(context.Background(), "gpt-x", "GPT X", nil, nil, &key, nil); err == nil {
		t.Fatal("expected UpdateModel to refuse plaintext key in production, got nil")
	}
	if execCalled {
		t.Error("no SQL must run when the write is refused")
	}
	if err := s.UpdateModelWithParams(context.Background(), UpdateModelParams{
		ModelName:      "gpt-x",
		UpstreamAPIKey: &key,
	}); err == nil {
		t.Fatal("expected UpdateModelWithParams to refuse plaintext key in production, got nil")
	}
	if execCalled {
		t.Error("no SQL must run when the write is refused")
	}
}

func TestCreateModel_PlaintextKeyAllowedInDevTest(t *testing.T) {
	var stored interface{}
	db := &mockDB{
		queryRowFn: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			stored = args[4]
			storedKey, _ := stored.(*string)
			return &mockPGXRow{data: [][]interface{}{modelRow13("id-1", "gpt-x", *storedKey)}}
		},
	}
	s := newForTest(db, newTestLogger(), nil)

	key := "sk-super-secret"
	m, err := s.CreateModel(context.Background(), "gpt-x", "GPT X", "smart", nil, &key)
	if err != nil {
		t.Fatalf("dev/test plaintext write must succeed, got: %v", err)
	}
	if stored == nil {
		t.Fatal("expected INSERT to run with the key argument")
	}
	if got := stored.(*string); got == nil || *got != key {
		t.Errorf("expected raw plaintext stored in dev/test, got %v", stored)
	}
	if m.UpstreamAPIKey == nil || *m.UpstreamAPIKey != key {
		t.Errorf("expected plaintext round-trip, got %v", m.UpstreamAPIKey)
	}
}

// reads return the original secret.
func TestCreateModel_KeyEncryptedWhenEncryptorConfigured(t *testing.T) {
	enc := encryption.MustNew(encryption.EncodeKey())
	var stored string
	db := &mockDB{
		queryRowFn: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			stored = *args[4].(*string)
			return &mockPGXRow{data: [][]interface{}{modelRow13("id-1", "gpt-x", stored)}}
		},
	}
	s := newForTest(db, newTestLogger(), enc)

	key := "sk-super-secret"
	if _, err := s.CreateModel(context.Background(), "gpt-x", "GPT X", "smart", nil, &key); err != nil {
		t.Fatalf("create model: %v", err)
	}
	if !encryption.IsEncrypted(stored) {
		t.Fatalf("expected enc:-prefixed stored value, got %q", stored)
	}
	if strings.Contains(stored, key) {
		t.Fatal("stored value must not contain the plaintext key")
	}
}

// legacy plaintext rows, and never fail on plaintext (read-only until the
// one-time migration runs).
func TestGetModelByName_ReadsCiphertextAndPlaintext(t *testing.T) {
	enc := encryption.MustNew(encryption.EncodeKey())
	secret := "sk-read-secret"
	ct, err := enc.Encrypt(secret)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	s := newForTest(&mockDB{
		queryRowFn: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			return &mockPGXRow{data: [][]interface{}{modelRow13("id-1", "gpt-x", ct)}}
		},
	}, newTestLogger(), enc)
	m, err := s.GetModelByName(context.Background(), "gpt-x")
	if err != nil {
		t.Fatalf("ciphertext read must succeed: %v", err)
	}
	if m.UpstreamAPIKey == nil || *m.UpstreamAPIKey != secret {
		t.Errorf("expected original secret from ciphertext row, got %v", m.UpstreamAPIKey)
	}

	// Legacy plaintext row with an encryptor configured: readable as-is.
	sPlain := newForTest(&mockDB{
		queryRowFn: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			return &mockPGXRow{data: [][]interface{}{modelRow13("id-2", "gpt-old", secret)}}
		},
	}, newTestLogger(), enc)
	m2, err := sPlain.GetModelByName(context.Background(), "gpt-old")
	if err != nil {
		t.Fatalf("plaintext read must not fail: %v", err)
	}
	if m2.UpstreamAPIKey == nil || *m2.UpstreamAPIKey != secret {
		t.Errorf("expected original secret from plaintext row, got %v", m2.UpstreamAPIKey)
	}

	// Without an encryptor, plaintext stays readable (read-only mode).
	sNoEnc := newForTest(&mockDB{
		queryRowFn: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			return &mockPGXRow{data: [][]interface{}{modelRow13("id-2", "gpt-old", secret)}}
		},
	}, newTestLogger(), nil)
	m3, err := sNoEnc.GetModelByName(context.Background(), "gpt-old")
	if err != nil {
		t.Fatalf("plaintext read without key must not fail: %v", err)
	}
	if m3.UpstreamAPIKey == nil || *m3.UpstreamAPIKey != secret {
		t.Errorf("expected original secret without encryptor, got %v", m3.UpstreamAPIKey)
	}
}

// A ciphertext row that cannot be decrypted (wrong key) must fail the read
// rather than serving ciphertext or an empty key.
func TestGetModelByName_WrongKeyCiphertextFails(t *testing.T) {
	e1 := encryption.MustNew(encryption.EncodeKey())
	e2 := encryption.MustNew(encryption.EncodeKey())
	ct, err := e1.Encrypt("sk-secret")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	s := newForTest(&mockDB{
		queryRowFn: func(ctx context.Context, sql string, args ...interface{}) pgx.Row {
			return &mockPGXRow{data: [][]interface{}{modelRow13("id-1", "gpt-x", ct)}}
		},
	}, newTestLogger(), e2)
	if _, err := s.GetModelByName(context.Background(), "gpt-x"); err == nil {
		t.Fatal("expected error decrypting ciphertext with the wrong key, got nil")
	}
}

func TestMigratePlaintextSecrets_NoEncryptorIsNoop(t *testing.T) {
	s := newForTest(&mockDB{}, newTestLogger(), nil)
	n, err := s.MigratePlaintextSecrets(context.Background())
	if err != nil {
		t.Fatalf("migration without encryptor must be a no-op, got: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 migrated, got %d", n)
	}
}

func TestMigratePlaintextSecrets_EncryptsAndIsIdempotent(t *testing.T) {
	enc := encryption.MustNew(encryption.EncodeKey())
	legacy := map[string]string{
		"row-1": "sk-legacy-one",
		"row-2": "sk-legacy-two",
	}
	updated := map[string]string{}
	queryCount := 0
	s := newForTest(&mockDB{
		queryFn: func(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
			queryCount++
			if queryCount > 1 { // idempotent second run: nothing left to do
				return rowWithData(nil), nil
			}
			rows := make([][]interface{}, 0, len(legacy))
			for id, key := range legacy {
				rows = append(rows, []interface{}{id, key})
			}
			return rowWithData(rows), nil
		},
		execFn: func(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
			if len(args) != 3 {
				return pgconn.NewCommandTag(""), errors.New("expected guarded update args (ct, id, old)")
			}
			ct, _ := args[0].(string)
			id, _ := args[1].(string)
			old, _ := args[2].(string)
			if !encryption.IsEncrypted(ct) {
				return pgconn.NewCommandTag(""), errors.New("migrated value must be enc:-prefixed")
			}
			if old != legacy[id] {
				return pgconn.NewCommandTag(""), errors.New("guard must match the read plaintext value")
			}
			updated[id] = ct
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}, newTestLogger(), enc)

	n, err := s.MigratePlaintextSecrets(context.Background())
	if err != nil {
		t.Fatalf("first migration run: %v", err)
	}
	if n != len(legacy) || len(updated) != len(legacy) {
		t.Fatalf("expected %d migrated, got %d", len(legacy), n)
	}
	for id, ct := range updated {
		plain, err := enc.Decrypt(ct)
		if err != nil || plain != legacy[id] {
			t.Errorf("row %s: migrated ciphertext must decrypt to the original secret", id)
		}
	}

	// Second run: scan finds nothing, no further updates.
	n2, err := s.MigratePlaintextSecrets(context.Background())
	if err != nil {
		t.Fatalf("second migration run: %v", err)
	}
	if n2 != 0 {
		t.Errorf("expected idempotent second run with 0 migrated, got %d", n2)
	}
	if len(updated) != len(legacy) {
		t.Errorf("second run must not update additional rows, got %d", len(updated)-len(legacy))
	}
}
