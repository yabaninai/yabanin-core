package kms

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The aws provider is a fail-closed stub (see aws_kms.go): the factory must
// never hand out a usable Provider for it, regardless of key id.
func TestNew_AWSProviderFailsClosed(t *testing.T) {
	p, err := New("aws", "alias/test-key")
	if err == nil {
		t.Fatalf("New(aws) = (%v, nil), want error (fail-closed stub)", p)
	}
	if p != nil {
		t.Fatalf("New(aws) returned non-nil Provider %v alongside the error", p)
	}
}

// ReadKeyFromEnv resolves key material through the pkg/config facet
// (config.KMSLocalFromEnv): the _FILE variant wins over the direct variable,
// file contents are trimmed, an empty file is rejected, and absence of both
// variables is an error. Each case sets both variables explicitly, so the
// results are hermetic against the ambient environment.
func TestReadKeyFromEnv(t *testing.T) {
	dir := t.TempDir()
	writeKeyFile := func(t *testing.T, name, content string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write key file: %v", err)
		}
		return path
	}

	tests := []struct {
		name    string
		keyFile string
		key     string
		want    string
		wantErr string
	}{
		{
			name:    "neither variable set",
			wantErr: "neither YABANIN_KMS_LOCAL_KEY_FILE nor YABANIN_KMS_LOCAL_KEY is set",
		},
		{
			name: "direct key used when no file",
			key:  "0123456789abcdef0123456789abcdef",
			want: "0123456789abcdef0123456789abcdef",
		},
		{
			name:    "file wins over direct key and is trimmed",
			keyFile: writeKeyFile(t, "padded", "\n  abcdef  \n"),
			key:     "ignored",
			want:    "abcdef",
		},
		{
			name:    "whitespace-only file rejected",
			keyFile: writeKeyFile(t, "empty", "  \n\t "),
			wantErr: "is empty",
		},
		{
			name:    "missing file rejected",
			keyFile: filepath.Join(dir, "does-not-exist"),
			wantErr: "read kms key file",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("YABANIN_KMS_LOCAL_KEY_FILE", tc.keyFile)
			t.Setenv("YABANIN_KMS_LOCAL_KEY", tc.key)

			got, err := ReadKeyFromEnv()
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("ReadKeyFromEnv() = %q, want error containing %q", got, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("ReadKeyFromEnv() error = %q, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ReadKeyFromEnv() error = %v, want key %q", err, tc.want)
			}
			if string(got) != tc.want {
				t.Fatalf("ReadKeyFromEnv() = %q, want %q", got, tc.want)
			}
		})
	}
}
