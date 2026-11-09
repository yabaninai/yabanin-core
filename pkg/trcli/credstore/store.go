package credstore

import (
	"context"
	"strings"
)

// Runner runs a credential helper. The secret belongs on stdin, not in args.
type Runner interface {
	Run(ctx context.Context, stdin []byte, name string, args ...string) (string, error)
	LookPath(file string) (string, error)
}

// Store saves and loads an API key for a profile name.
type Store interface {
	Put(ctx context.Context, name, key string) (ref, warning string, err error)
	Get(ctx context.Context, name string) (string, error)
	Delete(ctx context.Context, name string) error
}

func escapeQuoted(value string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range value {
		if r == '\\' || r == '"' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	b.WriteByte('"')
	return b.String()
}

// KeychainStdin is the security -i script. The key is only inside this script.
func KeychainStdin(name, key string) string {
	return "add-generic-password -U -s yabanin -a " + escapeQuoted(name) + " -w " + escapeQuoted(key) + "\n"
}

// KeychainGetArgs reads a password. The secret is not an argument.
func KeychainGetArgs(name string) []string {
	return []string{"find-generic-password", "-s", "yabanin", "-a", name, "-w"}
}

// SecretToolStoreArgs stores a secret. The secret itself is stdin.
func SecretToolStoreArgs(name string) []string {
	return []string{"store", "--label=yabanin", "service", "yabanin", "account", name}
}

// SecretToolLookupArgs reads a secret. The secret is not an argument.
func SecretToolLookupArgs(name string) []string {
	return []string{"lookup", "service", "yabanin", "account", name}
}
