package credstore

import (
	"context"
	"strings"
)

// keychain stores secrets in the macOS keychain through the security helper.
// The type compiles on every platform so the store logic stays exercisable
// with an injected Runner on non-darwin platforms (tests pass a fake helper,
// never a real keychain); production Open wiring returns it only on darwin.
// The stored value travels as security -i stdin script data, never as a
// process argument.
type keychain struct {
	run Runner
}

func (k keychain) Put(ctx context.Context, name, key string) (string, string, error) {
	if _, err := k.run.Run(ctx, []byte(KeychainStdin(name, key)), "security", "-i"); err != nil {
		return "", "", err
	}
	return "keychain:" + name, "", nil
}

func (k keychain) Get(ctx context.Context, name string) (string, error) {
	out, err := k.run.Run(ctx, nil, "security", KeychainGetArgs(name)...)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(out, "\r\n"), nil
}

func (k keychain) Delete(ctx context.Context, name string) error {
	_, err := k.run.Run(ctx, nil, "security", "delete-generic-password", "-s", "yabanin", "-a", name)
	return err
}
