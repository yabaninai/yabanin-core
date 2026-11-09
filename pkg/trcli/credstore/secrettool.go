package credstore

import (
	"context"
	"strings"
)

type secretTool struct {
	run Runner
}

func (s secretTool) Put(ctx context.Context, name, key string) (string, string, error) {
	if _, err := s.run.Run(ctx, []byte(key), "secret-tool", SecretToolStoreArgs(name)...); err != nil {
		return "", "", err
	}
	return "secret-tool:" + name, "", nil
}

func (s secretTool) Get(ctx context.Context, name string) (string, error) {
	out, err := s.run.Run(ctx, nil, "secret-tool", SecretToolLookupArgs(name)...)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(out, "\r\n"), nil
}

func (s secretTool) Delete(ctx context.Context, name string) error {
	_, err := s.run.Run(ctx, nil, "secret-tool", "clear", "service", "yabanin", "account", name)
	return err
}
