package credstore

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
)

const fileFallbackWarning = "key stored in ~/.yabanin/credentials.json; secret-tool is not installed"

type fileStore struct {
	home string
	warn bool
}

func (f fileStore) path() string {
	return filepath.Join(f.home, ".yabanin", "credentials.json")
}

func (f fileStore) Put(_ context.Context, name, key string) (string, string, error) {
	dir := filepath.Join(f.home, ".yabanin")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", err
	}
	secrets, err := f.read()
	if err != nil && !os.IsNotExist(err) {
		return "", "", err
	}
	if secrets.Keys == nil {
		secrets.Keys = map[string]string{}
	}
	secrets.Keys[name] = key
	body, err := json.Marshal(secrets)
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(f.path(), body, 0o600); err != nil {
		return "", "", err
	}
	warning := ""
	if f.warn {
		warning = fileFallbackWarning
	}
	return "file:" + name, warning, nil
}

func (f fileStore) Get(_ context.Context, name string) (string, error) {
	secrets, err := f.read()
	if err != nil {
		return "", err
	}
	key, ok := secrets.Keys[name]
	if !ok {
		return "", os.ErrNotExist
	}
	return key, nil
}

func (f fileStore) Delete(_ context.Context, name string) error {
	secrets, err := f.read()
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	delete(secrets.Keys, name)
	body, err := json.Marshal(secrets)
	if err != nil {
		return err
	}
	return os.WriteFile(f.path(), body, 0o600)
}

type fileSecrets struct {
	Keys map[string]string `json:"keys"`
}

func (f fileStore) read() (fileSecrets, error) {
	body, err := os.ReadFile(f.path())
	if err != nil {
		return fileSecrets{}, err
	}
	var secrets fileSecrets
	if err := json.Unmarshal(body, &secrets); err != nil {
		return fileSecrets{}, err
	}
	return secrets, nil
}
