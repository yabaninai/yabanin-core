package harness

import (
	"errors"
	"os"
	"path/filepath"
)

// FS is the filesystem the engine edits. Tests inject failures.
type FS interface {
	Read(path string) ([]byte, error)
	Stat(path string) (os.FileInfo, error)
	Lstat(path string) (os.FileInfo, error)
	Readlink(path string) (string, error)
	Remove(path string) error
	AtomicWrite(path string, data []byte, perm os.FileMode) error
}

type osFS struct{}

func (osFS) Read(path string) ([]byte, error) {
	return os.ReadFile(path) //nolint:gosec // G304: harness edits the path from the plan, which is a local config file
}

func (osFS) Stat(path string) (os.FileInfo, error) { return os.Stat(path) }

func (osFS) Lstat(path string) (os.FileInfo, error) { return os.Lstat(path) }

func (osFS) Readlink(path string) (string, error) { return os.Readlink(path) }

func (osFS) Remove(path string) error { return os.Remove(path) }

func (osFS) AtomicWrite(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".yb-tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	ok = true
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return nil
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return err
	}
	return dir.Close()
}

func resolveWritePath(fs FS, path string) (link, target string, err error) {
	info, err := fs.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", path, nil
		}
		return "", "", err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return "", path, nil
	}
	dest, err := fs.Readlink(path)
	if err != nil {
		return "", "", err
	}
	if !filepath.IsAbs(dest) {
		dest = filepath.Join(filepath.Dir(path), dest)
	}
	return path, dest, nil
}
