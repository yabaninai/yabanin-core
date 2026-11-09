package delegation

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ConfineWorkspace returns a cleaned absolute workspace path. Symlinks are
// resolved when the path exists so later confinement checks use the real root.
func ConfineWorkspace(workspace string) (string, error) {
	workspace = strings.TrimSpace(workspace)
	if workspace == "" {
		return "", fmt.Errorf("workspace is required")
	}
	abs, err := filepath.Abs(workspace)
	if err != nil {
		return "", fmt.Errorf("workspace: %w", err)
	}
	abs = filepath.Clean(abs)
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = filepath.Clean(resolved)
	}
	info, err := os.Stat(abs)
	if err == nil && !info.IsDir() {
		return "", fmt.Errorf("workspace is not a directory")
	}
	return abs, nil
}

// AssertInside reports whether p is the workspace root or a file inside it
// after symlink resolution. Paths that escape via .. or a symlink are rejected.
func AssertInside(root, p string) error {
	root = filepath.Clean(root)
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = filepath.Clean(resolved)
	}
	if strings.TrimSpace(p) == "" {
		return fmt.Errorf("path is required")
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return err
	}
	abs = filepath.Clean(abs)
	resolved, err := resolveExisting(abs)
	if err != nil {
		return err
	}
	sep := string(filepath.Separator)
	if resolved != root && !strings.HasPrefix(resolved, root+sep) {
		return fmt.Errorf("path escapes workspace")
	}
	return nil
}

func resolveExisting(abs string) (string, error) {
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		return filepath.Clean(real), nil
	}
	dir := abs
	for {
		parent := filepath.Dir(dir)
		if real, err := filepath.EvalSymlinks(dir); err == nil {
			rel, relErr := filepath.Rel(dir, abs)
			if relErr != nil || strings.HasPrefix(rel, "..") {
				return "", fmt.Errorf("path escapes workspace")
			}
			return filepath.Clean(filepath.Join(real, rel)), nil
		}
		if parent == dir {
			return filepath.Clean(abs), nil
		}
		dir = parent
	}
}

func filterChangedFiles(root string, files []string) []string {
	if len(files) == 0 {
		return nil
	}
	out := make([]string, 0, len(files))
	for _, f := range files {
		if AssertInside(root, f) != nil {
			continue
		}
		out = append(out, f)
	}
	return out
}
