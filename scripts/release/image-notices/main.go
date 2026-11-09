// Command image-notices collects original legal texts for the compiled image payload.
// It does not assess license compatibility or grant distribution approval.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"
)

type moduleRecord struct {
	Path          string `json:"path"`
	Version       string `json:"version"`
	SourcePath    string `json:"source_path"`
	SourceVersion string `json:"source_version"`
	Sum           string `json:"source_sum"`
}
type fileRecord struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type inventory struct {
	SchemaVersion int            `json:"schema_version"`
	BinarySHA256  string         `json:"binary_sha256"`
	GoVersion     string         `json:"go_version"`
	Modules       []moduleRecord `json:"modules"`
	Files         []fileRecord   `json:"files"`
}

var legalName = regexp.MustCompile(`(?i)^(licen[cs]es?|copying|notices?|patents?|copyright|authors)([.-].*)?$`)

func main() {
	binary := flag.String("binary", "", "compiled binary to inspect")
	source := flag.String("source", ".", "project source root")
	output := flag.String("output", "", "new legal payload directory")
	epoch := flag.String("epoch", "", "SOURCE_DATE_EPOCH in seconds")
	flag.Parse()
	if err := run(*binary, *source, *output, *epoch); err != nil {
		fmt.Fprintln(os.Stderr, "image-notices:", err)
		os.Exit(1)
	}
}

func goOutput(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", args...) // #nosec G204 -- fixed Go subcommands; only the explicit local binary path varies, without a shell.
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOWORK=off")
	data, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("go %s: %w", args[0], err)
	}
	return strings.TrimSpace(string(data)), nil
}

// go version -m uses the BuildInfo.String representation with one leading tab.
// ParseBuildInfo preserves replacement modules rather than licensing their originals.
func parseModules(text string) (string, []*debug.Module, error) {
	header, rest, ok := strings.Cut(text, "\n")
	fields := strings.Fields(header)
	if !ok || len(fields) < 2 || !strings.HasPrefix(fields[len(fields)-1], "go1.") {
		return "", nil, errors.New("missing binary Go build information")
	}
	var body strings.Builder
	for _, line := range strings.Split(rest, "\n") {
		body.WriteString(strings.TrimPrefix(line, "\t"))
		body.WriteByte('\n')
	}
	info, err := debug.ParseBuildInfo(body.String())
	if err != nil {
		return "", nil, err
	}
	if info.Path == "" {
		return "", nil, errors.New("missing binary package path")
	}
	return fields[len(fields)-1], info.Deps, nil
}

func escaped(value string) (string, error) {
	if value == "" || !filepath.IsLocal(value) || strings.ContainsAny(value, "\\@!\t\r\n ") || filepath.ToSlash(filepath.Clean(value)) != value {
		return "", errors.New("invalid versioned module identity")
	}
	for _, part := range strings.Split(value, "/") {
		if part == "." || part == ".." {
			return "", errors.New("invalid module component")
		}
	}
	var out strings.Builder
	for _, c := range value {
		if c >= 'A' && c <= 'Z' {
			out.WriteByte('!')
			out.WriteRune(c + 'a' - 'A')
		} else {
			out.WriteRune(c)
		}
	}
	return out.String(), nil
}

func moduleSource(m *debug.Module) (moduleRecord, string, error) {
	effective := m
	if m.Replace != nil {
		effective = m.Replace
	}
	if !strings.HasPrefix(effective.Version, "v") || strings.Contains(effective.Version, "/") {
		return moduleRecord{}, "", errors.New("local or unversioned replacement cannot supply versioned module notices")
	}
	path, err := escaped(effective.Path)
	if err != nil {
		return moduleRecord{}, "", err
	}
	version, err := escaped(effective.Version)
	if err != nil {
		return moduleRecord{}, "", err
	}
	return moduleRecord{m.Path, m.Version, effective.Path, effective.Version, effective.Sum}, path + "@" + version, nil
}

func isLegalText(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".go", ".c", ".h", ".cc", ".cpp", ".py", ".sh", ".js", ".ts", ".rb", ".rs", ".java":
		return false
	}
	return legalName.MatchString(name)
}

func legalFiles(root string, all bool) ([]string, error) {
	info, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("legal source must be a real directory")
	}
	var found []string
	hasLicense := all
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return errors.New("nonregular entry in legal source")
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		selected := all || isLegalText(entry.Name())
		// A source package named copyright is not a directory of license texts.
		// LICENSES directories can contain SPDX-named texts such as BSD-3-Clause.txt.
		parts := strings.Split(filepath.ToSlash(rel), "/")
		for _, part := range parts[:len(parts)-1] {
			lower := strings.ToLower(part)
			if lower == "licenses" || lower == "licences" {
				selected = true
				info, infoErr := entry.Info()
				if infoErr != nil {
					return infoErr
				}
				if info.Size() > 0 {
					hasLicense = true
				}
			}
		}
		if isLegalText(entry.Name()) {
			lower := strings.ToLower(entry.Name())
			if strings.HasPrefix(lower, "license") || strings.HasPrefix(lower, "licence") || strings.HasPrefix(lower, "copying") {
				info, infoErr := entry.Info()
				if infoErr != nil {
					return infoErr
				}
				if info.Size() > 0 {
					hasLicense = true
				}
			}
		}
		if selected {
			found = append(found, rel)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(found) == 0 || !hasLicense {
		return nil, errors.New("no legal texts found for linked component")
	}
	return found, nil
}

func readRegular(path string) (data []byte, err error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	info, err := root.Lstat(filepath.Base(path))
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("input must be a regular file")
	}
	return root.ReadFile(filepath.Base(path))
}

func copyFile(source, output, name string) (fileRecord, error) {
	info, err := os.Lstat(source)
	if err != nil {
		return fileRecord{}, err
	}
	if !info.Mode().IsRegular() {
		return fileRecord{}, errors.New("legal text must be a regular file")
	}
	data, err := readRegular(source)
	if err != nil {
		return fileRecord{}, err
	}
	if len(data) == 0 && strings.HasPrefix(filepath.ToSlash(name), "project/") {
		return fileRecord{}, fmt.Errorf("empty legal text: %s", name)
	}
	dest := filepath.Join(output, name)
	if err = os.MkdirAll(filepath.Dir(dest), 0755); err != nil { // #nosec G301 -- public image notices must be traversable by its unprivileged user.
		return fileRecord{}, err
	}
	if err = os.WriteFile(dest, data, 0644); err != nil { // #nosec G306 -- upstream legal texts are intentionally public, never secrets.
		return fileRecord{}, err
	}
	sum := sha256.Sum256(data)
	return fileRecord{filepath.ToSlash(name), hex.EncodeToString(sum[:])}, nil
}

func collectTree(root, output, prefix string, all bool) ([]fileRecord, error) {
	paths, err := legalFiles(root, all)
	if err != nil {
		return nil, err
	}
	var files []fileRecord
	for _, rel := range paths {
		record, copyErr := copyFile(filepath.Join(root, rel), output, filepath.Join(prefix, rel))
		if copyErr != nil {
			return nil, copyErr
		}
		files = append(files, record)
	}
	return files, nil
}

func collect(source, cache, goroot, output string, modules []*debug.Module, goVersion, binaryHash string, epoch int64) (resultErr error) {
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		return errors.New("output directory must not already exist")
	}
	if err := os.MkdirAll(output, 0755); err != nil { // #nosec G301 -- public image legal payload must be traversable.
		return err
	}
	inv := inventory{SchemaVersion: 1, BinarySHA256: binaryHash, GoVersion: goVersion, Modules: []moduleRecord{}, Files: []fileRecord{}}
	for _, name := range []string{"LICENSE", "NOTICE", "LICENSING.md", "pkg/pricing/NOTICE-litellm.txt"} {
		item, err := copyFile(filepath.Join(source, name), output, filepath.Join("project", filepath.Base(name)))
		if err != nil {
			return err
		}
		inv.Files = append(inv.Files, item)
	}
	// Preserve the Go license and nested standard-library/vendor legal texts.
	files, err := collectTree(goroot, output, "go-toolchain", false)
	if err != nil {
		return err
	}
	if _, err = os.Stat(filepath.Join(output, "go-toolchain", "LICENSE")); err != nil {
		return errors.New("go toolchain LICENSE absent")
	}
	inv.Files = append(inv.Files, files...)
	sort.Slice(modules, func(i, j int) bool { return modules[i].Path < modules[j].Path })
	seen := map[string]bool{}
	for _, m := range modules {
		record, key, sourceErr := moduleSource(m)
		if sourceErr != nil {
			return sourceErr
		}
		inv.Modules = append(inv.Modules, record)
		if seen[key] {
			continue
		}
		seen[key] = true
		files, err = collectTree(filepath.Join(cache, key), output, filepath.Join("modules", key), false)
		if err != nil {
			return fmt.Errorf("module %s@%s: %w", record.SourcePath, record.SourceVersion, err)
		}
		inv.Files = append(inv.Files, files...)
	}
	files, err = collectTree(filepath.Join(source, "scripts/release/image-os-notices"), output, "os", true)
	if err != nil {
		return err
	}
	inv.Files = append(inv.Files, files...)
	sort.Slice(inv.Files, func(i, j int) bool { return inv.Files[i].Path < inv.Files[j].Path })
	data, err := json.MarshalIndent(inv, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(output, "inventory.json"), append(data, '\n'), 0644); err != nil { // #nosec G306 -- public checksums and module identities, no credentials.
		return err
	}
	root, err := os.OpenRoot(output)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, root.Close()) }()
	stamp := time.Unix(epoch, 0)
	return filepath.WalkDir(output, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		mode := fs.FileMode(0644)
		if entry.IsDir() {
			mode = 0755
		}
		rel, err := filepath.Rel(output, path)
		if err != nil {
			return err
		}
		if err := root.Chmod(rel, mode); err != nil {
			return err
		}
		return root.Chtimes(rel, stamp, stamp)
	})
}

func run(binary, source, output, epochText string) error {
	epoch, err := strconv.ParseInt(epochText, 10, 64)
	if err != nil || epoch < 0 || binary == "" || output == "" {
		return errors.New("binary, output and nonnegative integer epoch are required")
	}
	text, err := goOutput("version", "-m", binary)
	if err != nil {
		return err
	}
	version, modules, err := parseModules(text)
	if err != nil {
		return err
	}
	toolVersion, err := goOutput("env", "GOVERSION")
	if err != nil {
		return err
	}
	if version != toolVersion {
		return errors.New("binary and notice toolchain versions differ")
	}
	cache, err := goOutput("env", "GOMODCACHE")
	if err != nil {
		return err
	}
	goroot, err := goOutput("env", "GOROOT")
	if err != nil {
		return err
	}
	data, err := readRegular(binary)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	return collect(source, cache, goroot, output, modules, version, hex.EncodeToString(sum[:]), epoch)
}
