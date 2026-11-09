package trcli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestIntegrationYAML(t *testing.T) {
	root := filepath.Join("..", "..")
	files := []string{
		filepath.Join(root, "integrations", "gitlab", "yabanin.gitlab-ci.yml"),
		filepath.Join(root, "integrations", "github", "setup-yb", "action.yml"),
		filepath.Join(root, "integrations", "github", "examples", "agent-job.yml"),
	}
	literalKey := regexp.MustCompile(`(?i)(yb_|sk-|ghp_|AKIA)[A-Za-z0-9]{8,}`)
	for _, path := range files {
		body, err := os.ReadFile(path) //nolint:gosec // G304: path is a repository integration file, not user input
		if err != nil {
			t.Fatal(err)
		}
		var doc yaml.Node
		if err := yaml.Unmarshal(body, &doc); err != nil {
			t.Fatal(path, err)
		}
		if doc.Kind == 0 {
			t.Fatalf("%s parsed empty", path)
		}
		text := string(body)
		if strings.Contains(path, "examples") {
			if !strings.Contains(text, "yb ci exec") || !strings.Contains(text, "yb ci env --format github") {
				t.Fatalf("%s missing the documented commands", path)
			}
		} else if !strings.Contains(text, "sha256sum -c") {
			t.Fatalf("%s does not verify sha256", path)
		}
		if literalKey.Match(body) {
			t.Fatalf("%s contains a literal key", path)
		}
	}
}
