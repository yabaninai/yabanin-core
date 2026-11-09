package adapters

import (
	"fmt"
	"os"
	"strings"

	"github.com/reireirei/yabanin/pkg/cictx"
	"github.com/reireirei/yabanin/pkg/harness"
	"github.com/reireirei/yabanin/pkg/labels"
)

// ConnectParams is the input for planning a harness connection.
type ConnectParams struct {
	GatewayURL   string
	LabelsMode   string
	StaticLabels labels.Set
	Model        string
	SetDefault   bool
	Force        bool
	Experimental bool
	GlobalEnv    bool
	Models       []string
}

// Detection describes whether a tool is present and already connected.
type Detection struct {
	Installed  bool
	Version    string
	ConfigPath string
	Connected  bool
}

// Adapter plans and removes a tool's managed configuration.
type Adapter interface {
	ID() string
	Supported() (bool, string)
	Detect(home string, run cictx.Runner) Detection
	Plan(home string, p ConnectParams) (harness.Plan, error)
	Unapply(path string, current []byte, m harness.Managed) ([]byte, error)
}

// All returns supported tools first, then the unsupported list.
func All() []Adapter {
	return []Adapter{
		codexAdapter{}, claudeAdapter{}, opencodeAdapter{}, continueAdapter{}, aiderAdapter{}, shellAdapter{},
		unsupported("cursor", "requests go through Cursor servers; an internal gateway is not reachable"),
		unsupported("cline", "settings live in VS Code extension state"),
		unsupported("roo-code", "settings live in VS Code extension state"),
		unsupported("kilo-code", "settings live in VS Code extension state"),
		unsupported("zed", "not supported for automatic edits"),
		unsupported("jetbrains", "not supported for automatic edits"),
		unsupported("copilot", "not supported for automatic edits"),
		unsupported("gemini-cli", "the Gemini API format is not supported by the gateway until RM-104"),
	}
}

// ByID finds an adapter by its id.
func ByID(id string) (Adapter, bool) {
	for _, adapter := range All() {
		if adapter.ID() == id {
			return adapter, true
		}
	}
	return nil, false
}

func wrapBlock(tool, block, body string) string {
	id := tool + ":" + block
	body = strings.TrimRight(body, "\n")
	return fmt.Sprintf("# >>> yabanin:%s (managed by `yb harness`; undo: `yb harness disconnect %s`) >>>\n%s\n# <<< yabanin:%s <<<\n", id, tool, body, id)
}

func readOrEmpty(path string) ([]byte, error) {
	body, err := os.ReadFile(path) //nolint:gosec // G304: path is the tool config under the user home
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return body, nil
}
