package consumer

import (
	"strings"
	"testing"
)

func TestLabelsJSON(t *testing.T) {
	before := labelDecodeErrors.Load()
	if got := string(labelsJSON(nil)); got != "{}" {
		t.Fatalf("%s", got)
	}
	ok := string(labelsJSON(map[string]interface{}{"labels": `{"issue":"PAY-1","ci.pipeline":"42"}`}))
	if !strings.Contains(ok, `"issue":"PAY-1"`) || !strings.Contains(ok, `"ci.pipeline":"42"`) {
		t.Fatalf("%s", ok)
	}
	if got := string(labelsJSON(map[string]interface{}{"labels": "not-json"})); got != "{}" {
		t.Fatalf("%s", got)
	}
	if labelDecodeErrors.Load() == before {
		t.Fatal("decode error was not counted")
	}
	filtered := string(labelsJSON(map[string]interface{}{"labels": `{"1bad":"x","issue":"PAY-1"}`}))
	if strings.Contains(filtered, "1bad") || !strings.Contains(filtered, "PAY-1") {
		t.Fatalf("%s", filtered)
	}
}
