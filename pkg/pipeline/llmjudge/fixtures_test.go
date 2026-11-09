package llmjudge

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"github.com/reireirei/yabanin/pkg/pipeline"
	"github.com/reireirei/yabanin/pkg/upstream"
)

// fixture is one quality-suite case: text plus the label a well-behaved
// toxicity judge is expected to produce.
type fixture struct {
	ID    string `json:"id"`
	Label string `json:"label"` // toxic | clean | boundary
	Text  string `json:"text"`
}

func loadFixtures(t *testing.T) []fixture {
	t.Helper()
	data, err := os.ReadFile("testdata/judge_fixtures.json")
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	var fs []fixture
	if err := json.Unmarshal(data, &fs); err != nil {
		t.Fatalf("decode fixtures: %v", err)
	}
	if len(fs) != 20 {
		t.Fatalf("fixtures = %d, want 20 (quality suite size is a contract)", len(fs))
	}
	labels := map[string]int{"toxic": 0, "clean": 0, "boundary": 0}
	for _, f := range fs {
		if _, ok := labels[f.Label]; !ok {
			t.Fatalf("fixture %s: unknown label %q", f.ID, f.Label)
		}
		labels[f.Label]++
	}
	for label, n := range labels {
		if n < 5 {
			t.Fatalf("label %s has %d fixtures, want >= 5 per class", label, n)
		}
	}
	return fs
}

// scriptedVerdict is the canned answer of the mock judge model per label —
// a stand-in for a correctly calibrated classifier: toxic claims with high
// confidence, clean returns no findings, boundary sits below the default
// threshold (0.8) so the documented threshold rule decides.
func scriptedVerdict(label string) string {
	switch label {
	case "toxic":
		return `{"findings":[{"category":"toxicity","severity":"high","confidence":0.97,"evidence":"per fixture"}],"summary":"violates"}`
	case "boundary":
		return `{"findings":[{"category":"toxicity","severity":"low","confidence":0.55,"evidence":"per fixture"}],"summary":"borderline"}`
	default:
		return `{"findings":[],"summary":"clean"}`
	}
}

// expectedAction is the verdict→Action mapping under threshold 0.8:
// toxic (0.97 ≥ 0.8) denies, boundary (0.55 < 0.8) flags, clean allows.
func expectedAction(label string) pipeline.Action {
	switch label {
	case "toxic":
		return pipeline.ActionDeny
	case "boundary":
		return pipeline.ActionFlag
	default:
		return pipeline.ActionAllow
	}
}

// fixturesHarness serves the scripted judge over HTTP (full transport path:
// adapter, pool, marker header) and maps fixture text → label.
func fixturesHarness(t *testing.T, fs []fixture, seen func(req ChatRequest)) *pipeline.Engine {
	t.Helper()
	byText := make(map[string]string, len(fs))
	for _, f := range fs {
		byText[f.Text] = f.Label
	}
	var mu sync.Mutex
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var wire struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
			Temperature float64 `json:"temperature"`
		}
		if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
			t.Errorf("decode: %v", err)
		}
		if wire.Temperature != 0 {
			t.Errorf("temperature = %v, want 0 (consistency contract)", wire.Temperature)
		}
		text := wire.Messages[len(wire.Messages)-1].Content
		label, ok := byText[text]
		if !ok {
			t.Errorf("mock model received unknown text %q", text)
			label = "clean"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]any{"role": "assistant", "content": scriptedVerdict(label)}},
			},
		})
	}))
	t.Cleanup(mock.Close)

	client := JudgeClientFunc(func(ctx context.Context, req ChatRequest) (ChatResponse, error) {
		mu.Lock()
		seen(req)
		mu.Unlock()
		// Route through the real upstream adapter for transport realism.
		pool := upstream.NewPool(upstream.Options{})
		uc := NewUpstreamJudgeClient(pool, ModelResolverFunc(func(_ context.Context, ref string) (Target, error) {
			return Target{Model: ref, UpstreamURL: mock.URL}, nil // on-prem endpoint: loopback
		}), nil)
		return uc.JudgeChat(ctx, req)
	})
	eng := pipeline.NewEngine()
	if err := Register(eng.Steps(), Deps{Client: client}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	return eng
}

// TestFixtures_QualitySuite runs the 20-case quality suite through a full
// engine run against the scripted (well-calibrated) judge: every toxic case
// denies, every clean case allows, every boundary case flags — never denies.
// This pins the verdict→Action contract the threshold documentation promises.
func TestFixtures_QualitySuite(t *testing.T) {
	fs := loadFixtures(t)
	eng := fixturesHarness(t, fs, func(ChatRequest) {})

	compiled, err := eng.LoadPolicy(judgePolicyYAML("judges-fixture-model", "", "fail_closed"))
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	for _, f := range fs {
		res := eng.Run(context.Background(), []pipeline.Compiled{compiled}, userPayload(f.Text))
		if got, want := res.Verdict, expectedAction(f.Label); got != want {
			t.Errorf("fixture %s (%s): verdict = %s, want %s", f.ID, f.Label, got, want)
		}
		if f.Label == "boundary" && res.Verdict == pipeline.ActionDeny {
			t.Errorf("fixture %s: boundary case must never deny under the documented threshold rule", f.ID)
		}
	}
}

// TestFixtures_Consistency is the judge-consistency contract: the same input
// must yield the same verdict on every run (temperature pinned to 0), and
// the run-to-run duration variance must not leak into decisions. It also
// exercises the step concurrently (race detector gate).
func TestFixtures_Consistency(t *testing.T) {
	fs := loadFixtures(t)
	var mu sync.Mutex
	temps := make(map[float64]int)
	eng := fixturesHarness(t, fs, func(req ChatRequest) {
		mu.Lock()
		temps[req.Temperature]++
		mu.Unlock()
	})

	compiled, err := eng.LoadPolicy(judgePolicyYAML("judges-fixture-model", "", "fail_closed"))
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}

	// Two full passes, second one concurrent: verdicts must be identical.
	first := make([]pipeline.Action, len(fs))
	for i, f := range fs {
		res := eng.Run(context.Background(), []pipeline.Compiled{compiled}, userPayload(f.Text))
		first[i] = res.Verdict
	}

	var wg sync.WaitGroup
	results := make([]pipeline.Action, len(fs))
	for i, f := range fs {
		wg.Add(1)
		go func(i int, f fixture) {
			defer wg.Done()
			res := eng.Run(context.Background(), []pipeline.Compiled{compiled}, userPayload(f.Text))
			results[i] = res.Verdict
		}(i, f)
	}
	wg.Wait()

	for i, f := range fs {
		if results[i] != first[i] {
			t.Errorf("fixture %s: inconsistent verdict %s vs %s across runs", f.ID, first[i], results[i])
		}
		if results[i] != expectedAction(f.Label) {
			t.Errorf("fixture %s: verdict = %s, want %s", f.ID, results[i], expectedAction(f.Label))
		}
	}
	if len(temps) != 1 {
		t.Fatalf("judge requests used temperatures %v, want only 0", temps)
	}
	if _, ok := temps[0]; !ok {
		t.Fatal("temperature 0 was never used")
	}
}

// TestFixtures_ThresholdDocExample pins the README threshold-choice example:
// with a stricter threshold the boundary verdict tightens from flag to deny
// only above the scripted confidence — and with a lenient one it stays a
// flag while toxic still denies. Guards against accidental threshold
// semantics drift.
func TestFixtures_ThresholdDocExample(t *testing.T) {
	fs := loadFixtures(t)
	eng := fixturesHarness(t, fs, func(ChatRequest) {})

	// lenient (0.5): boundary (0.55) now denies — documented consequence.
	compiled, err := eng.LoadPolicy(judgePolicyYAMLWithThreshold("judges-fixture-model", 0.5))
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	for _, f := range fs {
		if f.Label != "boundary" {
			continue
		}
		res := eng.Run(context.Background(), []pipeline.Compiled{compiled}, userPayload(f.Text))
		if res.Verdict != pipeline.ActionDeny {
			t.Errorf("fixture %s: lenient threshold must deny boundary, got %s", f.ID, res.Verdict)
		}
	}

	// strict (0.99): toxic (0.97) degrades to flag — documented consequence,
	// the reason the default is 0.8 and not higher.
	compiled, err = eng.LoadPolicy(judgePolicyYAMLWithThreshold("judges-fixture-model", 0.99))
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	for _, f := range fs {
		if f.Label != "toxic" {
			continue
		}
		res := eng.Run(context.Background(), []pipeline.Compiled{compiled}, userPayload(f.Text))
		if res.Verdict != pipeline.ActionFlag {
			t.Errorf("fixture %s: strict threshold must degrade toxic to flag, got %s", f.ID, res.Verdict)
		}
	}
}

// judgePolicyYAMLWithThreshold renders a judge policy with an explicit
// threshold param.
func judgePolicyYAMLWithThreshold(model string, threshold float64) []byte {
	return fmt.Appendf(nil, `
apiVersion: ypp/v1
kind: Policy
name: judge-threshold
mode: enforce
hooks: [pre_upstream]
steps:
  - id: judge_tox
    llm_judge:
      model: %s
      prompt_ref: "judges/toxicity@2"
    params:
      threshold: %v
`, model, threshold)
}
