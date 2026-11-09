package classifier

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// mockClassifier is a test double that wraps a function.
type mockClassifier struct {
	name   string
	class  Class
	conf   float64
	err    error
	source Source
}

func (m *mockClassifier) Name() string { return m.name }
func (m *mockClassifier) Classify(_ context.Context, _ Input) (Result, error) {
	if m.err != nil {
		return Result{}, m.err
	}
	return Result{
		Class:      m.class,
		Confidence: m.conf,
		Source:     string(m.source),
		Latency:    1234,
	}, nil
}

func TestRegistry_PrimaryWorks(t *testing.T) {
	mc := &mockClassifier{name: "mock", class: ClassEasy, conf: 0.95, source: SourceRuleTier}
	reg := NewRegistry(mc)

	res := reg.Classify(context.Background(), Input{Prompt: "hello"})

	assert.Equal(t, ClassEasy, res.Class)
	assert.InDelta(t, 0.95, res.Confidence, 0.01)
	assert.Equal(t, string(SourceRuleTier), res.Source)
}

func TestRegistry_PrimaryFails_FallbackUsed(t *testing.T) {
	failing := &mockClassifier{name: "failing", err: errors.New("model unavailable")}
	fb := &mockClassifier{name: "fallback_tier", class: ClassHard, conf: 0.80, source: SourceRuleTier}

	reg := NewRegistry(failing, fb)

	res := reg.Classify(context.Background(), Input{Prompt: "debug this"})

	assert.Equal(t, ClassHard, res.Class)
	// Should have fallback suffix appended by the registry.
	assert.Contains(t, res.Source, "fallback_tier_fallback")
}

func TestRegistry_AllFail_DefaultMedium(t *testing.T) {
	failing1 := &mockClassifier{name: "fail1", err: errors.New("err1")}
	failing2 := &mockClassifier{name: "fail2", err: errors.New("err2")}

	reg := NewRegistry(failing1, failing2)

	res := reg.Classify(context.Background(), Input{Prompt: "anything"})

	assert.Equal(t, ClassMedium, res.Class, "should default to Medium when all classifiers fail")
	assert.Equal(t, string(SourceDefault), res.Source)
	assert.Zero(t, res.Confidence)
}

func TestRegistry_NoClassifiers_DefaultMedium(t *testing.T) {
	reg := NewRegistry(nil) // no primary, no fallbacks

	res := reg.Classify(context.Background(), Input{Prompt: "anything"})

	assert.Equal(t, ClassMedium, res.Class)
	assert.Equal(t, string(SourceDefault), res.Source)
}

func TestRegistry_PrimaryNil_FallbackWorks(t *testing.T) {
	fb := &mockClassifier{name: "only_fb", class: ClassEasy, conf: 0.90, source: SourceRuleTier}
	reg := NewRegistry(nil, fb) // nil primary

	res := reg.Classify(context.Background(), Input{Prompt: "summarize"})

	assert.Equal(t, ClassEasy, res.Class)
	assert.InDelta(t, 0.90, res.Confidence, 0.01)
}

func TestRegistry_MultipleFallbacks_TriesInOrder(t *testing.T) {
	firstFail := &mockClassifier{name: "fb1", err: errors.New("fail")}
	secondWorks := &mockClassifier{name: "fb2", class: ClassHard, conf: 0.75, source: SourceRuleTier}

	reg := NewRegistry(firstFail, firstFail, secondWorks) // fb1 twice then fb2

	res := reg.Classify(context.Background(), Input{Prompt: "test"})

	assert.Equal(t, ClassHard, res.Class)
	assert.Contains(t, res.Source, "fb2_fallback")
}

func TestClassifier_Constants(t *testing.T) {
	// Verify class constants have expected values.
	assert.Equal(t, ClassEasy, Class("easy"))
	assert.Equal(t, ClassMedium, Class("medium"))
	assert.Equal(t, ClassHard, Class("hard"))
}
