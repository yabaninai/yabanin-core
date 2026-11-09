package cache

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestABTest_Assign_Deterministic(t *testing.T) {
	test := NewABTest("test-cache", map[string]float64{
		"control":   0.5,
		"treatment": 0.5,
	})

	v1 := test.Assign("org-123")
	v2 := test.Assign("org-123")
	assert.Equal(t, v1, v2, "same org should always get same variant (sticky)")
}

func TestABTest_Assign_Variants(t *testing.T) {
	test := NewABTest("test-cache", map[string]float64{
		"control":   0.5,
		"treatment": 0.5,
	})

	// Collect assignments for many orgs — should get both variants.
	variants := make(map[string]bool)
	for i := 0; i < 100; i++ {
		v := test.Assign("org-" + string(rune('a'+i%26)))
		variants[v] = true
	}

	assert.Contains(t, variants, "control")
	assert.Contains(t, variants, "treatment")
}

func TestABTest_Assign_EmptyVariants(t *testing.T) {
	test := NewABTest("empty", map[string]float64{})
	assert.Empty(t, test.Assign("org-1"))
}

func TestStripPunctuation(t *testing.T) {
	assert.Equal(t, "Hello World 123", stripPunctuation("Hello, World! 123"))
	assert.Equal(t, "abc", stripPunctuation("a,b,c"))
	assert.Empty(t, stripPunctuation("!@#$%"))
}

func TestNormalizeWithPolicy_Aggressive_LowercaseAndStrip(t *testing.T) {
	input := []byte(`{"messages":[{"role":"user","content":"Hello, World! 123"}]}`)
	result, err := NormalizeWithPolicy(input, PolicyAggressive)
	if err != nil {
		t.Fatal(err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatal(err)
	}
	msgs := parsed["messages"].([]interface{})
	content := msgs[0].(map[string]interface{})["content"].(string)
	assert.Equal(t, "hello world 123", content)
}
