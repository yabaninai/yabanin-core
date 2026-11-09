package pipeline

import "testing"

func TestParsePolicy_RejectsTrailingDocument(t *testing.T) {
	input := validNoWhenYAML + "\n---\n" + validNoWhenYAML
	if _, err := ParsePolicy([]byte(input)); err == nil {
		t.Fatal("ParsePolicy accepted a second YAML document")
	}
}
