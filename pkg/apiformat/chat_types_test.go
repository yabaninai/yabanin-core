package apiformat

import (
	"encoding/json"
	"testing"
)

func TestContentText(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{name: "string", raw: `"hello"`, want: "hello"},
		{name: "null", raw: `null`, want: ""},
		{name: "empty", raw: ``, want: ""},
		{name: "parts", raw: `[{"type":"text","text":"a"},{"type":"image_url","image_url":{"url":"http://example"}},{"type":"input_text","text":"b"},{"type":"output_text","text":"c"}]`, want: "abc"},
		{name: "number", raw: `1`, want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ContentText(json.RawMessage(tc.raw)); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
