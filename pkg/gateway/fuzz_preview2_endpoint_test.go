package cli

import (
	"context"
	"testing"
)

func FuzzEndpointFrom(f *testing.F) {
	f.Add("production", "staging")
	f.Add("", "default")
	f.Add("dev", "test")
	f.Add("", "")

	f.Fuzz(func(t *testing.T, endpoint, def string) {
		var absent context.Context
		if got := endpointFrom(absent, def); got != def {
			t.Fatalf("missing context: got %q, want %q", got, def)
		}
		parent := withEndpoint(t.Context(), "parent")
		ctx := withEndpoint(parent, endpoint)
		if got := endpointFrom(parent, def); got != "parent" {
			t.Fatalf("child changed parent endpoint: got %q", got)
		}
		got := endpointFrom(ctx, def)

		if endpoint != "" && got != endpoint {
			t.Errorf("endpointFrom() = %v, want %v", got, endpoint)
		} else if endpoint == "" && got != def {
			t.Errorf("endpointFrom() = %v, want fallback %v", got, def)
		}
	})
}
