package cli

import "context"

type endpointCtxKey struct{}

func withEndpoint(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, endpointCtxKey{}, name)
}

func endpointFrom(ctx context.Context, def string) string {
	if ctx == nil {
		return def
	}
	name, _ := ctx.Value(endpointCtxKey{}).(string)
	if name == "" {
		return def
	}
	return name
}
