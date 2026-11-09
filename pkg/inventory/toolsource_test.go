package inventory

// E02-P01 wiring card: the production ToolSource adapter — nil-safety
// and error propagation only (the listing behavior itself is
// *mcpagg.Proxy's, covered by its own tests; the per-server miss
// handling of the importer is covered by the W02 import tests).

import (
	"context"
	"testing"

	"github.com/reireirei/yabanin/pkg/mcpagg"
	"github.com/reireirei/yabanin/pkg/ssrf"
	"github.com/stretchr/testify/require"
)

func TestProxyToolSourceNilProxyIsReportedMissNotPanic(t *testing.T) {
	var p *ProxyToolSource
	_, err := p.ListTools(context.Background(), "org", "srv")
	require.ErrorIs(t, err, ErrNilSource)

	p = &ProxyToolSource{}
	_, err = p.ListTools(context.Background(), "org", "srv")
	require.ErrorIs(t, err, ErrNilSource)
}

func TestProxyToolSourceZeroIdentityMissesWithoutPanic(t *testing.T) {
	// Golden-constructible proxy: nil-DB store, default config, no
	// upstream. The zero identity must surface the proxy's refusal (the
	// delegation chain of an empty agent is empty), not a panic.
	proxy := mcpagg.NewProxy(mcpagg.NewStore(nil), mcpagg.NewDefaultConfig(), ssrf.AllowList{}, nil, nil)
	p := &ProxyToolSource{Proxy: proxy}

	_, err := p.ListTools(context.Background(), "org-ts", "srv")
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrNilSource)
	require.NotErrorIs(t, err, context.Canceled, "the miss is the proxy posture, not ctx")
}
