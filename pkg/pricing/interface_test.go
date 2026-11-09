package pricing

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixedPricer returns one fixed answer regardless of the model.
type fixedPricer struct {
	price Price
	ok    bool
}

func (f fixedPricer) Lookup(_, _ string) (Price, bool) { return f.price, f.ok }

// TestSetDefaultPricer_SwapVisibleViaDefaultLookup (W-MONEY): the override
// reaches DefaultLookup immediately and a nil override is ignored. The
// static table is restored on cleanup so shuffle-order siblings (which
// assert against the static table) stay green.
func TestSetDefaultPricer_SwapVisibleViaDefaultLookup(t *testing.T) {
	t.Cleanup(func() { SetDefaultPricer(staticPricer{}) })

	SetDefaultPricer(fixedPricer{price: Price{InputPerM: 3}, ok: true})
	price, ok := DefaultLookup("openai", "gpt-4o")
	require.True(t, ok)
	assert.InDelta(t, 3.0, price.InputPerM, 1e-9)

	SetDefaultPricer(nil)
	price, ok = DefaultLookup("openai", "gpt-4o")
	require.True(t, ok)
	assert.InDelta(t, 3.0, price.InputPerM, 1e-9, "a nil override keeps the previous pricer")
}

// TestDefaultPricer_ConcurrentAccess (W-MONEY): SetDefaultPricer during
// live DefaultLookup traffic is race-free — the pre-atomic plain package
// global data-races here under -race.
func TestDefaultPricer_ConcurrentAccess(t *testing.T) {
	t.Cleanup(func() { SetDefaultPricer(staticPricer{}) })

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			SetDefaultPricer(fixedPricer{price: Price{InputPerM: float64(i)}})
		}(i)
		go func() {
			defer wg.Done()
			_, _ = DefaultLookup("openai", "gpt-4o")
		}()
	}
	wg.Wait()
}
