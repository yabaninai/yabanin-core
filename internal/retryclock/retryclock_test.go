// SPDX-License-Identifier: Apache-2.0

package retryclock

import (
	"context"
	"testing"
	"time"
)

func TestFromReportsNoSleeperOnBareContext(t *testing.T) {
	if _, ok := From(context.Background()); ok {
		t.Fatal("a bare context must not carry a sleeper")
	}
}

func TestWithCarriesSleeperAcrossDerivedContexts(t *testing.T) {
	carried := false
	base := With(context.Background(), func(context.Context, time.Duration) { carried = true })
	ctx, cancel := context.WithCancel(base)
	defer cancel()
	sleep, ok := From(ctx)
	if !ok {
		t.Fatal("a derived context must expose the carried sleeper")
	}
	sleep(context.Background(), 0)
	if !carried {
		t.Fatal("From must return the sleeper installed by With")
	}
}

func TestWithNilSleeperFallsBackToRealTime(t *testing.T) {
	if sleep, ok := From(With(context.Background(), nil)); ok || sleep != nil {
		t.Fatal("a nil sleeper must select the real-time wait")
	}
}
