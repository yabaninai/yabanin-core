package policy_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/reireirei/yabanin/pkg/policy"
)

// TestMarketplace_ConcurrentSubscribeAndApply_NoRace reproduces the audit race
// in ApplySubscribed: it iterated m.subscribed without the lock while Subscribe
// appended under the lock. ApplySubscribed must work from a copy taken under
// the lock, and its localTmpls lookups must not race RegisterLocal either.
func TestMarketplace_ConcurrentSubscribeAndApply_NoRace(t *testing.T) {
	mp := policy.NewTemplateMarketplace(nil)

	const (
		iterations = 200
		readers    = 4
		writers    = 4
	)

	var wg sync.WaitGroup

	// RegisterLocal writer: mutates localTmpls concurrently with lookups.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			orgID := fmt.Sprintf("org-tmpl-%d", i)
			tmpl := policy.ExportAsTemplate(orgID, "shared-pack", "shared rules", "sg", "shared-rules",
				policy.ResidencyRule{AllowedJurisdictions: []policy.Region{"US"}})
			if err := mp.RegisterLocal(orgID, tmpl); err != nil {
				t.Errorf("RegisterLocal(%s) error: %v", orgID, err)
				return
			}
		}
	}()

	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				if err := mp.Subscribe("org-bob", fmt.Sprintf("org-tmpl-%d", i)); err != nil {
					t.Errorf("Subscribe error: %v", err)
					return
				}
			}
		}()
	}

	for r := 0; r < readers; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				cfgs, err := mp.ApplySubscribed("org-bob")
				if err != nil {
					t.Errorf("ApplySubscribed error: %v", err)
					return
				}
				for _, cfg := range cfgs {
					if cfg["template_id"] == "" {
						t.Errorf("ApplySubscribed returned config without template_id: %v", cfg)
						return
					}
				}
			}
		}()
	}

	wg.Wait()
}
