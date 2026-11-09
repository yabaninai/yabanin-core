package classifier

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/reireirei/yabanin/pkg/evalgate"
)

// CalibrationRefresher periodically reads evalgate verdicts and refits the calibrator.
type CalibrationRefresher struct {
	store    *evalgate.Store
	log      *slog.Logger
	mlClient *MLClassifier
	interval time.Duration
	ticker   *time.Ticker
	done     chan struct{}
}

// NewCalibrationRefresher creates a calibration refresher.
func NewCalibrationRefresher(store *evalgate.Store, mlClient *MLClassifier, log *slog.Logger) *CalibrationRefresher {
	return &CalibrationRefresher{
		store:    store,
		log:      log.With("component", "calibration-refresher"),
		mlClient: mlClient,
		interval: 1 * time.Hour,
		done:     make(chan struct{}),
	}
}

// Start begins periodic calibration refitting.
func (cr *CalibrationRefresher) Start(ctx context.Context) {
	cr.ticker = time.NewTicker(cr.interval)
	go func() {
		for {
			select {
			case <-ctx.Done():
				cr.ticker.Stop()
				return
			case <-cr.done:
				cr.ticker.Stop()
				return
			case <-cr.ticker.C:
				if err := cr.refit(); err != nil { //nolint:contextcheck // background refit loop owns its lifecycle
					cr.log.Warn("calibration refit failed", "error", err)
				} else {
					cr.log.Info("calibration refitted successfully")
				}
			}
		}
	}()
}

// Stop terminates the refresher.
func (cr *CalibrationRefresher) Stop() { close(cr.done) }

func (cr *CalibrationRefresher) refit() error {
	now := time.Now().Add(-7 * 24 * time.Hour) // last 7 days of data
	pairs, err := cr.store.LoadCalibrationPairs(context.Background(), now)
	if err != nil {
		return fmt.Errorf("load calibration pairs: %w", err)
	}

	if len(pairs) < 3 {
		cr.log.Info("calibration refit skipped — not enough data points", "points", len(pairs))
		return nil
	}

	// Create a fresh calibrator and fit it
	calc := NewCalibrator()
	calc.Fit(pairs)

	if calc.IsEnabled() {
		cr.mlClient.WithCalibrator(calc)
		cr.log.Info("calibration fitted", "pairs", len(pairs), "enabled", true)
	} else {
		return fmt.Errorf("calibration failed — not enough signal in data")
	}

	return nil
}
