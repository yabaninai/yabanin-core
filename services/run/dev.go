package run

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
)

const (
	defaultDevGatewayAddr = ":8082"
	defaultDevGatewayOps  = ":9090"
	defaultDevLoggerdAddr = ":8085"
	defaultDevAdminAddr   = ":8086"
)

// DevFlags selects the optional parts of `yabanin dev`. Gateway always starts.
type DevFlags struct {
	Migrate   bool
	NoAdmin   bool
	NoLoggerd bool
}

// DevRunners are the in-process entrypoints for `yabanin dev`. Tests replace
// them so the orchestrator can be proven without a database or sockets.
type DevRunners struct {
	Migrate        func(ctx context.Context) error
	Gateway        func(ctx context.Context) error
	Loggerd        func(ctx context.Context) error
	Admin          func(ctx context.Context) error
	Log            *slog.Logger
	GatewayAddr    string
	GatewayOpsAddr string
	LoggerdAddr    string
	AdminAddr      string
}

type devService struct {
	name string
	fn   func(ctx context.Context) error
}

// Dev loads nothing itself: the caller passes an already loaded config via the
// runners. With Migrate set, migrations run first and a failure starts nothing
// else. The remaining services share a context that is cancelled on the first
// error or when the parent context ends. Dev waits for every started service
// and returns the first failure.
func Dev(parent context.Context, flags DevFlags, runners DevRunners) error {
	log := runners.Log
	if log == nil {
		log = slog.Default()
	}

	if flags.Migrate {
		if runners.Migrate == nil {
			return errors.New("dev: migrate runner is required")
		}
		if err := runners.Migrate(parent); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	if err := parent.Err(); err != nil {
		return err
	}

	services := []devService{{name: "gateway", fn: runners.Gateway}}
	if !flags.NoLoggerd {
		services = append(services, devService{name: "loggerd", fn: runners.Loggerd})
	}
	if !flags.NoAdmin {
		services = append(services, devService{name: "admin", fn: runners.Admin})
	}
	for _, svc := range services {
		if svc.fn == nil {
			return fmt.Errorf("dev: %s runner is required", svc.name)
		}
	}

	log.Info("yabanin dev listening",
		"gateway", devAddr(runners.GatewayAddr, defaultDevGatewayAddr),
		"gateway_ops", devAddr(runners.GatewayOpsAddr, defaultDevGatewayOps),
		"loggerd", devAddr(runners.LoggerdAddr, defaultDevLoggerdAddr),
		"admin", devAddr(runners.AdminAddr, defaultDevAdminAddr),
	)

	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	errCh := make(chan error, len(services))
	var wg sync.WaitGroup
	for _, svc := range services {
		wg.Add(1)
		go func(svc devService) {
			defer wg.Done()
			log.Info("starting", "service", svc.name)
			err := svc.fn(ctx)
			if err != nil {
				log.Error("service failed", "service", svc.name, "error", err)
				cancel()
				errCh <- fmt.Errorf("%s: %w", svc.name, err)
				return
			}
			errCh <- nil
		}(svc)
	}
	go func() {
		wg.Wait()
		close(errCh)
	}()

	var first error
	for err := range errCh {
		if err != nil && first == nil {
			first = err
			cancel()
		}
	}
	return first
}

func devAddr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
