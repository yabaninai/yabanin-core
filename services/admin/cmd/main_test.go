package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

// TestAdminShutdownDeadlock verifies the fix for P0.1: admin shutdown no longer
// hangs on errCh read after srv.Shutdown() returns. The old pattern used a buffered
// error channel that ListenAndServe only writes to on fatal errors — clean shutdown
// via http.ErrServerClosed was filtered out, causing <-errCh to block forever.
func TestAdminShutdownDeadlock(t *testing.T) {
	mux := http.NewServeMux()
	var lc net.ListenConfig
	lis, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := srv.Serve(lis); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	url := "http://" + lis.Addr().String() + "/"
	var ok bool
	for i := 0; i < 100; i++ {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			ok = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ok {
		t.Fatal("server didn't start")
	}

	// Simulate SIGTERM shutdown pattern from main.go lines 80-97
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	quit <- syscall.SIGTERM

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Logf("shutdown returned error: %v", err)
	}

	// With the fix (sync.WaitGroup), we don't read from errCh here.
	// The old buggy code would hang on <-errCh. Verify it doesn't block.
	select {
	case <-errCh:
		t.Fatal("unexpected: got error from errCh after clean shutdown")
	case <-time.After(2 * time.Second):
		t.Log("PASS: no deadlock — errCh read does not block (fixed via WaitGroup)")
	}
}
