//go:build unix

package harness

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
)

var (
	processMu   sync.Mutex
	processHeld bool
)

func acquireLock(path string) (func(), error) {
	processMu.Lock()
	if processHeld {
		processMu.Unlock()
		return nil, errLockBusy
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // G304: path is the harness lock under the user home, not a request path
	if err != nil {
		processMu.Unlock()
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		processMu.Unlock()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, errLockBusy
		}
		return nil, fmt.Errorf("another yb harness is running: %w", err)
	}
	processHeld = true
	processMu.Unlock()
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
		processMu.Lock()
		processHeld = false
		processMu.Unlock()
	}, nil
}
