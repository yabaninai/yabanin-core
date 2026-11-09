//go:build !unix

package harness

import "errors"

func acquireLock(string) (func(), error) {
	return nil, errors.New("yb harness supports macOS and Linux only")
}
