package adapters

import (
	"fmt"

	"github.com/reireirei/yabanin/pkg/cictx"
	"github.com/reireirei/yabanin/pkg/harness"
)

type unsupportedAdapter struct {
	id     string
	reason string
}

func unsupported(id, reason string) unsupportedAdapter {
	return unsupportedAdapter{id: id, reason: reason}
}

func (u unsupportedAdapter) ID() string { return u.id }

func (u unsupportedAdapter) Supported() (bool, string) { return false, u.reason }

func (u unsupportedAdapter) Detect(string, cictx.Runner) Detection { return Detection{} }

func (u unsupportedAdapter) Plan(string, ConnectParams) (harness.Plan, error) {
	return harness.Plan{}, fmt.Errorf("%s: %s", u.id, u.reason)
}

func (u unsupportedAdapter) Unapply(string, []byte, harness.Managed) ([]byte, error) {
	return nil, fmt.Errorf("%s: %s", u.id, u.reason)
}
