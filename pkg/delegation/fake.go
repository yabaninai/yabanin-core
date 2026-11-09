package delegation

import "context"

// FakeExecutor is an in-process executor used when no Codex/Cursor bridge is
// configured. It never touches the network, never writes files, and never
// logs the task body.
type FakeExecutor struct {
	name string
}

// NewFakeExecutor returns a named fake (codex or cursor).
func NewFakeExecutor(name string) *FakeExecutor {
	if name == "" {
		name = string(ProviderCodex)
	}
	return &FakeExecutor{name: name}
}

// Name implements Executor.
func (f *FakeExecutor) Name() string { return f.name }

// Available always reports the fake as ready.
func (f *FakeExecutor) Available(context.Context) bool { return true }

// Run returns a success summary without touching the filesystem or network.
func (f *FakeExecutor) Run(_ context.Context, req Request) (Result, error) {
	summary := "fake " + f.name + " " + string(req.Mode) + " completed without writing files"
	return Result{
		Status:       "ok",
		Executor:     f.name,
		Summary:      summary,
		ChangedFiles: nil,
		DiffSummary:  "",
		Validation:   "skipped",
	}, nil
}
