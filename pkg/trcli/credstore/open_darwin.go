package credstore

// Open returns the macOS keychain store.
func Open(home string, run Runner) (Store, error) {
	if run == nil {
		run = ExecRunner{}
	}
	_ = home
	return keychain{run: run}, nil
}
