package credstore

// linuxStore uses secret-tool when it is on PATH, otherwise the file fallback.
func linuxStore(home string, run Runner) (Store, error) {
	if _, err := run.LookPath("secret-tool"); err == nil {
		return secretTool{run: run}, nil
	}
	return fileStore{home: home, warn: true}, nil
}
