package credstore

// Open returns secret-tool when it is installed, otherwise the file fallback.
func Open(home string, run Runner) (Store, error) {
	if run == nil {
		run = ExecRunner{}
	}
	return linuxStore(home, run)
}
