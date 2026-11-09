//go:build !darwin && !linux

package credstore

// Open returns the file store on platforms without a native key helper.
func Open(home string, run Runner) (Store, error) {
	if run == nil {
		run = ExecRunner{}
	}
	return fileStore{home: home, warn: true}, nil
}
