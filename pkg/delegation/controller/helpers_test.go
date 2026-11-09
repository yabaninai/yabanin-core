package controller

import "os"

// writeFileForTest isolates the raw-file write the corrupt-state test needs
// (the store itself must never write non-episode bytes).
//
// TP16 flake hardening: the write is atomic — tmp file in the same
// directory, then rename — mirroring production SaveFenced. The TP16
// successor-state simulation runs concurrently with the controller's
// renewal worker, whose fencing Load must observe either the previous or
// the next COMPLETE file; a torn in-place write could surface as a false
// "corrupt episode" renewal failure instead of the fencing path this
// harness exists to exercise. The distinct ".test-tmp" suffix never
// collides with SaveFenced's own ".tmp" file for the same episode.
func writeFileForTest(path string, data []byte) error {
	tmp := path + ".test-tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
