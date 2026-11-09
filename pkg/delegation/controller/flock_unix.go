package controller

import (
	"os"
	"syscall"
)

// flockExNB takes an exclusive non-blocking flock (cross-process).
func flockExNB(fh *os.File) error {
	return syscall.Flock(int(fh.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}

// flockEx takes an exclusive blocking flock (cross-process). Callers must
// hold it only for the short critical section named in the lock hierarchy
// (see SaveFenced): blocked writers wait, so a long hold would stall every
// other controller touching the same episode.
func flockEx(fh *os.File) error {
	return syscall.Flock(int(fh.Fd()), syscall.LOCK_EX)
}

// funlock releases an flock taken by flockEx or flockExNB.
func funlock(fh *os.File) error {
	return syscall.Flock(int(fh.Fd()), syscall.LOCK_UN)
}
