package adwatchd_test

import (
	"os"

	"golang.org/x/sys/unix"
)

func terminateProc(signal os.Signal) error {
	p := os.Getpid()

	pgid, err := unix.Getpgid(p)
	if err != nil {
		return err
	}

	// use pgid, ref: http://unix.stackexchange.com/questions/14815/process-descendants
	if pgid == p {
		p = -1 * p
	}

	target, err := os.FindProcess(p)
	if err != nil {
		return err
	}
	return target.Signal(signal)
}
