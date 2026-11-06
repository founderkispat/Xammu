//go:build unix

package runlock

import (
	"errors"
	"fmt"
	"syscall"
)

type platformLock struct {
	fd int
}

func acquirePlatform(path string) (*platformLock, error) {
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("runlock: cannot open %s: %w", path, err)
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = syscall.Close(fd)
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrBusy
		}
		return nil, fmt.Errorf("runlock: cannot lock %s: %w", path, err)
	}
	return &platformLock{fd: fd}, nil
}

func (p *platformLock) release() error {
	if p.fd < 0 {
		return nil
	}
	unlockErr := syscall.Flock(p.fd, syscall.LOCK_UN)
	closeErr := syscall.Close(p.fd)
	p.fd = -1
	if unlockErr != nil {
		return fmt.Errorf("runlock: cannot unlock: %w", unlockErr)
	}
	if closeErr != nil {
		return fmt.Errorf("runlock: cannot close the lock file: %w", closeErr)
	}
	return nil
}
