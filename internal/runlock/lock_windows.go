//go:build windows

package runlock

import (
	"errors"
	"fmt"
	"syscall"
)

type platformLock struct {
	handle syscall.Handle
}

// ERROR_SHARING_VIOLATION is errno 32. The standard syscall package does not
// name it, and adding x/sys would break the zero-dependency rule for one
// constant.
const errorSharingViolation syscall.Errno = 32

// acquirePlatform opens the file with a share mode of zero, so any second
// opener — another process or this one — fails with ERROR_SHARING_VIOLATION.
// Closing the handle is the unlock, and the kernel closes it even if the process
// dies.
func acquirePlatform(path string) (*platformLock, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("runlock: invalid lock path %s: %w", path, err)
	}
	h, err := syscall.CreateFile(name,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		0, nil, syscall.OPEN_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		if errors.Is(err, errorSharingViolation) {
			return nil, ErrBusy
		}
		return nil, fmt.Errorf("runlock: cannot open %s: %w", path, err)
	}
	return &platformLock{handle: h}, nil
}

func (p *platformLock) release() error {
	if p.handle == 0 || p.handle == syscall.InvalidHandle {
		return nil
	}
	err := syscall.CloseHandle(p.handle)
	p.handle = syscall.InvalidHandle
	if err != nil {
		return fmt.Errorf("runlock: cannot close the lock file: %w", err)
	}
	return nil
}
