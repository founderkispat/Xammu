package main

import (
	"errors"
	"fmt"

	"xammu/internal/runlock"
)

// acquireAuthorizationLock keeps one live run per authorization and origin. The
// ledger and limiter are per process, so without this the target sees the sum of
// two runs that each believe they honour the same C-09. The lock is taken before
// the first socket and released when the command returns; a process that crashes
// releases it through the operating system, which is why it is a kernel lock and
// not a file that has to be cleaned up.
//
// origin is the scheme://host:port string the run resolved as its target, so the
// key names the exact destination the permission is being spent on.
func acquireAuthorizationLock(ref, origin string) (*runlock.Lock, error) {
	dir, err := runlock.DefaultDir()
	if err != nil {
		return nil, fmt.Errorf("%w: cannot coordinate this run with other processes: %v: "+
			"nothing was sent", errUsage, err)
	}
	key := ref + "\x00" + origin
	lock, err := runlock.Acquire(dir, key)
	switch {
	case errors.Is(err, runlock.ErrBusy):
		return nil, fmt.Errorf("%w: another xammu run is spending authorization %s against %s "+
			"(lock %s); only one live run may use a permission against an origin, so nothing was sent",
			errUsage, ref, origin, runlock.PathFor(dir, key))
	case errors.Is(err, runlock.ErrUnsupported):
		return nil, fmt.Errorf("%w: this platform has no cross-process run lock, so xammu cannot "+
			"promise that two processes will not spend the same authorization: nothing was sent", errUsage)
	case err != nil:
		return nil, fmt.Errorf("%w: cannot take the run lock for %s against %s: %v: nothing was sent",
			errUsage, ref, origin, err)
	}
	return lock, nil
}
