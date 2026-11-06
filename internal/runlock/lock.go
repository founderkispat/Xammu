// Package runlock serialises live runs that would otherwise spend the same
// authorization against the same origin at the same time.
//
// The in-process ledger and limiter are correct only for one process. Two
// processes holding the same C-09 each honour their own copy of the budget while
// the target sees the sum. This package closes that gap with an operating-system
// lock held for the lifetime of one run: the second process is refused before it
// opens a socket, and the first remains the only spender.
//
// The lock is a file whose name is derived from the authorization and the
// origin. Unix uses flock(2); Windows opens the same file with no sharing. Both
// release the lock when the process exits, including a crash, so there is no
// stale-state recovery to get wrong. Lock files are not deleted on release: a
// delete after unlock races with the next acquirer and could let two processes
// create different files for the same key.
package runlock

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrBusy reports that another process holds the same authorization and origin.
var ErrBusy = errors.New("another process holds this run lock")

// ErrUnsupported reports a platform without a cross-process lock. Acquire
// returns it instead of silently letting two runs proceed.
var ErrUnsupported = errors.New("cross-process run locks are not supported on this platform")

// Lock is one held lock. Release is idempotent and safe to defer.
type Lock struct {
	path     string
	platform *platformLock
	released bool
}

// DefaultDir is the per-user directory where lock files live. A cache
// directory keeps them out of the evidence tree and gives each operating-system
// user a separate namespace, so two operators on one machine do not block each
// other.
func DefaultDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil || base == "" {
		base = os.TempDir()
	}
	if base == "" {
		return "", errors.New("runlock: no cache or temporary directory for lock files")
	}
	return filepath.Join(base, "xammu", "locks"), nil
}

// Acquire takes the exclusive lock for key under dir, creating dir when needed.
// It does not wait: a run that cannot take the lock is refused rather than
// queued, because a queued run would still be spending the same budget.
func Acquire(dir, key string) (*Lock, error) {
	if dir == "" {
		return nil, errors.New("runlock: empty lock directory")
	}
	if key == "" {
		return nil, errors.New("runlock: empty lock key")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("runlock: cannot create the lock directory %s: %w", dir, err)
	}
	path := filepath.Join(dir, fileName(key))
	held, err := acquirePlatform(path)
	if err != nil {
		return nil, err
	}
	return &Lock{path: path, platform: held}, nil
}

// Release drops the lock. Calling it twice is not an error.
func (l *Lock) Release() error {
	if l == nil || l.platform == nil || l.released {
		return nil
	}
	l.released = true
	return l.platform.release()
}

// Path names the file that carries the lock. It is exposed for diagnostics: the
// refusal message tells an operator which run is in the way.
func (l *Lock) Path() string {
	if l == nil {
		return ""
	}
	return l.path
}

func fileName(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:]) + ".lock"
}

// PathFor names the file a key would use without taking the lock. It exists so
// a refusal can point at the lock without acquiring it first.
func PathFor(dir, key string) string {
	return filepath.Join(dir, fileName(key))
}
