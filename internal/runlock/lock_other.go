//go:build !unix && !windows

package runlock

// A platform without a portable exclusive-open primitive gets no silent
// degradation: Acquire returns ErrUnsupported and the live-run commands refuse
// to start, because proceeding would defeat the coordination they exist for.
type platformLock struct{}

func acquirePlatform(string) (*platformLock, error) {
	return nil, ErrUnsupported
}

func (*platformLock) release() error { return nil }
