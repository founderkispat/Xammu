package runlock

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

const (
	helperEnv = "XAMMU_RUNLOCK_HELPER"
	helperDir = "XAMMU_RUNLOCK_DIR"
	helperKey = "XAMMU_RUNLOCK_KEY"

	helperAcquired = 0
	helperBusy     = 3
)

func TestSecondAcquireIsBusyAndReleaseFreesIt(t *testing.T) {
	dir := t.TempDir()
	key := "AUTH-1\x00http://127.0.0.1:8080"

	first, err := Acquire(dir, key)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if _, err := Acquire(dir, key); !errors.Is(err, ErrBusy) {
		t.Fatalf("a second acquire must be busy, got %v", err)
	}
	if err := first.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	second, err := Acquire(dir, key)
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	if err := second.Release(); err != nil {
		t.Fatalf("second release: %v", err)
	}
}

func TestDifferentKeysDoNotBlockEachOther(t *testing.T) {
	dir := t.TempDir()
	a, err := Acquire(dir, "AUTH-1\x00http://127.0.0.1:8080")
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	defer a.Release()
	b, err := Acquire(dir, "AUTH-1\x00http://127.0.0.1:8081")
	if err != nil {
		t.Fatalf("a different origin must not be blocked: %v", err)
	}
	defer b.Release()
}

func TestReleaseIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	l, err := Acquire(dir, "AUTH-1")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if err := l.Release(); err != nil {
		t.Fatalf("first release: %v", err)
	}
	if err := l.Release(); err != nil {
		t.Fatalf("second release must be a no-op, got %v", err)
	}
	var nilLock *Lock
	if err := nilLock.Release(); err != nil {
		t.Fatalf("releasing a nil lock must be a no-op, got %v", err)
	}
}

func TestLockFileNameIsStableAndOpaque(t *testing.T) {
	dir := t.TempDir()
	l, err := Acquire(dir, "AUTH-1\x00http://127.0.0.1:8080")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer l.Release()
	if fileName("AUTH-1\x00http://127.0.0.1:8080") != fileName("AUTH-1\x00http://127.0.0.1:8080") {
		t.Fatal("the same key must name the same lock file")
	}
	if l.Path() == "" {
		t.Fatal("the lock must expose its path")
	}
	if strings.Contains(l.Path(), "AUTH-1") {
		t.Fatalf("the lock path must not leak the authorization reference: %s", l.Path())
	}
}

func TestLockFileIsOwnerOnlyOnUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows ACLs do not expose the POSIX mode this test asserts")
	}
	dir := t.TempDir()
	l, err := Acquire(dir, "AUTH-1")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer l.Release()
	info, err := os.Stat(l.Path())
	if err != nil {
		t.Fatalf("stat lock: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("lock file mode is %o, want 600", mode)
	}
}

// TestCrossProcessExclusion re-executes this test binary so the second holder is
// a real second process, not a second descriptor in the same one. That is the
// property the live-run commands rely on.
func TestCrossProcessExclusion(t *testing.T) {
	if runtime.GOOS != "windows" && runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("no cross-process lock primitive on this platform")
	}
	dir := t.TempDir()
	key := "AUTH-1|http://127.0.0.1:8080"

	held, err := Acquire(dir, key)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	t.Cleanup(func() { _ = held.Release() })
	if code := runHelper(t, dir, key); code != helperBusy {
		t.Fatalf("a second process must be refused with %d, got %d", helperBusy, code)
	}
	if err := held.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	if code := runHelper(t, dir, key); code != helperAcquired {
		t.Fatalf("after release the second process must acquire, got %d", code)
	}
}

func runHelper(t *testing.T, dir, key string) int {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestRunLockHelperProcess$")
	cmd.Env = append(os.Environ(), helperEnv+"=1", helperDir+"="+dir, helperKey+"="+key)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return helperAcquired
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode()
	}
	t.Fatalf("cannot run the helper process: %v\n%s", err, out)
	return -1
}

func TestRunLockHelperProcess(t *testing.T) {
	if os.Getenv(helperEnv) != "1" {
		return
	}
	l, err := Acquire(os.Getenv(helperDir), os.Getenv(helperKey))
	if errors.Is(err, ErrBusy) {
		os.Exit(helperBusy)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(4)
	}
	if err := l.Release(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(5)
	}
	os.Exit(0)
}
