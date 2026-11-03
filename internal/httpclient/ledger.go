package httpclient

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Ledger owns the two things that bound an authorized run: how many requests may
// still leave, and whether the client is still allowed to move at all. Budget and
// halt are checked together because either one alone is a way to keep sending.
type Ledger struct {
	mu         sync.Mutex
	max        int
	used       int
	seq        int
	halted     bool
	haltReason string
	haltAt     time.Time
	attempts   int
	sent       int
	refused    int
}

// NewLedger starts a budget of max requests.
func NewLedger(max int) *Ledger {
	return &Ledger{max: max}
}

// Reserve consumes one unit of budget. A refusal is not charged: the caller has
// to know that nothing reached the target.
func (l *Ledger) Reserve() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.attempts++
	if l.halted {
		l.refused++
		return ErrHalted
	}
	if l.used >= l.max {
		l.refused++
		return ErrBudgetExhausted
	}
	l.used++
	l.seq++
	l.sent++
	return nil
}

// Release returns a reservation when the request never left the process, so that
// a locally refused attempt does not eat budget.
func (l *Ledger) Release() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.used > 0 {
		l.used--
		l.sent--
		l.refused++
	}
}

// Restore seeds the counters of a resumed run. The authorized budget is a total,
// not a per-process allowance, so a run that has already spent 480 of 500 requests
// resumes with 20 left -- otherwise restarting the tool would silently buy more
// traffic than the operator approved.
func (l *Ledger) Restore(used int) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if used < l.used {
		return fmt.Errorf("ledger: cannot restore budget below the %d requests already charged", l.used)
	}
	if used > l.max {
		return fmt.Errorf("ledger: restored usage %d exceeds the authorized budget %d", used, l.max)
	}
	l.used = used
	l.sent = used
	l.seq = used
	return nil
}

// Halt stops the client. Nothing after this point may dial.
func (l *Ledger) Halt(reason string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.halted {
		l.halted = true
		l.haltReason = reason
		l.haltAt = time.Now().UTC()
	}
}

// Halted reports the stop state and its reason.
func (l *Ledger) Halted() (bool, string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.halted, l.haltReason
}

// Used reports consumed budget.
func (l *Ledger) Used() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.used
}

// Remaining reports budget left.
func (l *Ledger) Remaining() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.max-l.used <= 0 {
		return 0
	}
	return l.max - l.used
}

// Stats reports the tallies the report needs to separate sent, refused and
// attempted work.
func (l *Ledger) Stats() (attempts, sent, refused int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.attempts, l.sent, l.refused
}

// NextSequence numbers outgoing requests so observations can be ordered.
func (l *Ledger) NextSequence() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.seq
}

// Limiter paces requests at the authorized rate. It is a minimum interval
// rather than a burst bucket: a burst is exactly what a rate limit is meant to
// prevent.
type Limiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

// NewLimiter builds a pacer from a per-second rate.
func NewLimiter(ratePerSecond int) *Limiter {
	if ratePerSecond <= 0 {
		ratePerSecond = 1
	}
	return &Limiter{interval: time.Second / time.Duration(ratePerSecond)}
}

// Wait blocks until the next slot opens or the context ends.
func (l *Limiter) Wait(ctx context.Context) error {
	l.mu.Lock()
	now := time.Now()
	wait := time.Duration(0)
	if l.next.After(now) {
		wait = l.next.Sub(now)
	}
	l.next = now.Add(wait + l.interval)
	l.mu.Unlock()
	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
