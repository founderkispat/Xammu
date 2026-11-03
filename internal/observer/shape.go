package observer

import (
	"strings"

	"xammu/internal/contracts"
)

// ScanWindow bounds how far into a response body the detectors look. The client
// caps what it reads; scanning all of it would let one large page dominate the
// run's cost. A marker past the window is missed, which can only under-report a
// block and never invent one.
const ScanWindow = 256 << 10

// Shape is the entire input a response detector may read: the status line and the
// body bytes. It deliberately declares no headers.
//
// A filtering product can name itself in a response header, and a test lab can do
// the same to make its intent obvious. Scoring either would read the answer key
// instead of the response, and the resulting signal would only restate what
// somebody already said. So the type cannot carry a header, and a detector that
// wanted one would have to change this signature to get it.
type Shape struct {
	Status    int
	Body      []byte
	BodyBytes int
}

// ShapeOf builds a shape from a status and a body.
func ShapeOf(status int, body []byte) Shape {
	return Shape{Status: status, Body: body, BodyBytes: len(body)}
}

// ShapeFromJournal rebuilds the comparable part of a shape from a stored C-01
// record. The body is not there, because retention policy said it must not be, so
// anything that claims to compare responses after the fact may only use the status
// line and the length.
//
// That is not a concession. A contrast that needed the bytes could only be
// recomputed by a stage that kept them, and a run authorized for digest-only
// retention would then be classified by a different measurement than a run that
// kept prefixes.
func ShapeFromJournal(obs contracts.RawObservation) Shape {
	return Shape{Status: obs.ResponseStatus, BodyBytes: obs.ResponseBodyBytes}
}

// lower returns the scanned prefix of the body, case-folded. Detectors match
// case-insensitively because an interstitial page is written for a human reader,
// and humans do not agree on capitalisation.
func (s Shape) lower() string {
	n := s.BodyBytes
	if len(s.Body) < n {
		n = len(s.Body)
	}
	if n > ScanWindow {
		n = ScanWindow
	}
	return strings.ToLower(string(s.Body[:n]))
}

// Category is the status band the response arrived in.
func (s Shape) Category() string { return contracts.StatusCategory(s.Status) }

// SizeBucket groups body lengths by order of magnitude.
func (s Shape) SizeBucket() string {
	switch n := s.BodyBytes; {
	case n == 0:
		return "b0"
	case n <= 64:
		return "b1_64"
	case n <= 512:
		return "b65_512"
	case n <= 4096:
		return "b513_4k"
	case n <= 65536:
		return "b5k_64k"
	default:
		return "big"
	}
}

// Key is the coarse signature a reference contrast compares. Two responses share a
// key when they are in the same status band and the same size bucket.
//
// The bucket is deliberately coarse: a probe differs from a benign reference by the
// payload it carries, and a signature comparison that noticed thirty extra
// characters would report every probe as a divergence from ordinary handling. The
// content shape -- HTML where a JSON answer was expected -- is asserted by the
// envelope detector instead, as a reading with its own evidence, rather than being
// folded silently into a comparison key.
func (s Shape) Key() string { return s.Category() + "|" + s.SizeBucket() }
