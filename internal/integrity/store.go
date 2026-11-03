// Package integrity is the evidence layer: an append-only journal, a per-stream
// hash chain, and an Ed25519-signed manifest. It exists so that a reviewer can
// distinguish "XAMMU recorded this" from "XAMMU claims this", and so that
// removing a record is an event that leaves a trace instead of a silent edit.
//
// There is no database. Every artifact is a file a human can read with cat and
// verify with a checksum.
package integrity

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"xammu/internal/contracts"
)

// Stream names one journal. The set is fixed so a missing stream is visible as
// an absence rather than as an optional file someone forgot to write.
type Stream string

const (
	StreamObservations    Stream = "observations"
	StreamCaptures        Stream = "captures"
	StreamAnalyses        Stream = "analyses"
	StreamClassifications Stream = "classifications"
	StreamAttributions    Stream = "attributions"
	StreamStatuses        Stream = "status_records"
	StreamEvidence        Stream = "evidence_profiles"
	StreamHypotheses      Stream = "hypotheses"
	StreamProfiles        Stream = "run_profiles"
	StreamTransitions     Stream = "transitions"
	StreamFindings        Stream = "findings"
	StreamRefusals        Stream = "refusals"
	StreamPlan            Stream = "plan"
	StreamNotes           Stream = "notes"
)

// AllStreams lists the journal names a complete run must be able to produce.
func AllStreams() []Stream {
	return []Stream{StreamObservations, StreamCaptures, StreamAnalyses,
		StreamClassifications, StreamAttributions, StreamStatuses, StreamEvidence,
		StreamHypotheses, StreamProfiles,
		StreamTransitions, StreamFindings, StreamRefusals, StreamPlan, StreamNotes}
}

// StreamContract maps a journal to the contract its records must satisfy. A
// stream with no entry here accepts any payload; every evidence-bearing stream
// is listed, so a record that fails its own contract cannot enter the journal.
//
// The C-02, C-03 and C-08 streams are here because a later stage must be able to
// re-derive a reading without the original process: a classification that cites an
// analysis nobody journaled can only be trusted by asking the classifier to agree
// again, and a hypothesis that cites an absent evidence profile is a dangling
// reference in the middle of the evidence trail.
var StreamContract = map[Stream]contracts.ID{
	StreamObservations:    contracts.IDRawObservation,
	StreamCaptures:        contracts.IDTransientCapture,
	StreamAnalyses:        contracts.IDSignatureAnalysis,
	StreamClassifications: contracts.IDBehavioralClassification,
	StreamAttributions:    contracts.IDAttribution,
	StreamStatuses:        contracts.IDAttributionStatus,
	StreamEvidence:        contracts.IDEvidenceProfile,
	StreamHypotheses:      contracts.IDHypothesis,
	StreamProfiles:        contracts.IDRunProfile,
	StreamFindings:        contracts.IDDiscoveryFinding,
}

// ErrSealed means the journal was closed for writing; appending afterwards is
// refused rather than silently reopening an evidence trail.
var ErrSealed = errors.New("journal is sealed")

// ErrTampered reports a chain break. It carries no detail because the detail
// belongs in the returned error text, not in a boolean.
var ErrTampered = errors.New("hash chain verification failed")

// Record is one journal line as stored.
type Record struct {
	Seq        int             `json:"seq"`
	At         time.Time       `json:"at"`
	Stream     Stream          `json:"stream"`
	Payload    json.RawMessage `json:"payload"`
	PrevDigest string          `json:"prev_digest"`
	Digest     string          `json:"digest"`
}

// ChainMaterial is the exact byte sequence a record's digest commits to. It is
// exported because verification is only auditable if the rule is written down
// once instead of being implied by two implementations.
func ChainMaterial(prev string, seq int, payload []byte) []byte {
	buf := make([]byte, 0, len(prev)+12+len(payload))
	buf = append(buf, prev...)
	buf = append(buf, '|')
	buf = append(buf, strconv.Itoa(seq)...)
	buf = append(buf, '|')
	return append(buf, payload...)
}

// ChainDigest is the SHA-256 of the chain material in the canonical transport
// form, so a chain pointer and a contract digest field are the same kind of
// string and cannot be quietly swapped.
func ChainDigest(prev string, seq int, payload []byte) string {
	return contracts.NewDigest(ChainMaterial(prev, seq, payload))
}

// Genesis is the digest every stream's first record chains from. It is a fixed
// literal, not an empty string, so "the file was truncated to nothing" and "the
// file never started" are different verifiable states.
const Genesis = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

type streamState struct {
	mu   sync.Mutex
	seq  int
	prev string
}

// Store is one run's directory of append-only journals.
type Store struct {
	dir     string
	mu      sync.Mutex
	streams map[Stream]*streamState
	sealed  bool
}

// Open prepares a store directory. Existing journals are replayed so a resumed
// run continues the chain instead of starting a second one.
func Open(dir string) (*Store, error) {
	if dir == "" {
		return nil, errors.New("integrity: empty store directory")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("integrity: cannot create store: %w", err)
	}
	s := &Store{dir: dir, streams: map[Stream]*streamState{}}
	for _, st := range AllStreams() {
		last, seq, err := s.tail(st)
		if err != nil {
			return nil, err
		}
		s.streams[st] = &streamState{seq: seq, prev: last}
	}
	return s, nil
}

// Dir returns the root the journals live in.
func (s *Store) Dir() string { return s.dir }

func (s *Store) path(st Stream) string {
	return filepath.Join(s.dir, string(st)+".jsonl")
}

// tail reads the last record of a stream and returns its digest and sequence.
func (s *Store) tail(st Stream) (string, int, error) {
	f, err := os.Open(s.path(st))
	if errors.Is(err, os.ErrNotExist) {
		return Genesis, 0, nil
	}
	if err != nil {
		return "", 0, fmt.Errorf("integrity: cannot read journal %s: %w", st, err)
	}
	defer f.Close()

	var last Record
	count := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 32*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		var r Record
		if err := json.Unmarshal(line, &r); err != nil {
			return "", 0, fmt.Errorf("%w: journal %s line %d is not a record: %v",
				ErrTampered, st, count+1, err)
		}
		if r.Digest != ChainDigest(r.PrevDigest, r.Seq, r.Payload) {
			return "", 0, fmt.Errorf("%w: journal %s line %d digest mismatch", ErrTampered, st, count+1)
		}
		last = r
		count++
	}
	if err := sc.Err(); err != nil {
		return "", 0, fmt.Errorf("integrity: failed reading journal %s: %w", st, err)
	}
	if count == 0 {
		return Genesis, 0, nil
	}
	return last.Digest, last.Seq, nil
}

// Append validates the payload against its contract, then writes exactly one
// line. Nothing is ever rewritten: the file is opened O_APPEND and the record
// commits to its predecessor's digest.
func (s *Store) Append(st Stream, payload any) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sealed {
		return Record{}, ErrSealed
	}
	if id, ok := StreamContract[st]; ok {
		if err := contracts.Validate(id, payload); err != nil {
			return Record{}, fmt.Errorf("integrity: record rejected by %s before journaling: %w", id, err)
		}
	}
	body, err := canonicalJSON(payload)
	if err != nil {
		return Record{}, err
	}
	state := s.streams[st]
	if state == nil {
		state = &streamState{prev: Genesis}
		s.streams[st] = state
	}
	state.mu.Lock()
	defer state.mu.Unlock()

	rec := Record{
		Seq:        state.seq + 1,
		At:         time.Now().UTC(),
		Stream:     st,
		Payload:    body,
		PrevDigest: state.prev,
	}
	rec.Digest = ChainDigest(rec.PrevDigest, rec.Seq, rec.Payload)
	line, err := canonicalJSON(rec)
	if err != nil {
		return Record{}, err
	}
	f, err := os.OpenFile(s.path(st), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return Record{}, fmt.Errorf("integrity: cannot open journal %s: %w", st, err)
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return Record{}, fmt.Errorf("integrity: cannot append to %s: %w", st, err)
	}
	if err := f.Sync(); err != nil {
		return Record{}, fmt.Errorf("integrity: cannot flush %s: %w", st, err)
	}
	state.seq = rec.Seq
	state.prev = rec.Digest
	return rec, nil
}

// AppendNote journals a free-text operator note. Notes are the only unvalidated
// stream because they carry no claims; they still join the chain, so a note
// cannot be inserted after the fact without breaking verification.
func (s *Store) AppendNote(text string) (Record, error) {
	return s.Append(StreamNotes, map[string]string{"note": text})
}

func canonicalJSON(v any) ([]byte, error) {
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("integrity: cannot encode record: %w", err)
	}
	return []byte(strings.TrimSuffix(buf.String(), "\n")), nil
}

// Break is one concrete verification failure, located so an operator can see
// which journal and which line stopped being trustworthy.
type Break struct {
	Stream Stream
	Line   int
	Reason string
}

func (b Break) String() string {
	return fmt.Sprintf("%s.jsonl line %d: %s", b.Stream, b.Line, b.Reason)
}

// Verify walks every journal and re-derives the chain. It reports each break it
// finds; an empty result means every line still commits to its predecessor.
func (s *Store) Verify() []Break {
	var breaks []Break
	for _, st := range AllStreams() {
		breaks = append(breaks, s.verifyStream(st)...)
	}
	return breaks
}

// VerifyDir checks the chains of a directory without holding a Store. A reviewer
// with a damaged bundle cannot construct a Store at all -- opening replays the
// journal and refuses a broken chain -- so verification has to work from the raw
// files.
func VerifyDir(root string) []Break {
	out := []Break{}
	for _, st := range AllStreams() {
		out = append(out, verifyFile(filepath.Join(root, string(st)+".jsonl"), st)...)
	}
	return out
}

func (s *Store) verifyStream(st Stream) []Break {
	return verifyFile(s.path(st), st)
}

func verifyFile(path string, st Stream) []Break {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return []Break{{Stream: st, Line: 0, Reason: "journal unreadable: " + err.Error()}}
	}
	defer f.Close()

	var breaks []Break
	prev := Genesis
	expectedSeq := 1
	lineNo := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 32*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		lineNo++
		var r Record
		if err := json.Unmarshal(line, &r); err != nil {
			breaks = append(breaks, Break{Stream: st, Line: lineNo, Reason: "not a record: " + err.Error()})
			continue
		}
		if r.Seq != expectedSeq {
			breaks = append(breaks, Break{Stream: st, Line: lineNo,
				Reason: fmt.Sprintf("sequence is %d, expected %d", r.Seq, expectedSeq)})
		}
		if r.PrevDigest != prev {
			breaks = append(breaks, Break{Stream: st, Line: lineNo,
				Reason: "chains from " + short(r.PrevDigest) + ", previous record is " + short(prev) +
					" (a record was removed, inserted or reordered)"})
		}
		if r.Digest != ChainDigest(r.PrevDigest, r.Seq, r.Payload) {
			breaks = append(breaks, Break{Stream: st, Line: lineNo,
				Reason: "payload no longer matches its digest (the record was edited)"})
		}
		prev = r.Digest
		expectedSeq = r.Seq + 1
	}
	if err := sc.Err(); err != nil {
		breaks = append(breaks, Break{Stream: st, Line: lineNo, Reason: "read failed: " + err.Error()})
	}
	return breaks
}

// Head returns the digest of a stream's newest record, or Genesis when the
// stream is empty. The run's resume token commits to it, so a checkpoint cannot
// be re-attached to a different or shorter journal.
func (s *Store) Head(st Stream) string {
	state := s.streams[st]
	if state == nil {
		return Genesis
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.prev == "" {
		return Genesis
	}
	return state.prev
}

// Count reports how many records a stream holds, for the manifest's
// observation_count check.
func (s *Store) Count(st Stream) int {
	state := s.streams[st]
	if state == nil {
		return 0
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.seq
}

// Records returns every record of a stream in journal order.
func (s *Store) Records(st Stream) ([]Record, error) {
	f, err := os.Open(s.path(st))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 32*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		var r Record
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, fmt.Errorf("%w: journal %s: %v", ErrTampered, st, err)
		}
		out = append(out, r)
	}
	return out, sc.Err()
}

// Seal freezes the store for writing. The manifest is produced after sealing, so
// a signed evidence trail cannot grow afterwards.
func (s *Store) Seal() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sealed = true
}

// Sealed reports whether the store still accepts appends.
func (s *Store) Sealed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sealed
}

func short(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}
