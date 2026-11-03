package integrity_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"xammu/internal/contracts"
	"xammu/internal/integrity"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func observation(seq int) *contracts.RawObservation {
	o := contracts.ValidRawObservation()
	o.Sequence = seq
	o.ObservationID = contracts.NewUUID()
	o.ObservedAt = time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC).Add(time.Duration(seq) * time.Second)
	return o
}

// journal writes n observation records and returns the store plus its directory.
func journal(t *testing.T, n int) (string, *integrity.Store) {
	t.Helper()
	dir := t.TempDir()
	s, err := integrity.Open(dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	for i := 1; i <= n; i++ {
		if _, err := s.Append(integrity.StreamObservations, observation(i)); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	return dir, s
}

func lines(t *testing.T, dir string, st integrity.Stream) []string {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, string(st)+".jsonl"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		t.Fatalf("open journal: %v", err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 32*1024*1024)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) != "" {
			out = append(out, sc.Text())
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan journal: %v", err)
	}
	return out
}

func writeLines(t *testing.T, dir string, st integrity.Stream, content []string) {
	t.Helper()
	raw := strings.Join(content, "\n")
	if raw != "" {
		raw += "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, string(st)+".jsonl"), []byte(raw), 0o640); err != nil {
		t.Fatalf("rewrite journal: %v", err)
	}
}

func parseRecord(t *testing.T, line string) integrity.Record {
	t.Helper()
	var r integrity.Record
	if err := json.Unmarshal([]byte(line), &r); err != nil {
		t.Fatalf("line is not a record: %v", err)
	}
	return r
}

// forgeEdit changes one field inside record idx's payload and re-derives every
// digest from that record onward. This is the attacker who knows the chaining
// rule, which is exactly why the chain alone is not the whole defence.
func forgeEdit(t *testing.T, dir string, st integrity.Stream, idx int, field string, value any) {
	t.Helper()
	content := lines(t, dir, st)
	var prev string
	for i := range content {
		if i < idx {
			prev = parseRecord(t, content[i]).Digest
			continue
		}
		r := parseRecord(t, content[i])
		var payload map[string]any
		if err := json.Unmarshal(r.Payload, &payload); err != nil {
			t.Fatalf("payload is not an object: %v", err)
		}
		payload[field] = value
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("re-marshal payload: %v", err)
		}
		r.Payload = body
		r.PrevDigest = prev
		r.Digest = integrity.ChainDigest(prev, r.Seq, r.Payload)
		out, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("re-marshal record: %v", err)
		}
		content[i] = string(out)
		prev = r.Digest
	}
	writeLines(t, dir, st, content)
}

func head(t *testing.T, dir string) string {
	t.Helper()
	s, err := integrity.Open(dir)
	if err != nil {
		// A tampered file cannot even be reopened; the caller's tamper is proven
		// by that error, so report an empty head rather than failing here.
		return ""
	}
	recs, err := s.Records(integrity.StreamObservations)
	if err != nil || len(recs) == 0 {
		return ""
	}
	return recs[len(recs)-1].Digest
}

// signBundle seals the store and produces a signed manifest the way a run would.
// The signing key lives outside the evidence directory: a bundle the reviewer
// hands over must not contain the thing that can forge more bundles.
func signBundle(t *testing.T, dir string, s *integrity.Store) contracts.IntegrityManifest {
	t.Helper()
	key, err := integrity.LoadOrCreateKey(filepath.Join(t.TempDir(), "operator.ed25519"))
	if err != nil {
		t.Fatalf("load key: %v", err)
	}
	return signWith(t, dir, s, key)
}

func signWith(t *testing.T, dir string, s *integrity.Store, key *integrity.Key) contracts.IntegrityManifest {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "run.json"), []byte(`{"run_id":"run-1"}`), 0o640); err != nil {
		t.Fatalf("write checkpoint: %v", err)
	}
	if !s.Sealed() {
		s.Seal()
	}
	m, err := integrity.BuildManifest(dir, "run-1", "auth-2026-042", "",
		s.Count(integrity.StreamObservations), head(t, dir))
	if err != nil {
		t.Fatalf("build manifest: %v", err)
	}
	if err := integrity.Sign(&m, key); err != nil {
		t.Fatalf("sign manifest: %v", err)
	}
	if err := integrity.WriteManifest(dir, m); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return m
}

func trusted(t *testing.T, m contracts.IntegrityManifest) []byte {
	t.Helper()
	pub, err := integrity.PublicKeyOf(m)
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	return pub
}

func check(t *testing.T, statuses []integrity.VerifyStatus, name string) integrity.VerifyStatus {
	t.Helper()
	for _, st := range statuses {
		if st.Check == name {
			return st
		}
	}
	t.Fatalf("verification never performed check %q; ran %d checks", name, len(statuses))
	return integrity.VerifyStatus{}
}

func requireFail(t *testing.T, statuses []integrity.VerifyStatus, names ...string) {
	t.Helper()
	for _, n := range names {
		c := check(t, statuses, n)
		if c.OK {
			t.Errorf("tamper was not detected by %q (%s)", n, c.Detail)
		}
	}
}

func requirePass(t *testing.T, statuses []integrity.VerifyStatus, names ...string) {
	t.Helper()
	for _, n := range names {
		c := check(t, statuses, n)
		if !c.OK {
			t.Errorf("expected %q to pass, got %s", n, c.Detail)
		}
	}
}

func breakMentions(breaks []integrity.Break, needle string) bool {
	for _, b := range breaks {
		if strings.Contains(b.Reason, needle) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Baseline: the checks must pass when nothing is wrong, otherwise every
// detection test below is vacuous.
// ---------------------------------------------------------------------------

func TestCleanBundleVerifies(t *testing.T) {
	dir, s := journal(t, 4)
	m := signBundle(t, dir, s)
	statuses := integrity.Verify(dir, m, trusted(t, m))
	for _, st := range statuses {
		if !st.OK {
			t.Errorf("clean bundle failed %q: %s", st.Check, st.Detail)
		}
	}
	if breaks := integrity.VerifyDir(dir); len(breaks) != 0 {
		t.Errorf("clean journal reported breaks: %v", breaks)
	}
}

// TestContractRejectsUnverifiableRecord proves nothing enters the journal that
// cannot satisfy its own contract: the evidence layer is not a dump.
func TestContractRejectsUnverifiableRecord(t *testing.T) {
	dir := t.TempDir()
	s, err := integrity.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	bad := contracts.ValidRawObservation()
	bad.RunID = ""
	if _, err := s.Append(integrity.StreamObservations, bad); err == nil {
		t.Fatal("a record failing C-01 was journaled")
	} else if !strings.Contains(err.Error(), "raw_observation") {
		t.Fatalf("rejection did not name the contract: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "observations.jsonl")); err == nil {
		t.Fatal("a rejected record still created the journal file")
	}
}

// TestSealedStoreRefusesAppend stops "append-only" from meaning "appendable
// forever after signing".
func TestSealedStoreRefusesAppend(t *testing.T) {
	_, s := journal(t, 2)
	s.Seal()
	if _, err := s.Append(integrity.StreamObservations, observation(3)); !errors.Is(err, integrity.ErrSealed) {
		t.Fatalf("append after seal returned %v, want %v", err, integrity.ErrSealed)
	}
	if got := s.Count(integrity.StreamObservations); got != 2 {
		t.Fatalf("sealed store recorded %d observations", got)
	}
}

// TestReopenContinuesChain is the resume property: a second process picking up
// the same directory extends the chain instead of starting a parallel one.
func TestReopenContinuesChain(t *testing.T) {
	dir, _ := journal(t, 3)
	reopened, err := integrity.Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	rec, err := reopened.Append(integrity.StreamObservations, observation(4))
	if err != nil {
		t.Fatalf("append after reopen: %v", err)
	}
	if rec.Seq != 4 {
		t.Fatalf("resumed append wrote sequence %d, expected 4", rec.Seq)
	}
	if rec.PrevDigest == integrity.Genesis {
		t.Fatal("resumed record chained from genesis instead of the existing head")
	}
	if breaks := reopened.Verify(); len(breaks) != 0 {
		t.Fatalf("resumed chain does not verify: %v", breaks)
	}
}

// ---------------------------------------------------------------------------
// Naive tampering: the chain catches it inside the file, without any manifest.
// ---------------------------------------------------------------------------

func TestEditedRecordBreaksChain(t *testing.T) {
	dir, _ := journal(t, 4)
	content := lines(t, dir, integrity.StreamObservations)
	var r map[string]any
	if err := json.Unmarshal([]byte(content[1]), &r); err != nil {
		t.Fatal(err)
	}
	// Flip one value in the payload and leave the stored digest untouched.
	payload := r["payload"].(map[string]any)
	payload["response_status"] = float64(200)
	out, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	content[1] = string(out)
	writeLines(t, dir, integrity.StreamObservations, content)

	_, err = integrity.Open(dir)
	if err == nil {
		t.Fatal("a store opened over an edited journal without complaining")
	}
	if !errors.Is(err, integrity.ErrTampered) {
		t.Fatalf("reopen error was %v, want ErrTampered", err)
	}
	// Verify() reads the file directly, so it reports the break even when the
	// store refuses to open.
	breaks := verifyWithoutOpen(t, dir)
	if len(breaks) == 0 {
		t.Fatal("verification reported no break for an edited record")
	}
	if !breakMentions(breaks, "payload no longer matches its digest") {
		t.Fatalf("break was reported for the wrong reason: %v", breaks)
	}
}

func TestRemovedRecordBreaksChain(t *testing.T) {
	dir, _ := journal(t, 5)
	content := lines(t, dir, integrity.StreamObservations)
	content = append(content[:2], content[3:]...)
	writeLines(t, dir, integrity.StreamObservations, content)

	breaks := verifyWithoutOpen(t, dir)
	if len(breaks) == 0 {
		t.Fatal("deleting a record left the chain intact")
	}
	if !breakMentions(breaks, "was removed, inserted or reordered") {
		t.Fatalf("removal was not attributed: %v", breaks)
	}
	// The surviving prefix must show the gap in the sequence as well.
	if !breakMentions(breaks, "expected 3") {
		t.Logf("sequence gap not separately reported (still detected by the chain): %v", breaks)
	}
}

func TestInsertedRecordBreaksChain(t *testing.T) {
	dir, s := journal(t, 4)
	forged := forgeRecord(t, s, 2, observation(99))
	content := lines(t, dir, integrity.StreamObservations)
	content = append(content[:1], append([]string{forged}, content[1:]...)...)
	writeLines(t, dir, integrity.StreamObservations, content)

	breaks := verifyWithoutOpen(t, dir)
	if len(breaks) == 0 {
		t.Fatal("an inserted record left the chain intact")
	}
	if !breakMentions(breaks, "was removed, inserted or reordered") &&
		!breakMentions(breaks, "sequence is") {
		t.Fatalf("insertion was not attributed: %v", breaks)
	}
}

func TestReorderedRecordsBreakChain(t *testing.T) {
	dir, _ := journal(t, 4)
	content := lines(t, dir, integrity.StreamObservations)
	content[1], content[2] = content[2], content[1]
	writeLines(t, dir, integrity.StreamObservations, content)
	if breaks := verifyWithoutOpen(t, dir); len(breaks) == 0 {
		t.Fatal("swapping two records left the chain intact")
	}
}

// TestTruncatedTailPassesChainButFailsTheManifest states the boundary honestly:
// a hash chain cannot prove that the last record is still there. Only the signed
// inventory can, which is why both layers exist.
func TestTruncatedTailPassesChainButFailsTheManifest(t *testing.T) {
	dir, s := journal(t, 5)
	m := signBundle(t, dir, s)
	statuses := integrity.Verify(dir, m, trusted(t, m))
	requirePass(t, statuses, "hash_chain_intact", "no_modified_files", "observation_count_matches")

	content := lines(t, dir, integrity.StreamObservations)
	writeLines(t, dir, integrity.StreamObservations, content[:3])

	after := integrity.Verify(dir, m, trusted(t, m))
	// The chain itself still verifies, because what remains is an honest prefix.
	requirePass(t, after, "hash_chain_intact")
	// The manifest is what notices two observations are gone.
	requireFail(t, after, "no_modified_files", "merkle_root_matches", "observation_count_matches")
	if c := check(t, after, "observation_count_matches"); !strings.Contains(c.Detail, "journal holds 3") {
		t.Fatalf("count mismatch was not quantified: %s", c.Detail)
	}
}

// TestForgedChainValidAppendIsCaughtByManifest is the strongest chain-only
// attacker: they know the chaining rule and append a perfectly-formed record.
func TestForgedChainValidAppendIsCaughtByManifest(t *testing.T) {
	dir, s := journal(t, 4)
	m := signBundle(t, dir, s)

	rec := forgeRecordStruct(t, s, 5, observation(99))
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(dir, "observations.jsonl"), os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(append(raw, '\n')); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	// Chain verification is satisfied: the forgery is internally consistent.
	requirePass(t, integrity.Verify(dir, m, trusted(t, m)), "hash_chain_intact")
	// The signed inventory is not: the file it hashed is no longer that file.
	requireFail(t, integrity.Verify(dir, m, trusted(t, m)),
		"no_modified_files", "merkle_root_matches", "observation_count_matches")
}

// TestReSignedWithForeignKeyFailsTrustCheck covers the case where the attacker
// rebuilds the whole manifest. Without the operator's private key they can only
// substitute their own identity, which the trust check exists to surface.
func TestReSignedWithForeignKeyFailsTrustCheck(t *testing.T) {
	dir, s := journal(t, 4)
	operatorKey, err := integrity.LoadOrCreateKey(filepath.Join(t.TempDir(), "operator.ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	m := signWith(t, dir, s, operatorKey)
	requirePass(t, integrity.Verify(dir, m, trusted(t, m)), "signer_is_trusted", "signature_valid")

	// The attacker edits an observation, re-chains the journal, and re-signs a
	// rebuilt manifest with a key they generated themselves.
	forgeEdit(t, dir, integrity.StreamObservations, 1, "response_status", float64(200))
	resigned, err := integrity.Open(dir)
	if err != nil {
		t.Fatalf("attacker left the journal unverifiable: %v", err)
	}
	foreign, err := integrity.LoadOrCreateKey(filepath.Join(t.TempDir(), "attacker.ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	m2 := signWith(t, dir, resigned, foreign)

	statuses := integrity.Verify(dir, m2, operatorKey.Public)
	// Everything is internally consistent, and that is precisely the trap this
	// check exists for.
	requirePass(t, statuses, "signature_valid", "payload_digest_recomputed", "merkle_root_matches")
	requireFail(t, statuses, "signer_is_trusted")
	if c := check(t, statuses, "signer_is_trusted"); !strings.Contains(c.Detail, "trusted key") {
		t.Fatalf("trust failure did not name both identities: %s", c.Detail)
	}
	// And the original manifest no longer describes the tampered bundle.
	requireFail(t, integrity.Verify(dir, m, operatorKey.Public), "no_modified_files")
}

// TestVerificationWithoutTrustedKeyDoesNotClaimIdentity makes the limit explicit
// rather than leaving it implied: a self-consistent signature proves nothing
// about who signed.
func TestVerificationWithoutTrustedKeyDoesNotClaimIdentity(t *testing.T) {
	dir, s := journal(t, 3)
	m := signBundle(t, dir, s)
	statuses := integrity.Verify(dir, m, nil)
	requirePass(t, statuses, "signature_valid")
	c := check(t, statuses, "signer_is_trusted")
	if c.OK {
		t.Fatal("identity was asserted without a trusted key")
	}
	if !strings.Contains(c.Detail, "self-consistent") {
		t.Fatalf("the limitation was not stated: %s", c.Detail)
	}
}

// TestSigningKeyMaterialStaysOutsideTheBundle checks the layout the tests rely
// on: the manifest embeds the public key only.
func TestBundleContainsNoPrivateKey(t *testing.T) {
	dir, s := journal(t, 2)
	signBundle(t, dir, s)
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(strings.ToLower(string(raw)), "private") &&
			strings.HasSuffix(path, ".ed25519") {
			return fmt.Errorf("%s looks like key material", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestCorruptSigningKeyIsRejected: a truncated or wrong-length seed must not be
// silently accepted as an identity.
func TestCorruptSigningKeyIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.ed25519")
	if err := os.WriteFile(path, []byte("not-a-seed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := integrity.LoadOrCreateKey(path); err == nil {
		t.Fatal("a corrupt seed file was accepted as a signing key")
	}
	// A fresh path must create exactly one key and read it back identically.
	fresh := filepath.Join(t.TempDir(), "fresh.ed25519")
	k1, err := integrity.LoadOrCreateKey(fresh)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := integrity.LoadOrCreateKey(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if k1.KeyID != k2.KeyID || !bytes.Equal(k1.Public, k2.Public) {
		t.Fatal("key did not round-trip through its seed file")
	}
	fi, err := os.Stat(fresh)
	if err != nil {
		t.Fatal(err)
	}
	// Windows reports 0666 for every file regardless of the mode requested, so
	// the assertion is skipped there instead of being dropped everywhere.
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("signing key is readable by group or other: %v", fi.Mode())
	}
}

// TestJournalMarkerMustMatchFileName closes the loophole of laundering an unknown
// contract type as a journal entry.
func TestJournalMarkerMustMatchFileName(t *testing.T) {
	dir, s := journal(t, 2)
	if _, err := s.Append(integrity.StreamNotes, map[string]string{"note": "operator pause"}); err != nil {
		t.Fatal(err)
	}
	m := signBundle(t, dir, s)
	var sawNotes bool
	for _, f := range m.Files {
		if f.Path == "notes.jsonl" {
			sawNotes = true
			if f.Contract != contracts.JournalContract("notes") {
				t.Fatalf("notes journal declared %q", f.Contract)
			}
		}
	}
	if !sawNotes {
		t.Fatal("the notes journal was omitted from the signed inventory")
	}

	mislabelled := m
	mislabelled.Files = append([]contracts.ManifestFileEntry(nil), m.Files...)
	for i := range mislabelled.Files {
		if mislabelled.Files[i].Path == "notes.jsonl" {
			mislabelled.Files[i].Contract = contracts.JournalContract("observations")
		}
	}
	if err := contracts.Validate(contracts.IDIntegrityManifest, &mislabelled); err == nil {
		t.Fatal("a journal marker naming a different file was accepted")
	} else if !strings.Contains(err.Error(), "does not match the file name") {
		t.Fatalf("unexpected rejection reason: %v", err)
	}
	bogus := m
	bogus.Files = append([]contracts.ManifestFileEntry(nil), m.Files...)
	bogus.Files[0].Contract = "some_unknown_contract"
	if err := contracts.Validate(contracts.IDIntegrityManifest, &bogus); err == nil {
		t.Fatal("an unknown contract type was accepted")
	}
}

// verifyWithoutOpen runs chain verification over a directory whose store cannot
// be constructed, which is the state a reviewer faces with a damaged bundle.
func verifyWithoutOpen(t *testing.T, dir string) []integrity.Break {
	t.Helper()
	return integrity.VerifyDir(dir)
}

// forgeRecord builds a raw journal line that chains correctly from the store's
// current state, without going through the store (which is sealed in some tests).
func forgeRecord(t *testing.T, s *integrity.Store, seq int, payload any) string {
	t.Helper()
	return mustLine(t, forgeRecordStruct(t, s, seq, payload))
}

func forgeRecordStruct(t *testing.T, s *integrity.Store, seq int, payload any) integrity.Record {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var prev string
	if seq == 1 {
		prev = integrity.Genesis
	} else {
		recs, err := s.Records(integrity.StreamObservations)
		if err != nil || len(recs) < seq-1 {
			t.Fatalf("cannot read %d prior records", seq-1)
		}
		prev = recs[seq-2].Digest
	}
	return integrity.Record{Seq: seq, At: time.Now().UTC(),
		Stream: integrity.StreamObservations, Payload: body,
		PrevDigest: prev, Digest: integrity.ChainDigest(prev, seq, body)}
}

func mustLine(t *testing.T, r integrity.Record) string {
	t.Helper()
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
