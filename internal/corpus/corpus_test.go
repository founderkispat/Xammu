package corpus_test

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"xammu/internal/contracts"
	"xammu/internal/corpus"
)

var stamp = time.Date(2026, time.October, 28, 0, 0, 0, 0, time.UTC)

func shipped(t *testing.T) *corpus.Set {
	t.Helper()
	set, err := corpus.Load(filepath.Join("..", "..", "corpus"), corpus.DefaultPolicy())
	if err != nil {
		t.Fatalf("the shipped corpus must load: %v", err)
	}
	return set
}

// ---------------------------------------------------------------- shipped tree

func TestShippedCorpusIsCertifiable(t *testing.T) {
	set := shipped(t)

	dev := set.Items(contracts.PartitionDevelopment)
	cal := set.Items(contracts.PartitionCalibration)
	ind := set.Items(contracts.PartitionIndependent)
	if len(dev) < 20 || len(cal) < 8 || len(ind) < 5 {
		t.Fatalf("the shipped corpus is too small to cover the matrix it claims: development %d, "+
			"calibration %d, independent %d", len(dev), len(cal), len(ind))
	}
	for _, item := range append(append(append([]contracts.CorpusItem{}, dev...), cal...), ind...) {
		if item.Inertness.Verdict != contracts.InertVerified {
			t.Errorf("ref %s was loaded with verdict %q: the gate refuses a probe it cannot certify, so a "+
				"non-verified record here means the gate was bypassed", item.Ref, item.Inertness.Verdict)
		}
		if item.Inertness.GateVersion != corpus.GateVersion {
			t.Errorf("ref %s is stamped with gate %q, not the running %q", item.Ref,
				item.Inertness.GateVersion, corpus.GateVersion)
		}
	}
	if err := set.EvidenceCheck(); err != nil {
		t.Errorf("every validation entry must name a classifiable artifact: %v", err)
	}
	if err := set.Usable(); err != nil {
		t.Errorf("the shipped corpus must be leak-free to be usable at all: %v", err)
	}

	partitions, err := set.BuildPartitions("corpus@"+corpus.GateVersion, stamp)
	if err != nil {
		t.Fatalf("build C-14 records: %v", err)
	}
	if len(partitions) != 3 {
		t.Fatalf("got %d partitions, want 3", len(partitions))
	}
	for _, p := range partitions {
		if err := contracts.Validate(contracts.IDCorpusPartition, p); err != nil {
			t.Errorf("partition %s: %v", p.Name, err)
		}
		if p.LeakageVerdict != "clean" {
			t.Errorf("partition %s reports %q: a shipped corpus that leaks cannot validate anything",
				p.Name, p.LeakageVerdict)
		}
		if len(p.MemberRefs) != len(set.Items(p.Name)) {
			t.Errorf("partition %s seals %d members but the tree holds %d", p.Name,
				len(p.MemberRefs), len(set.Items(p.Name)))
		}
		if len(p.OverlapChecks) != 2 {
			t.Errorf("partition %s carries %d overlap checks: it must be compared against each of the two "+
				"other partitions", p.Name, len(p.OverlapChecks))
		}
	}

	// Nothing has been observed yet: the shipped expectations are declared against
	// the fixture's rule table, and the report has to be able to say so.
	if got := len(set.Unobserved(contracts.PartitionDevelopment)); got != len(dev) {
		t.Errorf("Unobserved listed %d of %d development refs: a ref with declared evidence only is not "+
			"observed, and claiming otherwise would report tuning as measurement", got, len(dev))
	}
}

func TestShippedCorpusCoversTheMatrixItClaims(t *testing.T) {
	set := shipped(t)
	seenClass := map[contracts.AttackClass]int{}
	seenVector := map[contracts.Vector]int{}
	seenEncoding := map[contracts.Encoding]int{}
	for _, item := range set.Items(contracts.PartitionDevelopment) {
		seenClass[item.AttackClass]++
		seenVector[item.Vector]++
		seenEncoding[item.Encoding]++
	}
	// nosql_injection is deliberately absent: the inertness gate refuses an
	// operator-injecting probe, so the class is reported as a corpus gap.
	for _, cls := range []contracts.AttackClass{contracts.ClassSQLi, contracts.ClassXSS,
		contracts.ClassPathTraversal, contracts.ClassCommandInjection, contracts.ClassCRLFInjection,
		contracts.ClassSSRF, contracts.ClassXXE, contracts.ClassLDAPInjection} {
		if seenClass[cls] == 0 {
			t.Errorf("the development corpus carries no %s probe: the coverage report would have to call "+
				"the class untested", cls)
		}
	}
	for _, vec := range []contracts.Vector{contracts.VectorQuery, contracts.VectorBodyJSON,
		contracts.VectorBodyForm, contracts.VectorPath, contracts.VectorHeader, contracts.VectorCookie,
		contracts.VectorMultipart} {
		if seenVector[vec] == 0 {
			t.Errorf("no %s probe in the development corpus", vec)
		}
	}
	for _, enc := range []contracts.Encoding{contracts.EncodingCanonical, contracts.EncodingURLSingle,
		contracts.EncodingURLDouble, contracts.EncodingHTMLEntity, contracts.EncodingHTMLEntityNum,
		contracts.EncodingUnicodeEscape, contracts.EncodingCaseVariant, contracts.EncodingCommentInsert,
		contracts.EncodingWhitespaceVar} {
		if seenEncoding[enc] == 0 {
			t.Errorf("no %s probe in the development corpus: the encoding axis cannot be measured "+
				"without at least one item written in it", enc)
		}
	}
	if n := seenClass[contracts.ClassNoSQLInjection]; n != 0 {
		t.Errorf("the corpus holds %d nosql probe(s): the inertness gate refuses a query-operator probe, "+
			"so one here means the gate was edited rather than the corpus", n)
	}
}

// ------------------------------------------------------------------- the gate

func TestGateRefusesProbesThatCanExecute(t *testing.T) {
	p := corpus.DefaultPolicy()
	cases := []struct {
		name  string
		probe string
		rule  string
	}{
		{"union select reads rows", `' or 1=1 union select xammu-probe from users`, "inert.sql.data_exfiltration"},
		{"information_schema", `' or 1=1 xammu-probe from information_schema.tables`, "inert.sql.data_exfiltration"},
		{"write statement", `'; drop table xammu-probe`, "inert.sql.write"},
		{"second statement after a semicolon", `1'; select xammu-probe`, "inert.sql.stacked_query"},
		{"file read through the database", `' or 1=1 and load_file('/x') xammu-probe`, "inert.sql.file_access"},
		{"timed side channel", `' or sleep(5) xammu-probe`, "inert.sql.timed_side_effect"},
		{"database command shell", `'; xp_cmdshell xammu-probe`, "inert.db.exec"},
		{"command substitution", `; echo $(id) xammu-probe`, "inert.os.command_substitution"},
		{"backtick substitution", "`id` xammu-probe", "inert.os.command_substitution"},
		{"interpreter call", `xammu-probe; system('id')`, "inert.os.command_substitution"},
		{"named shell", `; /bin/sh xammu-probe`, "inert.os.binary_named"},
		{"fetches a second stage", `; curl http://127.0.0.1:9/xammu-probe`, "inert.os.binary_named"},
		{"reverse shell", `bash -i >& /dev/tcp/127.0.0.1/9 xammu-probe`, "inert.os.reverse_shell"},
		{"executable script", `<script>alert(1)</script> xammu-probe`, "inert.script.executable"},
		{"event handler", `<xammu-probe onerror=run()>`, "inert.script.executable"},
		{"script with a call", `javascript:alert(1)xammu-probe`, "inert.script.executable"},
		{"naming a cookie", `xammu-probe document.cookie`, "inert.script.executable"},
		{"expression evaluates", `${jndi:xammu-probe}`, "inert.template.expression"},
		{"external entity fetches", `<!ENTITY x SYSTEM "file:///x">xammu-probe`, "inert.xml.external_entity"},
		{"null byte truncation", `xammu-probe%00.jpg`, "inert.file.null_byte"},
		{"real file", `../../etc/passwd xammu-probe`, "inert.file.absolute_path"},
		{"non-http scheme", `gopher://127.0.0.1:11211/xammu-probe`, "inert.url.scheme_smuggling"},
		{"ldap filter logic", `xammu-probe)(&(|(a=b`, "inert.ldap.filter"},
		{"query operator", `{"xammu-probe":{"$where":"sleep(1)"}}`, "inert.nosql.operator"},
		{"request framing", `xammu-probe transfer-encoding: chunked`, "inert.control.request_smuggling"},
		{"credential material", `xammu-probe&password=hunter2hunter2`, "inert.secret.material"},
		{"names a routable host", `http://example.org/xammu-probe`, "inert.url.host_not_allowed"},
		{"hides a framing byte", "xammu-probe\x01\x02", "inert.control_byte"},
		{"too long to review", `xammu-probe` + strings.Repeat(" aaaaaaaaaa", 60), "inert.over_length"},
	}
	for _, tc := range cases {
		hits := p.Check(tc.probe)
		found := false
		for _, h := range hits {
			if h.Rule == tc.rule {
				found = true
			}
		}
		if !found {
			var got []string
			for _, h := range hits {
				got = append(got, h.Rule)
			}
			t.Errorf("%s: probe %q must refuse with %s, got %v", tc.name, tc.probe, tc.rule, got)
		}
	}
}

func TestGateAcceptsDiagnosticShapeWithoutCapability(t *testing.T) {
	p := corpus.DefaultPolicy()
	accepted := []string{
		"' or 1=1 xammu-probe",
		"%2527%2520or%201%3d1%20xammu-probe",
		"<xammu-probe-script",
		"javascript:xammu-probe",
		"; xammu-probe ;",
		"../../xammu-probe",
		"<!ENTITY xammu-probe \"inert\">",
		")xammu-probe=*",
		"http://127.0.0.1:8081/xammu-probe",
		"%0D%0Axammu-probe%3A%201",
		"xammu-probe=1",
	}
	for _, probe := range accepted {
		if hits := p.Check(probe); len(hits) > 0 {
			var rules []string
			for _, h := range hits {
				rules = append(rules, h.Rule+": "+h.Reason)
			}
			t.Errorf("the gate refused a probe that only carries shape: %q -> %s", probe,
				strings.Join(rules, "; "))
		}
	}
}

func TestGateRefusesAFileThatClaimsInertnessItHasNot(t *testing.T) {
	dir := t.TempDir()
	item := baseItem("' or 1=1 union select xammu-probe from users")
	item.Inertness.Verdict = contracts.InertVerified
	item.Inertness.Notes = "verified_inert by an earlier review"
	writeItem(t, dir, contracts.PartitionDevelopment, item)
	writeItem(t, dir, contracts.PartitionCalibration, baseItem("xammu-probe-token"))
	writeItem(t, dir, contracts.PartitionIndependent, baseItem("xammu-probe-iv"))

	_, err := corpus.Load(dir, corpus.DefaultPolicy())
	if err == nil {
		t.Fatal("the loader accepted a probe whose claim says inert and whose bytes say otherwise")
	}
	for _, want := range []string{"is not inert", "inert.sql.data_exfiltration", "discovers defensive behaviour"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal must contain %q; got %v", want, err)
		}
	}
}

func TestGateForgivesTheMarkerOnlyForTrafficThatIsBenignByDefinition(t *testing.T) {
	p := corpus.DefaultPolicy()

	diagnosis := baseItem("widget list page 2")
	diagnosis.Probe = "widget list page 2"
	diagnosis.Canonical = "widget list page 2"
	if err := p.Apply(&diagnosis); err == nil {
		t.Error("an attack-shaped diagnosis probe with no marker was accepted: traffic that cannot be " +
			"identified as diagnostic is indistinguishable from an attack")
	} else if !strings.Contains(err.Error(), "inert.marker_absent") {
		t.Errorf("expected the marker rule to refuse it, got %v", err)
	}

	benign := baseItem("widget list page 2")
	benign.Purpose = contracts.PurposeBenignReference
	if err := p.Apply(&benign); err != nil {
		t.Errorf("a benign reference must not need a marker; its whole purpose is to look like ordinary "+
			"traffic: %v", err)
	}

	dangerousBenignClaim := baseItem("widget list page 2; /bin/sh")
	dangerousBenignClaim.Purpose = contracts.PurposeNegativeControl
	if err := p.Apply(&dangerousBenignClaim); err == nil {
		t.Error("a negative control carrying a shell command was accepted: benign is not unchecked")
	}
}

// ------------------------------------------------------------------- the loader

func TestLoaderRefusesADigestThatDisagreesWithItsProbe(t *testing.T) {
	dir := t.TempDir()
	item := baseItem("xammu-probe-token")
	item.ProbeDigest = contracts.NewDigest([]byte("a different probe entirely"))
	writeItem(t, dir, contracts.PartitionDevelopment, item)
	for _, part := range contracts.AllPartitionNames() {
		if part == contracts.PartitionDevelopment {
			continue
		}
		writeItem(t, dir, part, baseItem("xammu-probe-"+string(part)))
	}
	_, err := corpus.Load(dir, corpus.DefaultPolicy())
	if err == nil || !strings.Contains(err.Error(), "digests to") {
		t.Fatalf("want the digest-mismatch refusal, got %v", err)
	}
}

func TestLoaderRefusesAnEmptyPartition(t *testing.T) {
	dir := t.TempDir()
	for _, part := range contracts.AllPartitionNames() {
		writeItem(t, dir, part, baseItem("xammu-probe-"+string(part)))
	}
	if _, err := corpus.Load(dir, corpus.DefaultPolicy()); err != nil {
		t.Fatalf("baseline load: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "calibration", "items.jsonl")); err != nil {
		t.Fatal(err)
	}
	_, err := corpus.Load(dir, corpus.DefaultPolicy())
	if err == nil || !strings.Contains(err.Error(), "holds no .jsonl files") {
		t.Fatalf("want the empty-partition refusal, got %v", err)
	}
}

func TestLoaderRefusesAMissingPartition(t *testing.T) {
	dir := t.TempDir()
	for _, part := range contracts.AllPartitionNames() {
		if part == contracts.PartitionIndependent {
			continue
		}
		writeItem(t, dir, part, baseItem("xammu-probe-"+string(part)))
	}
	_, err := corpus.Load(dir, corpus.DefaultPolicy())
	if err == nil || !strings.Contains(err.Error(), "no directory") {
		t.Fatalf("an absent partition is not an empty one: a corpus missing a partition cannot be judged "+
			"for leakage, got %v", err)
	}
}

func TestLoaderRefusesADuplicateRefAndAWronglyFiledItem(t *testing.T) {
	dir := t.TempDir()
	first := baseItem("xammu-probe-a")
	second := baseItem("xammu-probe-b")
	second.Ref = first.Ref
	second.ItemID = contracts.NewUUID()
	writeItem(t, dir, contracts.PartitionDevelopment, first)
	for _, part := range contracts.AllPartitionNames() {
		if part != contracts.PartitionDevelopment {
			writeItem(t, dir, part, baseItem("xammu-probe-"+string(part)))
		}
	}
	if _, err := corpus.Load(dir, corpus.DefaultPolicy()); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	writeItem(t, dir, contracts.PartitionDevelopment, second)
	_, err := corpus.Load(dir, corpus.DefaultPolicy())
	if err == nil || !strings.Contains(err.Error(), "already defined") {
		t.Fatalf("want the duplicate-ref refusal, got %v", err)
	}

	dir = t.TempDir()
	misfiled := baseItem("xammu-probe-misfiled")
	misfiled.Partition = contracts.PartitionCalibration
	writeItem(t, dir, contracts.PartitionDevelopment, misfiled)
	for _, part := range contracts.AllPartitionNames() {
		if part != contracts.PartitionDevelopment {
			writeItem(t, dir, part, baseItem("xammu-probe-"+string(part)))
		}
	}
	_, err = corpus.Load(dir, corpus.DefaultPolicy())
	if err == nil || !strings.Contains(err.Error(), "the directory is the authority") {
		t.Fatalf("want the wrongly-filed refusal, got %v", err)
	}
}

func TestLoaderRefusesAFutureDatedCertification(t *testing.T) {
	dir := t.TempDir()
	item := baseItem("xammu-probe-future")
	item.Inertness.CheckedAt = stamp.AddDate(3, 0, 0)
	writeItem(t, dir, contracts.PartitionDevelopment, item)
	for _, part := range contracts.AllPartitionNames() {
		if part != contracts.PartitionDevelopment {
			writeItem(t, dir, part, baseItem("xammu-probe-"+string(part)))
		}
	}
	_, err := corpus.Load(dir, corpus.DefaultPolicy())
	if err == nil || !strings.Contains(err.Error(), "in the future") {
		t.Fatalf("want the future-dated refusal, got %v", err)
	}
}

// -------------------------------------------------------------- the leak checks

func TestOverlapDetectorNamesTheCollisionItFinds(t *testing.T) {
	dir := t.TempDir()
	// The same group id in two partitions: the item labels differ, the traffic does
	// not, and a canonical probe calibrating a detector while its twin tunes
	// another is the leak C-13's group rule exists to prevent.
	shared := baseItem("xammu-probe-shared-group")
	shared.GroupID = "G-SHARED"
	writeItem(t, dir, contracts.PartitionDevelopment, shared)
	leaked := baseItem("xammu-probe-shared-group")
	leaked.ItemID = contracts.NewUUID()
	leaked.Ref = "IV-LEAK-01"
	leaked.GroupID = "G-SHARED"
	leaked.Partition = contracts.PartitionIndependent
	writeItem(t, dir, contracts.PartitionIndependent, leaked)
	writeItem(t, dir, contracts.PartitionCalibration, baseItem("xammu-probe-cal"))

	set, err := corpus.Load(dir, corpus.DefaultPolicy())
	if err != nil {
		t.Fatalf("a leaking tree must still load, so the leak can be reported: %v", err)
	}
	leaks := set.Overlaps()
	var named bool
	for _, l := range leaks {
		if l.Kind == "group_id" && l.Value == "G-SHARED" && len(l.Partitions) == 2 {
			named = true
			if !strings.Contains(l.String(), "development") || !strings.Contains(l.String(), "independent") {
				t.Errorf("leak must name both partitions: %s", l)
			}
		}
	}
	if !named {
		t.Fatalf("the detector missed the shared group: %+v", leaks)
	}
	if err := set.Usable(); err == nil || !strings.Contains(err.Error(), "leakage") {
		t.Fatalf("a leaking corpus must refuse to be used: %v", err)
	}
	_, err = set.BuildPartitions("corpus@1", stamp)
	if err == nil || !strings.Contains(err.Error(), "shares probe text") {
		t.Fatalf("the same bytes in two partitions must refuse the build: %v", err)
	}
	checks := set.OverlapChecks(contracts.PartitionIndependent, stamp)
	var verdict string
	for _, c := range checks {
		if c.Against == contracts.PartitionDevelopment {
			verdict = c.Verdict
			if len(c.SharedGroups) != 1 || c.SharedGroups[0] != "G-SHARED" {
				t.Errorf("the check must list the shared group, got %v", c.SharedGroups)
			}
		}
	}
	if verdict != "leak_detected" {
		t.Errorf("check against development reads %q, want leak_detected", verdict)
	}
}

func TestIndependentPartitionMayNotBeUsedForTuning(t *testing.T) {
	set := shipped(t)
	partitions, err := set.BuildPartitions("corpus@1", stamp)
	if err != nil {
		t.Fatal(err)
	}
	for _, use := range []string{"tuning", "detector_development", "threshold_setting", "calibration"} {
		if err := corpus.EnsureAllows(partitions, contracts.PartitionIndependent, use); err == nil {
			t.Errorf("the independent partition accepted use %q: tuning on the validation set is how a "+
				"fake result is produced", use)
		}
	}
	if err := corpus.EnsureAllows(partitions, contracts.PartitionIndependent, "independent_validation"); err != nil {
		t.Errorf("the independent partition must allow its own use: %v", err)
	}
	if err := corpus.EnsureAllows(partitions, contracts.PartitionDevelopment, "tuning"); err != nil {
		t.Errorf("the development partition is the tuning set: %v", err)
	}
	if err := corpus.EnsureAllows(partitions, contracts.PartitionDevelopment, "independent_validation"); err == nil {
		t.Error("the development partition is not a validation set: it was used to write the detectors")
	}
}

// ------------------------------------------------------------------- selection

func TestSelectSpendsTheBudgetCoverageFirst(t *testing.T) {
	set := shipped(t)
	req := corpus.SelectionRequest{
		Partition:         contracts.PartitionDevelopment,
		ControlsPartition: contracts.PartitionCalibration,
		Classes:           contracts.AllAttackClasses(),
		Vectors:           contracts.AllVectors(),
		Encodings:         contracts.AllEncodings(),
		Budget:            30,
	}
	sel, err := set.Select(req)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if sel.Requests != req.Budget {
		t.Errorf("the selection spends %d of %d authorized exchanges: an unused part of the budget is "+
			"probes that were never planned", sel.Requests, req.Budget)
	}
	if len(sel.Controls) == 0 {
		t.Error("a selection with no controls cannot validate its own readings")
	}
	classes := map[contracts.AttackClass]int{}
	for _, item := range sel.Probes {
		classes[item.AttackClass]++
	}
	if len(classes) < 5 {
		var got []string
		for c, n := range classes {
			got = append(got, string(c)+"="+strconv.Itoa(n))
		}
		t.Errorf("a truncated budget must still spread across the matrix, it covered %d classes (%s): "+
			"spending it all on one class reports a partial run as a covered one", len(classes),
			strings.Join(got, " "))
	}
	if len(sel.Excluded) == 0 {
		t.Error("a selection that spent its budget left no exclusions, so the report cannot say what " +
			"was not tested")
	}
	var reasons []string
	for _, e := range sel.Excluded {
		reasons = append(reasons, e.Ref+": "+e.Reason)
	}
	joined := strings.Join(reasons, "\n")
	if !strings.Contains(joined, "budget ended") {
		t.Errorf("exclusions must name the budget as the reason for what did not fit:\n%s", joined)
	}
	for _, item := range sel.Items() {
		if item.Encoding != contracts.EncodingCanonical &&
			!canonicalPlannedBefore(sel.Probes, item) {
			t.Errorf("ref %s is an encoding replica planned without its canonical twin: the replica is only "+
				"interpretable against that reading", item.Ref)
		}
	}
}

// TestSelectExcludesControlTrafficInsideTheProbePartition covers the case the
// shipped tree does not have: a control that was filed into the partition a run
// draws probes from. It must be named, and named as a control, because a reader
// of the denominator has to know it was never counted.
func TestSelectExcludesControlTrafficInsideTheProbePartition(t *testing.T) {
	dir := t.TempDir()
	probe := baseItem("xammu-probe-alpha")
	probe.Ref, probe.GroupID = "T-PROBE-ALPHA", "G-ALPHA"
	writeItem(t, dir, contracts.PartitionDevelopment, probe)

	misfiled := baseItem("xammu-probe-bravo")
	misfiled.Ref, misfiled.GroupID = "T-CONTROL-BRAVO", "G-BRAVO"
	misfiled.Purpose = contracts.PurposePositiveControl
	misfiled.ExpectedBehavior = contracts.ExpectBlock
	writeItem(t, dir, contracts.PartitionDevelopment, misfiled)

	calibration := []struct {
		ref     string
		group   string
		probe   string
		purpose contracts.Purpose
		want    contracts.ExpectedBehavior
	}{
		{"T-CAL-POS", "G-CAL-POS", "xammu-probe-calpos", contracts.PurposePositiveControl, contracts.ExpectBlock},
		{"T-CAL-NEG", "G-CAL-NEG", "xammu-probe-calneg", contracts.PurposeNegativeControl, contracts.ExpectPass},
		{"T-CAL-BEN-1", "G-CAL-BEN", "widget list page 2", contracts.PurposeBenignReference, contracts.ExpectPass},
		{"T-CAL-BEN-2", "G-CAL-BEN", "order 12345 shipped", contracts.PurposeBenignReference, contracts.ExpectPass},
	}
	for _, c := range calibration {
		item := baseItem(c.probe)
		item.Ref, item.GroupID = c.ref, c.group
		item.Purpose = c.purpose
		item.ExpectedBehavior = c.want
		writeItem(t, dir, contracts.PartitionCalibration, item)
	}
	indep := baseItem("xammu-probe-indep")
	indep.Ref, indep.GroupID = "T-INDEP", "G-INDEP"
	writeItem(t, dir, contracts.PartitionIndependent, indep)

	set, err := corpus.Load(dir, corpus.DefaultPolicy())
	if err != nil {
		t.Fatalf("load the fixture tree: %v", err)
	}
	sel, err := set.Select(corpus.SelectionRequest{
		Partition: contracts.PartitionDevelopment, ControlsPartition: contracts.PartitionCalibration,
		Classes: contracts.AllAttackClasses(), Vectors: contracts.AllVectors(),
		Encodings: contracts.AllEncodings(), Budget: 10,
	})
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	var reason string
	found := false
	for _, e := range sel.Excluded {
		if e.Ref == misfiled.Ref {
			reason, found = e.Reason, true
		}
	}
	if !found {
		t.Fatal("the control sitting in the probe partition was neither planned nor excluded: it vanished")
	}
	if !strings.Contains(reason, "calibration traffic") {
		t.Errorf("the exclusion must say the item is calibration traffic, not merely that it did not fit: %q",
			reason)
	}
	for _, item := range sel.Probes {
		if item.Ref == misfiled.Ref {
			t.Error("a control was planned as probe traffic, which puts it in the denominator it validates")
		}
	}
}

func TestSelectRefusesARunThatCannotValidateItself(t *testing.T) {
	set := shipped(t)
	_, err := set.Select(corpus.SelectionRequest{
		Partition: contracts.PartitionDevelopment, ControlsPartition: contracts.PartitionCalibration,
		Classes: []contracts.AttackClass{contracts.ClassSQLi},
		// No vector is authorized, so every control falls out of scope.
		Vectors:   []contracts.Vector{contracts.VectorMultipart},
		Encodings: contracts.AllEncodings(),
		Budget:    50,
	})
	if err == nil {
		t.Fatal("a selection with no controls at all must be refused rather than planned")
	}
	for _, want := range []string{"positive control", "negative control", "reference-contrast"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal must name the missing %s: %v", want, err)
		}
	}
	if _, err := set.Select(corpus.SelectionRequest{
		Partition: contracts.PartitionDevelopment, ControlsPartition: contracts.PartitionCalibration,
		Classes: contracts.AllAttackClasses(), Vectors: contracts.AllVectors(),
		Encodings: contracts.AllEncodings(), Budget: 0,
	}); err == nil || !strings.Contains(err.Error(), "no authorized exchanges") {
		t.Fatalf("a zero budget must be refused as arithmetic, not planned as an empty run: %v", err)
	}
}

// A budget that fits the calibration traffic and no probe buys a run with nothing to
// compare. The controls are selected first and they are the smaller half of the
// arithmetic, so this is decided before a single request is spent - which is the only
// time it is worth deciding.
func TestSelectRefusesABudgetThatBuysNoProbe(t *testing.T) {
	set := shipped(t)
	req := corpus.SelectionRequest{
		Partition: contracts.PartitionDevelopment, ControlsPartition: contracts.PartitionCalibration,
		Classes:   []contracts.AttackClass{contracts.ClassSQLi},
		Vectors:   []contracts.Vector{contracts.VectorQuery},
		Encodings: contracts.AllEncodings(),
		Budget:    40,
	}
	sel, err := set.Select(req)
	if err != nil {
		t.Fatalf("this scope has both controls and probes, so a wide budget must plan it: %v", err)
	}
	controlCount := len(sel.Controls)
	if controlCount == 0 {
		t.Fatal("the shipped calibration partition is expected to carry controls for sqli over query")
	}

	// The same scope at exactly the size of its calibration traffic plans no probe.
	req.Budget = controlCount
	_, err = set.Select(req)
	if err == nil {
		t.Fatal("a budget that holds only calibration traffic must be refused, not planned")
	}
	for _, want := range []string{"calibration exchange(s)", "the plan holds none", "raise --budget"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal must state %q so the operator sees the arithmetic: %v", want, err)
		}
	}

	// The other shape of the same refusal: a scope with controls but no probes at all.
	empty := corpus.SelectionRequest{
		Partition: contracts.PartitionDevelopment, ControlsPartition: contracts.PartitionCalibration,
		Classes:   []contracts.AttackClass{contracts.ClassXSS},
		Vectors:   []contracts.Vector{contracts.VectorMultipart},
		Encodings: contracts.AllEncodings(),
		Budget:    50,
	}
	if _, err := set.Select(empty); err == nil {
		t.Fatal("a scope that selects no probe cannot be measured, so it must not be planned")
	}
}

// ------------------------------------------------------------------ placement

func TestPlaceRendersEachVector(t *testing.T) {
	set := shipped(t)
	byRef := map[string]contracts.CorpusItem{}
	for _, part := range contracts.AllPartitionNames() {
		for _, item := range set.Items(part) {
			byRef[item.Ref] = item
		}
	}
	opts := corpus.Options{OriginPath: "/api/search"}

	cases := []struct {
		ref    string
		method string
		check  func(t *testing.T, p corpus.Placement)
	}{
		{"DEV-SQLI-Q-01", "GET", func(t *testing.T, p corpus.Placement) {
			// A canonical probe is the semantic value, so the transport escapes it.
			want := "q=%27+or+1%3D1+xammu-probe"
			if p.Query != want {
				t.Errorf("query rendering: got %q want %q", p.Query, want)
			}
		}},
		{"DEV-SQLI-Q-03", "GET", func(t *testing.T, p corpus.Placement) {
			// An authored encoding is the wire form: escaping it again would turn a
			// single-encoded probe into a double-encoded one and measure nothing.
			want := "q=%2527%2520or%25201%253d1%2520xammu-probe"
			if p.Query != want {
				t.Errorf("double-encoded rendering must preserve its own escapes: got %q want %q", p.Query, want)
			}
		}},
		{"DEV-SQLI-J-01", "POST", func(t *testing.T, p corpus.Placement) {
			if p.ContentType != "application/json" {
				t.Errorf("body vector content type: %q", p.ContentType)
			}
			if !strings.Contains(string(p.Body), `' or 1=1 xammu-probe`) {
				t.Errorf("json body must carry the probe as a JSON string value: %s", p.Body)
			}
		}},
		{"DEV-SQLI-F-01", "POST", func(t *testing.T, p corpus.Placement) {
			if p.ContentType != "application/x-www-form-urlencoded" {
				t.Errorf("form content type: %q", p.ContentType)
			}
			if !strings.HasPrefix(string(p.Body), "q=%27+or+1%3D1") {
				t.Errorf("form body: %s", p.Body)
			}
		}},
		{"DEV-SQLI-M-01", "POST", func(t *testing.T, p corpus.Placement) {
			if !strings.HasPrefix(p.ContentType, "multipart/form-data; boundary=") {
				t.Errorf("multipart content type: %q", p.ContentType)
			}
			if !strings.Contains(string(p.Body), "xammu-probe-multipart") {
				t.Errorf("multipart body must carry the value: %s", p.Body)
			}
		}},
		{"DEV-TRAV-P-01", "GET", func(t *testing.T, p corpus.Placement) {
			want := "/api/search/..%2F..%2Fxammu-probe"
			if p.Path != want {
				t.Errorf("path vector must stay one segment so the origin cannot route on it: got %q want %q",
					p.Path, want)
			}
		}},
		{"DEV-CRLF-H-01", "GET", func(t *testing.T, p corpus.Placement) {
			if len(p.Headers) != 1 || p.Headers[0].Name != "X-Xammu-Probe" {
				t.Fatalf("header rendering: %+v", p.Headers)
			}
			if p.Headers[0].Value != "%0D%0Axammu-probe%3A%201" {
				t.Errorf("a header probe is placed verbatim, because it is authored as the escaped form: %q",
					p.Headers[0].Value)
			}
		}},
		{"DEV-CRLF-H-02", "GET", func(t *testing.T, p corpus.Placement) {
			if len(p.Headers) != 1 || p.Headers[0].Name != "X-Trace-Site" {
				t.Errorf("the item's header tag must drive the name; the asymmetry is name-keyed: %+v", p.Headers)
			}
		}},
		{"DEV-COOKIE-01", "GET", func(t *testing.T, p corpus.Placement) {
			if len(p.Headers) != 1 || p.Headers[0].Name != "Cookie" {
				t.Fatalf("cookie rendering: %+v", p.Headers)
			}
			if got := p.Headers[0].Value; got != "xammu-probe-0=xammu-probe=1" {
				t.Errorf("the equals inside the value must survive, COOKIE-001 matches on it: %q", got)
			}
		}},
		{"DEV-COOKIE-02", "GET", func(t *testing.T, p corpus.Placement) {
			if got := p.Headers[0].Value; !strings.HasPrefix(got, "xammu_probe_payload=") {
				t.Errorf("the unscanned cookie name must come from the item: %q", got)
			}
		}},
		{"DEV-SQLI-Q-04", "GET", func(t *testing.T, p corpus.Placement) {
			// The whitespace variant is authored as the wire form: the spaces that make
			// it a variant must reach the transport escaped, and decoding the placed
			// query must reproduce the authored probe exactly -- one layer, no more.
			values, err := url.ParseQuery(p.Query)
			if err != nil {
				t.Fatalf("the rendered query must parse: %q: %v", p.Query, err)
			}
			if len(values) != 1 || len(values["q"]) != 1 {
				t.Fatalf("a probe that adds a parameter boundary is a different request: %q", p.Query)
			}
			if got := values["q"][0]; got != "' or   1  =  1 xammu-probe" {
				t.Errorf("decoding must give back the authored probe, one decode pass: %q", got)
			}
			if !strings.Contains(p.Query, "%20") {
				t.Errorf("the whitespace escapes are the encoding under test, they cannot be sent literal: %q",
					p.Query)
			}
		}},
	}
	for _, tc := range cases {
		item, ok := byRef[tc.ref]
		if !ok {
			t.Fatalf("the shipped corpus no longer carries %s", tc.ref)
		}
		placed, err := corpus.Place(item, opts)
		if err != nil {
			t.Fatalf("place %s: %v", tc.ref, err)
		}
		if placed.Method != tc.method {
			t.Errorf("%s: method %s, want %s", tc.ref, placed.Method, tc.method)
		}
		if placed.Rationale == "" {
			t.Errorf("%s: a planned exchange with no stated rationale is an unexplained request", tc.ref)
		}
		tc.check(t, placed)
	}
}

func TestPlaceRefusesWhatItCannotRender(t *testing.T) {
	item := baseItem("xammu-probe-token")
	item.Vector = contracts.Vector("grpc")
	if _, err := corpus.Place(item, corpus.Options{}); err == nil ||
		!strings.Contains(err.Error(), "cannot place") {
		t.Fatalf("an unknown vector must be refused rather than moved to a transport the corpus does not "+
			"claim, got %v", err)
	}

	unknown := baseItem("xammu-probe-token")
	unknown.Purpose = contracts.Purpose("reverse_shell")
	if _, err := corpus.Place(unknown, corpus.Options{}); err == nil ||
		!strings.Contains(err.Error(), "no planning role") {
		t.Fatalf("an unknown purpose must be refused rather than defaulted to probe, got %v", err)
	}
}

// ------------------------------------------------------------------- evidence

func TestEvidenceKindsSeparateDeclaredFromObserved(t *testing.T) {
	item := baseItem("xammu-probe-token")
	if err := corpus.AppendObservation(&item, "lab-run:2026-10-28T1",
		"sha256:7ea3616a1070243aaa01c3d7b143ac0d8c05bb5bcaf253a566e04eedf0f1a8be",
		"blocked", stamp, true); err != nil {
		t.Fatalf("append: %v", err)
	}
	if len(item.Validation) != 2 {
		t.Fatalf("got %d evidence entries, want the declared one plus the observation", len(item.Validation))
	}
	if got := item.Validation[1].Result; got != "blocked" {
		t.Errorf("the recorded result is the run's reading, got %q", got)
	}
	if err := corpus.AppendObservation(&item, "lab-rule-table:SQLI-001", "sha256:aa", "blocked", stamp, true); err == nil {
		t.Error("a rule-table reference must not be appended as an observation: it is the same claim twice")
	}
	if err := corpus.AppendObservation(&item, "lab-run:2026-10-28T2", "latest", "blocked", stamp, true); err == nil {
		t.Error("evidence tied to a mutable tag is not reproducible")
	}
	if err := corpus.AppendObservation(&item, "lab-run:2026-10-28T2", "sha256:aa", "blocked", time.Time{}, true); err == nil {
		t.Error("undated evidence cannot be ordered, so it cannot be cited")
	}
	if _, err := corpus.KindOf("somewhere-else:1"); err == nil {
		t.Error("an unclassified run_ref is exactly how a declared expectation becomes a reported observation")
	}
}

// ---------------------------------------------------------------------- helpers

func canonicalPlannedBefore(probes []contracts.CorpusItem, item contracts.CorpusItem) bool {
	if item.Provenance.DerivedFrom == "" {
		return true
	}
	for _, p := range probes {
		if p.Ref == item.Provenance.DerivedFrom && p.Encoding == contracts.EncodingCanonical {
			return true
		}
	}
	// The twin is not in this cell: nothing to wait for.
	return !anyCellSiblingHasCanonical(probes, item)
}

func anyCellSiblingHasCanonical(probes []contracts.CorpusItem, item contracts.CorpusItem) bool {
	group := item.GroupID
	cls, vec := item.AttackClass, item.Vector
	for _, p := range probes {
		if p.GroupID == group && p.AttackClass == cls && p.Vector == vec &&
			p.Encoding == contracts.EncodingCanonical {
			return true
		}
	}
	return false
}

func baseItem(probe string) contracts.CorpusItem {
	return contracts.CorpusItem{
		ItemID: contracts.NewUUID(), Ref: refFor(probe), GroupID: "G-" + strings.ToUpper(probe[:4]),
		AttackClass: contracts.ClassSQLi, Vector: contracts.VectorQuery,
		Encoding:         contracts.EncodingCanonical,
		Canonical:        probe,
		Probe:            probe,
		ProbeDigest:      contracts.NewDigest([]byte(probe)),
		Purpose:          contracts.PurposeDiagnosis,
		ExpectedBehavior: contracts.ExpectBlock,
		Provenance: contracts.Provenance{
			Source: "test", Author: "test", ReviewRef: "TEST-1", RetrievedAt: stamp,
		},
		Inertness: contracts.InertnessRecord{
			Verdict: contracts.InertVerified, CheckedAt: stamp, Notes: "test fixture",
		},
		Validation: []contracts.CorpusValidationEvidence{{
			RunRef: "lab-rule-table:GENERIC-001", ObservedAt: stamp,
			Result: "declared_by_fixture_rule_table", LabImageDigest: "sha256:aa", MatchesExpectation: true,
		}},
		AuthoringNote: "written for this test",
	}
}

func refFor(probe string) string {
	r := []rune(probe)
	if len(r) > 6 {
		r = r[:6]
	}
	return "T-" + strings.Map(func(c rune) rune {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			return c
		}
		return '-'
	}, string(r))
}

func writeItem(t *testing.T, root string, name contracts.PartitionName, item contracts.CorpusItem) {
	t.Helper()
	dir := filepath.Join(root, corpus.PartitionDir[name])
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if item.Partition == "" {
		item.Partition = name
	}
	file := filepath.Join(dir, "items.jsonl")
	f, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	raw, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(append(raw, '\n')); err != nil {
		t.Fatal(err)
	}
}
