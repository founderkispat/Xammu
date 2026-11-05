package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"xammu/internal/contracts"
	"xammu/internal/corpus"
	"xammu/internal/discover"
	"xammu/internal/httpclient"
	"xammu/internal/orchestrator"
)

// runCheckpointFile is the orchestrator's own name for the checkpoint, taken rather
// than copied, so a report cannot go looking for a file the run never wrote.
var runCheckpointFile = orchestrator.CheckpointFile

// defaultPlacementPath is the endpoint probes are placed against when the operator
// names none. It is a constant because a published reproduction command has to know
// which placement values are worth repeating, and quoting a default back at the
// reader every time makes the interesting half of the command hard to see.
const defaultPlacementPath = "/api/search"

// planFlags are the operator's narrowing choices. Every one of them selects a subset
// of what the authorization permits; none can add a class, a transport, an encoding, a
// destination or a request the authorization did not name.
type planFlags struct {
	authorization string
	authDir       string
	issuerKeyring string
	corpusRoot    string
	partition     string
	controls      string
	target        string
	budget        int
	classes       string
	vectors       string
	encodings     string
	path          string
	queryParam    string
	bodyField     string
	headerName    string
	cookieName    string
	mediaType     string
	// sensitiveHeaders extends the capture-time redaction list. It is an
	// engagement input, not a scope: it can only withhold more, never send more.
	sensitiveHeaders []string
	runsDir          string
	signingKey       string
	generatedBy      string
	runID            string
	round            string
	storeDir         string

	// authorizationRef and authorizationDir are recorded by bindAuthorization, not
	// typed by the operator: the reference the loaded C-09 carries and the directory
	// it was found in. A published command names the permission by its reference - the
	// identifier the report's own evidence block cites - and the reference is only
	// paste-able next to the place this process proved it lives.
	authorizationRef string
	authorizationDir string
}

// bindAuthorization loads the permission the operator named and records, on the flags,
// the two facts a published command needs to ask for the same permission: its
// reference and the directory it was found in. Every command that touches a target or
// re-derives a report gets these from here, so nothing renders a reference it never
// resolved.
func (p *planFlags) bindAuthorization() (*contracts.ProfilingAuthorization, error) {
	auth, foundIn, err := loadAuthorization(p.authorization, p.authDir, p.issuerKeyring)
	if err != nil {
		return nil, err
	}
	p.authorizationRef = auth.Ref
	p.authorizationDir = foundIn
	return auth, nil
}

// register declares the flags on a command's set. Commands that plan share this, so
// "playbook --class sqli" and "run --class sqli" cannot mean different things.
func (p *planFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&p.authorization, "authorization", "",
		"C-09 profiling authorization: a file path or the reference it carries")
	fs.StringVar(&p.authDir, "authorizations", defaultAuthDir,
		"directory searched when --authorization names a reference rather than a file")
	fs.StringVar(&p.issuerKeyring, "issuer-keyring", "",
		"directory of *.pub hex ed25519 keys that sign authorizations; required, and never "+
			"discovered from the document or the bundle")
	fs.StringVar(&p.corpusRoot, "corpus", "corpus", "corpus tree loaded through the inertness gate")
	fs.StringVar(&p.partition, "partition", string(contracts.PartitionDevelopment),
		"partition the probes come from")
	fs.StringVar(&p.controls, "controls", string(contracts.PartitionCalibration),
		"partition the calibration traffic comes from; it never enters a denominator")
	fs.StringVar(&p.target, "target", "", "authorized origin to bind to; default is the first listed")
	fs.IntVar(&p.budget, "budget", 0, "requests this run may spend; default is the authorized maximum")
	fs.StringVar(&p.classes, "class", "", "comma-separated attack classes to plan")
	fs.StringVar(&p.vectors, "vector", "", "comma-separated transports to plan")
	fs.StringVar(&p.encodings, "encoding", "", "comma-separated encodings to plan")
	fs.StringVar(&p.path, "path", defaultPlacementPath, "endpoint probes are placed against")
	fs.StringVar(&p.queryParam, "query-param", "", "query parameter name (default q)")
	fs.StringVar(&p.bodyField, "body-field", "", "JSON or form field name (default q)")
	fs.StringVar(&p.headerName, "header-name", "", "header carrying a header-vector probe")
	fs.StringVar(&p.cookieName, "cookie-name", "", "cookie name carrying a cookie probe")
	fs.StringVar(&p.mediaType, "media-type", "", "content type for the JSON body vector")
	fs.Func("sensitive-header", "response header whose value is withheld from the evidence; "+
		"repeatable, and it only adds to the base cookie/credential list", func(raw string) error {
		return p.addSensitiveHeader(raw)
	})
	fs.StringVar(&p.runsDir, "runs-dir", "runs", "where run bundles live")
	fs.StringVar(&p.signingKey, "signing-key", ".xammu-signing.ed25519",
		"ed25519 seed file outside the bundle; created with 0600 if absent")
	fs.StringVar(&p.generatedBy, "generated-by", "", "operator named in the evidence block")
	fs.StringVar(&p.runID, "run", "",
		"run this command writes or reads; a bundle is looked up under --runs-dir by this id")
	fs.StringVar(&p.round, "round", "round-1",
		"round label; a second round needs its own authorization, so this is a name and not a retry")
	fs.StringVar(&p.storeDir, "store", "",
		"run bundle directory; --run ID looks it up under --runs-dir, and a read command needs one of the two")
}

// bundle resolves where a run's evidence lives. A --store directory is taken as
// written; a --run id is looked up under the runs directory, which is the layout the
// reproduction commands published in a report assume.
func (p *planFlags) bundle() (string, error) {
	if p.storeDir != "" {
		return p.storeDir, nil
	}
	if p.runID == "" {
		return "", fmt.Errorf("%w: a bundle is named by --run ID or by --store DIR", errUsage)
	}
	if p.runsDir == "" {
		return "", fmt.Errorf("%w: --runs-dir is empty, so run %q has no home to look for", errUsage, p.runID)
	}
	return filepath.Join(p.runsDir, p.runID), nil
}

// engagementFlags names everything about the engagement except the scope of this one
// run: the permission, the corpus, and where the probes are placed. A step that exists
// to plan a scope the run did not cover is built from these, because inheriting the
// run's --class or --budget would silently ask the original question again.
//
// The permission is published by the reference its C-09 carries, not by the path the
// operator typed: a report is read by someone who was given the permission, not the
// operator's filesystem, and the reference is the identifier the report itself cites.
// The directory it was found in travels with it, because a bare reference resolves only
// where the reader already knows to look. A default directory is left unstated - the
// reader's default is the same convention - and any other is named as written, in slash
// form, since a backslash in a pasted command is an escape character that eats the path.
func (p planFlags) engagementFlags() string {
	var out []string
	add := func(flagName, value string) {
		out = append(out, flagName, shellArg(value))
	}
	if p.authorization != "" || p.authorizationRef != "" {
		ref := p.authorization
		if p.authorizationRef != "" {
			ref = p.authorizationRef
		}
		add("--authorization", filepath.ToSlash(ref))
		dir := p.authDir
		if p.authorizationDir != "" {
			dir = p.authorizationDir
		}
		if dir != "" && dir != defaultAuthDir {
			add("--authorizations", filepath.ToSlash(dir))
		}
		// The keyring is a trust input rather than a scope, but a published command
		// that loads a permission cannot run without it. It is recorded beside the
		// permission so the command the finding prints verifies the document it cites.
		if p.issuerKeyring != "" {
			add("--issuer-keyring", filepath.ToSlash(p.issuerKeyring))
		}
	}
	out = append(out, "--corpus", shellArg(filepath.ToSlash(p.corpusRoot)))
	if p.path != "" && p.path != defaultPlacementPath {
		add("--path", p.path)
	}
	if p.queryParam != "" {
		add("--query-param", p.queryParam)
	}
	if p.bodyField != "" {
		add("--body-field", p.bodyField)
	}
	if p.headerName != "" {
		add("--header-name", p.headerName)
	}
	if p.cookieName != "" {
		add("--cookie-name", p.cookieName)
	}
	if p.mediaType != "" {
		add("--media-type", p.mediaType)
	}
	// The redaction policy is published beside the permission because it changes
	// what the evidence can show a reader, even though it never changes the plan.
	for _, name := range p.sensitiveHeaders {
		add("--sensitive-header", name)
	}
	return strings.Join(out, " ")
}

// addSensitiveHeader records one --sensitive-header. Names are folded to the form
// the policy compares in and deduplicated, so a repeated flag neither redacts
// twice nor prints twice in the evidence.
func (p *planFlags) addSensitiveHeader(raw string) error {
	name := contracts.NormalizeHeaderName(raw)
	if name == "" {
		return errors.New("--sensitive-header needs a header name")
	}
	for _, existing := range p.sensitiveHeaders {
		if existing == name {
			return nil
		}
	}
	p.sensitiveHeaders = append(p.sensitiveHeaders, name)
	return nil
}

// reproFlags renders what a command printed by a report has to repeat about the
// engagement: the permission, the corpus, the placement, and where the bundle lives.
// The scope of this one run is appended by scopeFlagsOf, which reads the resolved
// scope instead of the operator's keystrokes; the split is what lets a run and a
// re-read of its bundle publish the same command for the same plan.
//
// The corpus is always named: a bundle downloaded next to no corpus tree cannot be
// re-derived at all, and the default directory is a convention rather than a fact
// about the reader's disk.
func (p planFlags) reproFlags() string {
	var out []string
	// The permission is the first thing a copied command needs: without it the reader
	// holds a plan with no scope and the tool refuses before it reads a single record.
	if e := p.engagementFlags(); e != "" {
		out = append(out, e)
	}
	// A bundle is only findable by run id if the reader knows which directory holds it.
	// The default is left unstated so the common case reads cleanly; any other
	// directory has to be named, or the published command looks for evidence that is
	// not where it says it is.
	if p.runsDir != "" && p.runsDir != defaultRunsDir {
		out = append(out, "--runs-dir", filepath.ToSlash(p.runsDir))
	}
	return strings.Join(out, " ")
}

// scopeFlagsOf renders the scope a run actually measured as the flags that re-plan it.
// It takes the resolved scope rather than the flags the operator typed, because the
// scope is a property of the plan and the keystrokes are not: a run that narrowed the
// authorization and a re-read of its bundle must publish one command, and two
// spellings of the same scope must not produce two strings a validator then calls a
// disagreement.
//
// A value equal to the permission's own limit is not repeated. Omitting it says
// "everything this authorization permits", which is exactly what the reader's default
// resolves to, so the command stays a description of the narrowing.
func scopeFlagsOf(sc scope, auth *contracts.ProfilingAuthorization) string {
	var out []string
	add := func(flagName, value string) {
		out = append(out, flagName, shellArg(value))
	}
	// The budget is part of the plan, not a pacing detail: the selection spends it
	// coverage-first, so a command that omits it re-plans a different set of probes.
	if sc.budget > 0 && auth != nil && sc.budget != auth.Limits.MaxRequests {
		add("--budget", strconv.Itoa(sc.budget))
	}
	if auth == nil || !sameSet(sc.classes, auth.AllowedClasses) {
		if len(sc.classes) > 0 {
			add("--class", strings.Join(orderedByVocabulary(sc.classes, contracts.AllAttackClasses()), ","))
		}
	}
	if auth == nil || !sameSet(sc.vectors, auth.AllowedVectors) {
		if len(sc.vectors) > 0 {
			add("--vector", strings.Join(orderedByVocabulary(sc.vectors, contracts.AllVectors()), ","))
		}
	}
	if auth == nil || !sameSet(sc.encodings, auth.AllowedEncodings) {
		if len(sc.encodings) > 0 {
			add("--encoding", strings.Join(orderedByVocabulary(sc.encodings, contracts.AllEncodings()), ","))
		}
	}
	if sc.controls != "" && sc.controls != contracts.PartitionCalibration {
		add("--controls", string(sc.controls))
	}
	return strings.Join(out, " ")
}

// orderedByVocabulary renders a set of vocabulary values in the vocabulary's own order,
// so two orderings of one scope produce one command. The order the operator typed is a
// keystroke; the order the vocabulary declares is the plan.
func orderedByVocabulary[T comparable](values, vocabulary []T) []string {
	chosen := make(map[T]bool, len(values))
	for _, v := range values {
		chosen[v] = true
	}
	out := make([]string, 0, len(chosen))
	seen := make(map[T]bool, len(chosen))
	for _, v := range vocabulary {
		if chosen[v] && !seen[v] {
			out = append(out, fmt.Sprint(v))
			seen[v] = true
		}
	}
	return out
}

// sameSet compares two vocabularies without caring about order: resolveScope preserves
// the order the operator typed, and a re-read reconstructs the canonical order.
func sameSet[T comparable](a, b []T) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[T]bool, len(a))
	for _, v := range a {
		seen[v] = true
	}
	if len(seen) != len(b) {
		return false
	}
	for _, v := range b {
		if !seen[v] {
			return false
		}
	}
	return true
}

// shellArg quotes a value a reader is going to paste into a shell. The placement
// names a run carries - a header, a cookie, a path - are not guaranteed to be
// space-free, and a command that silently splits into two arguments is a command
// that fails in a way the reader blames on the tool.
func shellArg(v string) string {
	if v == "" || strings.ContainsAny(v, " \t\"'") {
		return `"` + strings.ReplaceAll(v, `"`, `\"`) + `"`
	}
	return v
}

// planRequest is everything the selection needs, with the authorization's scope
// already applied to the operator's choices.
type planRequest struct {
	auth  *contracts.ProfilingAuthorization
	set   *corpus.Set
	sel   *corpus.Selection
	items []orchestrator.PlanItem
	// sc is the resolved scope, kept whole so a run and a re-read of its bundle
	// describe the same request the authorization covered.
	sc scope
}

// scope is the operator's request as the authorization constrains it. Resolving it
// is separate from placing probes because a report re-read of a sealed bundle has to
// run the same arithmetic to know what the run never planned.
type scope struct {
	partition contracts.PartitionName
	controls  contracts.PartitionName
	origin    string
	classes   []contracts.AttackClass
	vectors   []contracts.Vector
	encodings []contracts.Encoding
	budget    int
}

// resolveScope turns flags into a request the authorization covers. Every refusal
// here happens before a corpus is loaded and long before a socket is opened.
func resolveScope(auth *contracts.ProfilingAuthorization, f planFlags) (scope, error) {
	var sc scope
	if auth == nil {
		return sc, errors.New("a plan needs an authorization to be bounded by")
	}
	var err error
	if sc.partition, err = asPartition(f.partition); err != nil {
		return sc, err
	}
	if sc.controls, err = asPartition(f.controls); err != nil {
		return sc, err
	}
	if sc.partition == sc.controls {
		return sc, fmt.Errorf("probes and controls must come from different partitions, both asked for %q",
			sc.partition)
	}
	if sc.origin, err = pickOrigin(auth, f.target); err != nil {
		return sc, err
	}
	if sc.classes, err = asClasses(splitList(f.classes)); err != nil {
		return sc, err
	}
	if len(sc.classes) == 0 {
		sc.classes = auth.AllowedClasses
	}
	if sc.vectors, err = asVectors(splitList(f.vectors)); err != nil {
		return sc, err
	}
	if len(sc.vectors) == 0 {
		sc.vectors = auth.AllowedVectors
	}
	if sc.encodings, err = asEncodings(splitList(f.encodings)); err != nil {
		return sc, err
	}
	if len(sc.encodings) == 0 {
		sc.encodings = auth.AllowedEncodings
	}
	if err := withinScope(sc.classes, sc.vectors, sc.encodings, auth); err != nil {
		return sc, err
	}
	sc.budget = f.budget
	if sc.budget <= 0 {
		sc.budget = auth.Limits.MaxRequests
	}
	if auth.Limits.MaxRequests > 0 && sc.budget > auth.Limits.MaxRequests {
		return sc, fmt.Errorf("budget %d exceeds the authorized maximum %d in %s",
			sc.budget, auth.Limits.MaxRequests, auth.Ref)
	}
	if sc.budget <= 0 {
		return sc, fmt.Errorf("authorization %s states no request maximum and --budget was not given: "+
			"a run without a budget cannot be bounded and so cannot be approved", auth.Ref)
	}
	return sc, nil
}

// selectFrom loads nothing but the choice: it runs the same selection a plan does, so
// a re-derived report names the same unplanned refs the original run excluded.
func selectFrom(auth *contracts.ProfilingAuthorization, set *corpus.Set,
	f planFlags) (scope, *corpus.Selection, error) {
	sc, err := resolveScope(auth, f)
	if err != nil {
		return sc, nil, err
	}
	sel, err := set.Select(corpus.SelectionRequest{
		Partition:         sc.partition,
		ControlsPartition: sc.controls,
		Classes:           sc.classes,
		Vectors:           sc.vectors,
		Encodings:         sc.encodings,
		Budget:            sc.budget,
	})
	if err != nil {
		return sc, nil, fmt.Errorf("selection: %w", err)
	}
	return sc, sel, nil
}

// placementOptions names the slots probes go into. They come from the same flags a
// run was planned with, because a probe placed under a different header name is a
// different probe and a re-derived finding would not describe the exchange that
// happened.
func placementOptions(f planFlags) corpus.Options {
	return corpus.Options{
		OriginPath: f.path,
		QueryParam: f.queryParam,
		BodyField:  f.bodyField,
		HeaderName: f.headerName,
		CookieName: f.cookieName,
		MediaType:  f.mediaType,
	}
}

// buildPlan loads the corpus through the gate, selects probes for the authorized
// scope and renders each one onto its transport. It performs no network operation of
// any kind: a plan that was never sent costs no request and cannot harm a target.
func buildPlan(auth *contracts.ProfilingAuthorization, f planFlags) (*planRequest, error) {
	// The gate runs inside Load: an item that can execute does not reach the plan, and
	// no flag here can ask for it to be skipped.
	set, err := corpus.Load(f.corpusRoot, corpus.DefaultPolicy())
	if err != nil {
		return nil, fmt.Errorf("corpus %s: %w", f.corpusRoot, err)
	}
	sc, sel, err := selectFrom(auth, set, f)
	if err != nil {
		return nil, err
	}

	opts := placementOptions(f)
	items := make([]orchestrator.PlanItem, 0, len(sel.Items()))
	seen := map[string]bool{}
	for _, item := range sel.Items() {
		place, err := corpus.Place(item, opts)
		if err != nil {
			return nil, fmt.Errorf("cannot place %s: %w", item.Ref, err)
		}
		if seen[place.Ref] {
			return nil, fmt.Errorf("two planned exchanges share the reference %q; a probe that "+
				"cannot be named cannot be traced back from a finding", place.Ref)
		}
		seen[place.Ref] = true
		full, err := joinURL(sc.origin, place)
		if err != nil {
			return nil, fmt.Errorf("cannot build the destination for %s: %w", place.Ref, err)
		}
		items = append(items, orchestrator.PlanItem{
			Ref: place.Ref, CorpusRef: place.CorpusRef, Group: place.Group,
			Method: place.Method, URL: full, Body: place.Body,
			Headers:     placeHeaders(place),
			AttackClass: item.AttackClass, Vector: item.Vector, Encoding: item.Encoding,
			ControlRole: place.Role, Rationale: place.Rationale,
		})
	}

	clientScope, err := httpclient.ScopeFromProfiling(auth)
	if err != nil {
		return nil, fmt.Errorf("scope: %w", err)
	}
	if err := orchestrator.ValidatePlan(items, auth, clientScope, sc.budget); err != nil {
		return nil, fmt.Errorf("plan refused before any request: %w", err)
	}
	return &planRequest{auth: auth, set: set, sel: sel, items: items, sc: sc}, nil
}

// withinScope refuses a request that asks for something the authorization does not
// name, rather than letting the selection quietly drop it. The difference matters to
// the operator who typed the flag and believes they asked for ssrf.
func withinScope(classes []contracts.AttackClass, vectors []contracts.Vector,
	encodings []contracts.Encoding, auth *contracts.ProfilingAuthorization) error {
	for _, c := range classes {
		if !containsClass(auth.AllowedClasses, c) {
			return fmt.Errorf("class %q is not authorized by %s", c, auth.Ref)
		}
	}
	for _, v := range vectors {
		if !containsVector(auth.AllowedVectors, v) {
			return fmt.Errorf("transport %q is not authorized by %s", v, auth.Ref)
		}
	}
	for _, e := range encodings {
		if !containsEncoding(auth.AllowedEncodings, e) {
			return fmt.Errorf("encoding %q is not authorized by %s", e, auth.Ref)
		}
	}
	return nil
}

func containsClass(in []contracts.AttackClass, want contracts.AttackClass) bool {
	for _, v := range in {
		if v == want {
			return true
		}
	}
	return false
}

func containsVector(in []contracts.Vector, want contracts.Vector) bool {
	for _, v := range in {
		if v == want {
			return true
		}
	}
	return false
}

func containsEncoding(in []contracts.Encoding, want contracts.Encoding) bool {
	for _, v := range in {
		if v == want {
			return true
		}
	}
	return false
}

// joinURL puts the placement's path and query onto the bound origin. The result is
// what the transport is later asked for, so an origin that is not on the authorized
// list is caught here as well as at the scope check.
func joinURL(origin string, p corpus.Placement) (string, error) {
	u, err := url.Parse(origin)
	if err != nil {
		return "", fmt.Errorf("origin %q is unparsable: %w", origin, err)
	}
	u.Path = filepath.ToSlash(p.Path)
	if p.Query != "" {
		u.RawQuery = p.Query
	}
	return u.String(), nil
}

// placeHeaders adds the content type the placement chose for a body vector. The
// placement reports header entries as facts about the request it rendered; the media
// type belongs to the same request, so it is added here rather than inferred later.
func placeHeaders(p corpus.Placement) []contracts.HeaderEntry {
	out := append([]contracts.HeaderEntry(nil), p.Headers...)
	if p.ContentType != "" && headerValue(out, "Content-Type") == "" {
		out = append(out, contracts.HeaderEntry{Name: "Content-Type", Value: p.ContentType})
	}
	return out
}

// renderPlan is the playbook's answer: the plan as a table, with the exclusions the
// selection recorded. It is a preview of the same arithmetic a run would spend.
func renderPlan(out io.Writer, req *planRequest) {
	fmt.Fprintf(out, "authorization %s, target %s, partition %s (controls %s)\n",
		req.auth.Ref, req.sc.origin, req.sc.partition, req.sc.controls)
	fmt.Fprintf(out, "budget %d request(s); this plan costs %d\n\n", req.sc.budget, req.sel.Requests)
	fmt.Fprintf(out, "%-26s %-6s %-44s %-16s %-10s %-12s %s\n",
		"ref", "method", "url", "class", "transport", "encoding", "role")
	for _, item := range req.items {
		fmt.Fprintf(out, "%-26s %-6s %-44s %-16s %-10s %-12s %s\n",
			item.Ref, item.Method, shorten(item.URL, 44), item.AttackClass, item.Vector,
			item.Encoding, item.ControlRole)
	}
	fmt.Fprintf(out, "\n%d exchange(s) planned, %d corpus item(s) excluded by the selection:\n",
		len(req.items), len(req.sel.Excluded))
	for _, e := range req.sel.Excluded {
		fmt.Fprintf(out, "  %s: %s\n", e.Reason, e.Ref)
	}
	fmt.Fprint(out, "\nnothing was sent: a playbook run plans and validates only.\n")
}

// shorten keeps a table column from turning into a wall of text. The full URL is in
// the journal and in the plan file; this is a preview.
func shorten(s string, width int) string {
	if len(s) <= width || width < 8 {
		return s
	}
	return s[:width-3] + "..."
}

// unplannedFrom maps the selection's exclusions onto the discovery layer's unplanned
// items, which is how an undetermined zone learns whether the cause was the budget or
// the scope.
//
// Calibration traffic is left out on purpose: a positive control the run had no use
// for is not a zone the report failed to evaluate, and listing it as one would make
// the uncertainty dimension claim a gap that is actually the design.
func unplannedFrom(sel *corpus.Selection) []discover.Unplanned {
	var out []discover.Unplanned
	for _, e := range sel.Excluded {
		lower := strings.ToLower(e.Reason)
		if strings.Contains(lower, "calibration traffic") || strings.HasPrefix(lower, "control lives in") {
			continue
		}
		out = append(out, discover.Unplanned{Ref: e.Ref,
			Reason: unplannedReason(e.Reason), Detail: e.Reason})
	}
	return out
}

// summarizeAuth states the scope an operator is about to spend requests under. It is
// printed by every command that touches a target, because the numbers a report will
// later quote are fixed here.
func summarizeAuth(out io.Writer, a *contracts.ProfilingAuthorization) {
	fmt.Fprintf(out, "authorization %s (%s, partitions %s) expires %s\n",
		a.Ref, a.Environment, strings.Join(a.CorpusPartitions, "|"),
		a.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"))
	fmt.Fprintf(out, "  origins %d, methods %s\n", len(a.Origins), strings.Join(a.Methods, "|"))
	fmt.Fprintf(out, "  classes %s\n", strings.Join(classesToStrings(a.AllowedClasses), "|"))
	fmt.Fprintf(out, "  transports %s\n", strings.Join(vectorsToStrings(a.AllowedVectors), "|"))
	fmt.Fprintf(out, "  encodings %s\n", strings.Join(encodingsToStrings(a.AllowedEncodings), "|"))
	fmt.Fprintf(out, "  limits: %d request(s), %d/s, %d concurrent, %d ms timeout, retention %s\n",
		a.Limits.MaxRequests, a.Limits.RatePerSecond, a.Limits.MaxConcurrent,
		a.Limits.TimeoutMS, a.Retention)
}
