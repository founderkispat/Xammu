package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"xammu/internal/annex"
	"xammu/internal/contracts"
	"xammu/internal/gate"
	"xammu/internal/integrity"
)

// cmdGate applies one policy to one sealed bundle and publishes a consumable
// document. It sends nothing, writes nothing into the bundle, and refuses to
// evaluate evidence whose manifest or re-derivation does not hold.
//
// Exit codes are the pipeline contract: 0 every applicable check passed, 1 a
// check failed (a result about the target), 2 the gate could not evaluate the
// command, the policy or the evidence.
func cmdGate(c *cli, args []string) error {
	var (
		storeDir   string
		runID      string
		runsDir    string
		policyPath string
		format     string
		out        string
		trustKey   string
		signingKey string
		langName   string
		preparedBy string
	)
	fs := newFlagSet("gate", c.err)
	fs.StringVar(&storeDir, "store", "", "one sealed bundle directory, instead of a --runs-dir lookup")
	fs.StringVar(&runID, "run", "", "run id looked up under --runs-dir")
	fs.StringVar(&runsDir, "runs-dir", defaultRunsDir, "where bundles are looked up by --run")
	fs.StringVar(&policyPath, "policy", "",
		"xammu.policy/v1 file holding the thresholds; required, never discovered")
	fs.StringVar(&format, "format", "json",
		"json, yaml, sarif, markdown, annex or all (all writes the sealed delivery)")
	fs.StringVar(&out, "out", "",
		"directory to write the document into instead of printing it; required by --format all")
	fs.StringVar(&trustKey, "trust-key", "",
		"hex ed25519 public key this operator trusts; without it the signature is only checked "+
			"for self-consistency")
	fs.StringVar(&signingKey, "signing-key", "",
		"ed25519 seed file that signs the publication envelope; required by --format all and "+
			"never copied into the delivery or the bundle")
	fs.StringVar(&langName, "lang", "",
		"annex language for --format annex: es or en (default en); --format all writes both")
	fs.StringVar(&preparedBy, "prepared-by", "",
		"annex and report: person or team named as the preparer; the bundle stays anonymous")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := requireNoStrayArgs(fs); err != nil {
		return err
	}
	if policyPath == "" {
		return fmt.Errorf("%w: gate needs --policy FILE: a gate with no declared threshold would pass "+
			"everything silently", errUsage)
	}
	switch format {
	case gate.FormatJSON, gate.FormatYAML, gate.FormatSARIF, gate.FormatMarkdown, gate.FormatAnnex,
		gate.FormatAll:
	default:
		return fmt.Errorf("%w: --format %q is not json, yaml, sarif, markdown, annex or all",
			errUsage, format)
	}
	if format == gate.FormatAll && out == "" {
		return fmt.Errorf("%w: --format all writes a signed delivery and needs --out DIR", errUsage)
	}
	if format == gate.FormatAll && signingKey == "" {
		return fmt.Errorf("%w: --format all seals the delivery and needs --signing-key FILE; a "+
			"delivery without a signature is not a sealed delivery", errUsage)
	}
	if format != gate.FormatAll && signingKey != "" && format != gate.FormatMarkdown &&
		format != gate.FormatAnnex {
		return fmt.Errorf("%w: --signing-key only applies to --format all, the one rendering that "+
			"produces a sealed delivery", errUsage)
	}
	if signingKey != "" && (format == gate.FormatMarkdown || format == gate.FormatAnnex) {
		return fmt.Errorf("%w: --signing-key only applies to --format all; an ephemeral rendering "+
			"has no delivery to seal", errUsage)
	}
	if preparedBy != "" && format != gate.FormatAnnex && format != gate.FormatAll &&
		format != gate.FormatMarkdown {
		return fmt.Errorf("%w: --prepared-by only applies to markdown, annex or all", errUsage)
	}
	if langName != "" && format == gate.FormatAll {
		return fmt.Errorf("%w: --format all writes both annex languages; use --format annex --lang "+
			"es|en for one", errUsage)
	}
	if langName != "" && format != gate.FormatAnnex {
		return fmt.Errorf("%w: --lang only applies to --format annex", errUsage)
	}
	lang := annex.English
	if format == gate.FormatAnnex {
		var err error
		lang, err = annex.ParseLang(langName)
		if err != nil {
			return fmt.Errorf("%w: %v", errUsage, err)
		}
	}

	dir, err := bundleDir(storeDir, runID, runsDir)
	if err != nil {
		return err
	}
	if out != "" {
		if err := refuseGateOut(out, dir); err != nil {
			return err
		}
	}
	policy, err := gate.LoadPolicy(policyPath)
	if err != nil {
		return err
	}
	var trusted []byte
	if trustKey != "" {
		raw, err := os.ReadFile(trustKey)
		if err != nil {
			return fmt.Errorf("%w: cannot read the trusted key %s: %v", gate.ErrUnusable, trustKey, err)
		}
		trusted, err = decodeHexKey(string(raw))
		if err != nil {
			return fmt.Errorf("%w: %v", gate.ErrUnusable, err)
		}
	}
	evidence, err := gate.Load(dir, trusted)
	if err != nil {
		return err
	}
	evaluation, err := gate.Evaluate(evidence, policy, gateBundlePath(dir), trustKey != "")
	if err != nil {
		return err
	}

	if format == gate.FormatAll {
		if err := writeDelivery(c, evaluation, out, signingKey, preparedBy, trustKey != ""); err != nil {
			return err
		}
	} else {
		if err := renderOne(c, evaluation, format, out, lang, preparedBy); err != nil {
			return err
		}
	}

	if evaluation.ExitCode == 1 {
		fmt.Fprintf(c.err, "gate FAIL: run %s did not meet the policy; %d check(s) failed: %s\n",
			evaluation.Document.Source.RunID, len(evaluation.Failed),
			strings.Join(evaluation.Failed, ", "))
		return gate.ErrFailed
	}
	fmt.Fprintf(c.err, "gate PASS: run %s; %d applicable check(s) met the policy\n",
		evaluation.Document.Source.RunID, applicableChecks(evaluation.Document))
	return nil
}

// renderOne publishes an ephemeral rendering: one document, printed or written,
// with no envelope. A reader can consume it, but nothing about it claims to be
// sealed.
func renderOne(c *cli, e *gate.Evaluation, format, out string, lang annex.Lang,
	preparedBy string) error {
	var (
		raw  []byte
		name string
	)
	switch format {
	case gate.FormatMarkdown:
		raw = []byte(gate.ReportMarkdown(e.Document, gate.ReportOptions{PublicationDir: out}))
		name = "report.md"
	case gate.FormatAnnex:
		meta := annex.Meta{PreparedBy: preparedBy}
		raw = []byte(annex.EffectivenessMarkdown(e.Document, lang, meta, out))
		name = "annex-" + string(lang) + ".md"
	default:
		var err error
		raw, name, err = gate.Render(e, format)
		if err != nil {
			return err
		}
	}
	if out == "" {
		_, err := c.out.Write(raw)
		return err
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return fmt.Errorf("cannot create %s: %w", out, err)
	}
	path := filepath.Join(out, name)
	if err := os.WriteFile(path, raw, 0o640); err != nil {
		return fmt.Errorf("cannot write %s: %w", path, err)
	}
	fmt.Fprintf(c.out, "%s written to %s\n", name, filepath.ToSlash(path))
	return nil
}

// writeDelivery writes every document of a sealed delivery, signs the envelope
// that commits to them, and refuses to leave a half-sealed directory: the
// envelope is written last, after every file it names exists and hashes.
func writeDelivery(c *cli, e *gate.Evaluation, out, signingKey, preparedBy string, anchored bool) error {
	key, err := integrity.LoadKey(signingKey)
	if err != nil {
		return fmt.Errorf("%w: the publication signing key is unusable: %v", gate.ErrUnusable, err)
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return fmt.Errorf("cannot create %s: %w", out, err)
	}
	documents := map[string][]byte{}
	for _, format := range []string{gate.FormatJSON, gate.FormatYAML, gate.FormatSARIF} {
		raw, name, err := gate.Render(e, format)
		if err != nil {
			return err
		}
		documents[name] = raw
	}
	documents["report.md"] = []byte(gate.ReportMarkdown(e.Document,
		gate.ReportOptions{PublicationDir: filepath.ToSlash(out)}))
	for _, lang := range []annex.Lang{annex.Spanish, annex.English} {
		meta := annex.Meta{PreparedBy: preparedBy}
		documents["annex-"+string(lang)+".md"] = []byte(annex.EffectivenessMarkdown(
			e.Document, lang, meta, filepath.ToSlash(out)))
	}
	names := make([]string, 0, len(documents))
	for name := range documents {
		names = append(names, name)
	}
	sort.Strings(names)
	var files []gate.PublicationFile
	for _, name := range names {
		path := filepath.Join(out, name)
		if err := os.WriteFile(path, documents[name], 0o640); err != nil {
			return fmt.Errorf("cannot write %s: %w", path, err)
		}
		files = append(files, gate.PublicationFile{
			Path: name, SHA256: contracts.NewDigest(documents[name]), Bytes: len(documents[name]),
		})
	}
	publication := gate.NewPublication(e, files, anchored, time.Now().UTC())
	if err := gate.SignPublication(publication, key); err != nil {
		return err
	}
	raw, err := gate.RenderPublication(publication)
	if err != nil {
		return err
	}
	path := filepath.Join(out, gate.PublicationFileName)
	if err := os.WriteFile(path, raw, 0o640); err != nil {
		return fmt.Errorf("cannot write %s: %w", path, err)
	}
	digest, err := gate.PublicationDigest(*publication)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.out, "delivery written to %s: %d document(s) and %s\n", filepath.ToSlash(out),
		len(files), gate.PublicationFileName)
	fmt.Fprintf(c.out, "envelope %s signed by ed25519 key %s\n", digest, publication.SignerKeyID)
	return nil
}

func applicableChecks(d *gate.Document) int {
	ids := make([]string, 0, len(d.Checks))
	for id := range d.Checks {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	n := 0
	for _, id := range ids {
		if d.Checks[id].Applies {
			n++
		}
	}
	return n
}

// refuseGateOut keeps a derived delivery out of the sealed bundle. Evidence is
// read-only after the seal; writing beside it would also make the bundle look
// like it carried a document the manifest never signed.
func refuseGateOut(out, bundleDir string) error {
	absOut, err := filepath.Abs(out)
	if err != nil {
		return fmt.Errorf("cannot resolve --out %s: %w", out, err)
	}
	absBundle, err := filepath.Abs(bundleDir)
	if err != nil {
		return fmt.Errorf("cannot resolve bundle %s: %w", bundleDir, err)
	}
	rel, err := filepath.Rel(absBundle, absOut)
	if err != nil {
		return nil
	}
	if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return fmt.Errorf("--out %s is inside the evidence bundle %s: a read command does not write "+
			"into sealed evidence", out, filepath.ToSlash(bundleDir))
	}
	return nil
}

// gateBundlePath publishes a portable, slash-separated location. A path under
// the current directory stays relative; anything else keeps the cleaned path as
// the operator typed it, because inventing a different one would misstate where
// the evidence lives.
func gateBundlePath(dir string) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return filepath.ToSlash(dir)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return filepath.ToSlash(dir)
	}
	rel, err := filepath.Rel(cwd, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return filepath.ToSlash(dir)
	}
	return filepath.ToSlash(rel)
}
