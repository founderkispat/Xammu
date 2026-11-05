package gate

import (
	"encoding/json"
	"fmt"
)

// Format names a consumable rendering.
const (
	FormatJSON     = "json"
	FormatYAML     = "yaml"
	FormatSARIF    = "sarif"
	FormatMarkdown = "markdown"
	FormatAnnex    = "annex"
	FormatAll      = "all"
)

// Render returns the bytes of one format and the file name a written delivery
// uses. The JSON document is authoritative; YAML and SARIF are derived from the
// same in-memory document, never from the JSON bytes.
func Render(e *Evaluation, format string) ([]byte, string, error) {
	switch format {
	case FormatJSON:
		raw, err := JSON(e.Document)
		return raw, "gate.json", err
	case FormatYAML:
		raw, err := YAML(e.Document)
		return raw, "gate.yaml", err
	case FormatSARIF:
		raw, err := SARIF(e.Document, e.ExitCode)
		return raw, "results.sarif", err
	}
	return nil, "", fmt.Errorf("%w: format %q is not json, yaml or sarif", ErrUnusable, format)
}

// JSON renders the gate document with two-space indentation. No wall-clock field
// is added here: the same evidence and policy produce the same bytes.
func JSON(d *Document) ([]byte, error) {
	raw, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}
