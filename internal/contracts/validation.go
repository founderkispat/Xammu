package contracts

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ValidationError reports one or more field-level contract violations.
// Validators accumulate rather than fail fast so that a rejected contract
// tells the operator everything that is wrong with it.
type ValidationError struct {
	Contract ID
	Fields   []FieldError
}

// FieldError is a single field violation.
type FieldError struct {
	Field   string
	Reason  string
	Allowed []string
}

func (f FieldError) Error() string {
	if len(f.Allowed) > 0 {
		return fmt.Sprintf("%s: %s (allowed: %s)", f.Field, f.Reason, strings.Join(f.Allowed, "|"))
	}
	return fmt.Sprintf("%s: %s", f.Field, f.Reason)
}

func (v ValidationError) Error() string {
	parts := make([]string, 0, len(v.Fields))
	for _, f := range v.Fields {
		parts = append(parts, f.Error())
	}
	return fmt.Sprintf("%s (%s) invalid: %s", v.Contract, v.Contract.Label(), strings.Join(parts, "; "))
}

// Violations collects field errors during validation.
type Violations struct {
	contract ID
	fields   []FieldError
}

func newViolations(id ID) *Violations { return &Violations{contract: id} }

func (c *Violations) add(field, reason string) {
	c.fields = append(c.fields, FieldError{Field: field, Reason: reason})
}

func (c *Violations) addOne(field string, err error) {
	if err != nil {
		var vErr ValidationError
		if errors.As(err, &vErr) {
			for _, f := range vErr.Fields {
				c.fields = append(c.fields, FieldError{Field: field + "." + f.Field, Reason: f.Reason})
			}
			return
		}
		c.fields = append(c.fields, FieldError{Field: field, Reason: err.Error()})
	}
}

func (c *Violations) oneof(field, got string, allowed ...string) {
	for _, a := range allowed {
		if got == a {
			return
		}
	}
	if got == "" {
		c.add(field, "required")
	} else {
		c.fields = append(c.fields, FieldError{Field: field, Reason: "unknown value " + got, Allowed: allowed})
	}
}

// oneofT validates a typed enum field without string conversion at the call site.
func oneofT[E ~string](c *Violations, field string, got E, all ...E) {
	for _, a := range all {
		if got == a {
			return
		}
	}
	allowed := stringsOf(all)
	if got == "" {
		c.add(field, "required (one of "+strings.Join(allowed, "|")+")")
		return
	}
	c.fields = append(c.fields, FieldError{
		Field: field, Reason: "unknown value " + string(got), Allowed: allowed,
	})
}

func (c *Violations) required(field, got string) {
	if strings.TrimSpace(got) == "" {
		c.add(field, "required")
	}
}

func (c *Violations) nonNegative(field string, got int) {
	if got < 0 {
		c.add(field, fmt.Sprintf("must be >= 0, got %d", got))
	}
}

func (c *Violations) nonEmpty(field string, n int) {
	if n == 0 {
		c.add(field, "must not be empty")
	}
}

// err collapses accumulated violations into a ValidationError, or nil.
func (c *Violations) err() error {
	if len(c.fields) == 0 {
		return nil
	}
	sort.SliceStable(c.fields, func(i, j int) bool { return c.fields[i].Field < c.fields[j].Field })
	return ValidationError{Contract: c.contract, Fields: c.fields}
}

// ContractValidator checks a decoded contract instance.
type ContractValidator func(payload any) error

// Validate runs the registered validator for a contract ID. An unregistered
// contract is a hard error: silently accepting unknown schemas is how
// unverifiable evidence gets into a manifest.
func Validate(id ID, payload any) error {
	validator, ok := validators[id]
	if !ok {
		return fmt.Errorf("contract %q (%s) has no registered validator", id, id.Label())
	}
	return validator(payload)
}

var validators = map[ID]ContractValidator{}

func register(id ID, fn func(payload any) error) {
	if !Registered(id) {
		panic("contracts: cannot register validator for unknown contract " + string(id))
	}
	validators[id] = fn
}

// cast accepts a payload of the expected concrete type, as a value or as a
// pointer. Both forms are validated by the same rules over the same fields: the
// journals marshal whatever they are handed, so insisting on one calling
// convention would turn a forgotten ampersand into a run that cannot start,
// which is a worse failure than the one the convention pretends to prevent.
// A nil pointer is refused, because reading it would validate a zero struct and
// report an empty payload as evidence.
func cast[T any](id ID, payload any) (*T, error) {
	switch typed := payload.(type) {
	case *T:
		if typed == nil {
			var zero T
			return nil, ValidationError{
				Contract: id,
				Fields:   []FieldError{{Field: "(root)", Reason: fmt.Sprintf("*%T is nil", zero)}},
			}
		}
		return typed, nil
	case T:
		return &typed, nil
	}
	var zero T
	return nil, ValidationError{
		Contract: id,
		Fields:   []FieldError{{Field: "(root)", Reason: fmt.Sprintf("expected %T or *%T, got %T", zero, zero, payload)}},
	}
}
