package main

import (
	"fmt"
	"path/filepath"

	"xammu/internal/contracts"
	"xammu/internal/integrity"
)

// cmdAuthorization signs a permission. It sends nothing and reads no target: it
// takes a C-09 or C-10 the operator already wrote and produces the detached
// signature a run will verify. It refuses to sign a document whose fingerprint or
// immutability digest does not match the key and the fields, because a signature
// over an inconsistent declaration would make the inconsistency look approved.
func cmdAuthorization(c *cli, args []string) error {
	if len(args) == 0 || args[0] != "sign" {
		return fmt.Errorf("%w: authorization takes the subcommand sign", errUsage)
	}
	fs := newFlagSet("authorization sign", c.err)
	var authPath, keyPath string
	fs.StringVar(&authPath, "authorization", "", "C-09 or C-10 file to sign")
	fs.StringVar(&keyPath, "signing-key", "",
		"ed25519 seed file of the issuer; it must already exist, and it stays outside every bundle")
	if err := parseFlags(fs, args[1:]); err != nil {
		return err
	}
	if err := requireNoStrayArgs(fs); err != nil {
		return err
	}
	if authPath == "" {
		return fmt.Errorf("%w: authorization sign needs --authorization FILE", errUsage)
	}
	if keyPath == "" {
		return fmt.Errorf("%w: authorization sign needs --signing-key FILE: a signature names an issuer", errUsage)
	}
	key, err := integrity.LoadKey(keyPath)
	if err != nil {
		return err
	}
	kind, canonical, err := authorizationMaterial(authPath, key)
	if err != nil {
		return err
	}
	sig, err := integrity.SignAuthorization(kind, canonical, key)
	if err != nil {
		return err
	}
	if err := integrity.WriteAuthSignature(authPath, sig); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "signed %s as %s with issuer key %s\n", filepath.ToSlash(authPath), kind.Label(), key.KeyID)
	fmt.Fprintf(c.out, "signature: %s\n", filepath.ToSlash(integrity.AuthSidecarPath(authPath)))
	fmt.Fprintf(c.out, "issuer fingerprint: %s\n", integrity.KeyFingerprint(key.Public))
	return nil
}

// authorizationMaterial decodes the document strictly, proves it is internally
// consistent with the key, and returns the canonical bytes the signature covers.
// Trying C-09 first is safe because strict decoding rejects every field a C-10
// carries, so a C-10 cannot pass as a C-09.
func authorizationMaterial(path string, key *integrity.Key) (contracts.ID, []byte, error) {
	var profiling contracts.ProfilingAuthorization
	profilingErr := readContractFile(path, &profiling, contracts.IDProfilingAuthorization, "authorization", true)
	if profilingErr == nil {
		want := integrity.KeyFingerprint(key.Public)
		if profiling.IssuerKeyFingerprint != want {
			return "", nil, fmt.Errorf("authorization %s states issuer_key_fingerprint %q but the key "+
				"derives %q: set issuer_key_fingerprint to the derived value before signing", path,
				profiling.IssuerKeyFingerprint, want)
		}
		raw, err := contracts.Canonical(profiling)
		if err != nil {
			return "", nil, err
		}
		return contracts.IDProfilingAuthorization, raw, nil
	}
	var validation contracts.ValidationAuthorization
	if err := readContractFile(path, &validation, contracts.IDValidationAuthorization,
		"validation authorization", true); err != nil {
		return "", nil, fmt.Errorf("%s is neither a C-09 nor a C-10: as C-09, %v; as C-10, %v",
			path, profilingErr, err)
	}
	want, err := validation.RecomputeImmutabilityDigest()
	if err != nil {
		return "", nil, err
	}
	if validation.ImmutabilityDigest != want {
		return "", nil, fmt.Errorf("validation authorization %s states immutability_digest %s but its "+
			"fields derive %s: set the field to the derived value before signing", path,
			validation.ImmutabilityDigest, want)
	}
	raw, err := contracts.Canonical(validation)
	if err != nil {
		return "", nil, err
	}
	return contracts.IDValidationAuthorization, raw, nil
}
