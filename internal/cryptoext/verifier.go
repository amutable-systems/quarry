// Copyright (C) 2026 Amutable GmbH

package cryptoext

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
)

// Verifier is a generic verifier for a particular [crypto.PublicKey].
type Verifier interface {
	Verify(digest, sig []byte, opts crypto.SignerOpts) (bool, error)
}

// VerifyMessage verifies a message using the given [Verify]. As with
// [crypto.SignMessage], this helper will automatically hash the provided
// message in accordance with the provided [crypto.SignerOpts] (which MUST
// match the options used when the message was signed).
func VerifyMessage(verifier Verifier, msg, sig []byte, opts crypto.SignerOpts) (bool, error) {
	// Pre-hash if needed, this is the same as in crypto.SignMessage.
	if hash := opts.HashFunc(); hash != 0 {
		h := hash.New()
		h.Write(msg)
		msg = h.Sum(nil)
	}
	return verifier.Verify(msg, sig, opts)
}

type rsaVerifier struct {
	pubKey *rsa.PublicKey
}

func (v *rsaVerifier) Verify(digest, sig []byte, opts crypto.SignerOpts) (bool, error) {
	pssOptions, _ := opts.(*rsa.PSSOptions)
	h := opts.HashFunc()

	var err error
	if pssOptions != nil {
		err = rsa.VerifyPSS(v.pubKey, h, digest, sig, pssOptions)
	} else {
		err = rsa.VerifyPKCS1v15(v.pubKey, h, digest, sig)
	}
	if errors.Is(err, rsa.ErrVerification) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

type ecdsaVerifier struct {
	pubKey *ecdsa.PublicKey
}

func (v *ecdsaVerifier) Verify(msg, sig []byte, _ crypto.SignerOpts) (bool, error) {
	// TODO: sigstore's verifier checks that the public key is on the curve to
	// avoid VerifyASN1() panicking. Maybe we should do that too?

	// Ignore opts entirely as the message is assumed to be hashed with
	// HashFunc already and ECDSA doesn't need that information.

	// TODO: sigstore's verifier handles non-ASN1 signatures (namely IEEE
	// P1363). Should we support this too? Probably not...
	return ecdsa.VerifyASN1(v.pubKey, msg, sig), nil
}

type ed25519Verifier struct {
	pubKey ed25519.PublicKey
}

func (v *ed25519Verifier) Verify(msg, sig []byte, opts crypto.SignerOpts) (bool, error) {
	// ed25519.VerifyWithOptions() doesn't provide a way to distinguish
	// verification and other errors, so just disallow any non-zero options.
	// TUF doesn't support this either, so no real loss at the moment.
	if edOpts, ok := opts.(*ed25519.Options); ok && edOpts.Context != "" {
		return false, fmt.Errorf("validation of ed25519ctx is not supported")
	}
	if opts.HashFunc() != 0 {
		return false, fmt.Errorf("validation of ed25519ph is not supported")
	}
	return ed25519.Verify(v.pubKey, msg, sig), nil
}

// NewVerifier returns a [Verifier] for a given [crypto.PublicKey]. At the
// moment only RSA, ECDSA, and Ed25519 keys are supported.
func NewVerifier(pubKey crypto.PublicKey) (Verifier, error) {
	switch pubKey := pubKey.(type) {
	case ed25519.PublicKey:
		return &ed25519Verifier{pubKey: pubKey}, nil
	case *ecdsa.PublicKey:
		return &ecdsaVerifier{pubKey: pubKey}, nil
	case *rsa.PublicKey:
		return &rsaVerifier{pubKey: pubKey}, nil
	default:
		return nil, fmt.Errorf("unsupported public key type %T", pubKey)
	}
}
