// Copyright (C) 2026 Amutable GmbH

package tufext

import (
	"context"
	"crypto"
	"crypto/rand"
	"fmt"

	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/keystore"
)

// SignRole signs the given [tufmetadata.Metadata] object using the given
// [keystore.GenericKey].
//
// NOTE: Unlike the built-in signing support provided by go-tuf via
// [tufmetadata.Metadata.Sign], this function support the usage of
// hardware-backed private keys as long as there is a [keystore.Driver]
// implemented for the hardware keystore.
func SignRole[T tufmetadata.Roles](ctx context.Context, meta *tufmetadata.Metadata[T], key *keystore.GenericKey) (*tufmetadata.Signature, error) {
	// This implementation is heavily based on the one in go-tuf, to ensure
	// that we produce bit-for-bit compatible signatures. The main differences
	// are that we are more generic with respect to the HashFunc defined for
	// the signature scheme and the backing signature store.

	keyID, err := key.ID()
	if err != nil {
		return nil, err
	}

	signer, err := key.GetSigner(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get signer for key %s: %w", keyID, err)
	}

	signerOpts := key.KeyType().SignerOpts()
	if signerOpts == nil {
		return nil, fmt.Errorf("key %s uses a keyscheme unsupported by TUF", keyID)
	}

	payload, err := cjson.EncodeCanonical(meta.Signed)
	if err != nil {
		return nil, fmt.Errorf("failed to encode metadata to sign: %w", err)
	}

	// SignMessage will pre-compute the hash as per SignerOpts if necessary.
	//
	// TODO: We should figure out how to make the signing cancellable for
	// hardware-backed keys...
	sigBytes, err := crypto.SignMessage(signer, rand.Reader, payload, signerOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to sign with key %s: %w", keyID, err)
	}
	sig := tufmetadata.Signature{
		KeyID:     string(keyID),
		Signature: sigBytes,
	}
	meta.Signatures = append(meta.Signatures, sig)
	return &sig, nil
}
