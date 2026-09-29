// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package keystore

import (
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/cryptoext"
)

// PublicKey is the TUF representation of public keys ("KEY").
type PublicKey = tufmetadata.Key

// KeyType is a combination of the TUF "KEYTYPE" and "SCHEME" values, to allow
// for the marking of key types without including the public key portion.
type KeyType struct {
	Type   string `json:"keytype"`
	Scheme string `json:"scheme"`
}

// PublicKeyType returns the [KeyType] for a given [tufmetadata.Key] public
// key.
func PublicKeyType(pk PublicKey) KeyType {
	return KeyType{
		Type:   pk.Type,
		Scheme: pk.Scheme,
	}
}

// PublicKeyVerifier returns a [cryptoext.Verifier] for the given public key.
func PublicKeyVerifier(tufKey *PublicKey) (cryptoext.Verifier, error) {
	keyID, err := tufKey.ID()
	if err != nil {
		keyID = string(BadKeyID)
	}
	pubKey, err := tufKey.ToPublicKey()
	if err != nil {
		return nil, fmt.Errorf("could not convert key %s into crypto.PublicKey: %w", keyID, err)
	}
	return cryptoext.NewVerifier(pubKey)
}

// SignerOpts returns the necessary signing options for the given key type.
//
// When using [crypto.SignMessage] (or calling [crypto.Signer.Sign] directly),
// callers must hash their message using the hash functions returned by
// HashFunc (note that a zero-valued [crypto.Hash] indicates that you must pass
// the unhashed message to SignMessage).
func (k KeyType) SignerOpts() crypto.SignerOpts {
	switch k.Scheme {
	case tufmetadata.KeySchemeEd25519:
		// stock ed25519 signing takes the entire (unhashed) message
		return crypto.Hash(0)
	case tufmetadata.KeySchemeECDSA_SHA2_P256,
		tufmetadata.KeySchemeECDSA_SHA2_P384:
		// ecdsa-sha2 uses stock sha256
		return crypto.SHA256
	case tufmetadata.KeySchemeRSASSA_PSS_SHA256:
		// rsassa-pss requires a specific crypto.SignerOpts type
		return &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto, // same as sigstore's signer
			Hash:       crypto.SHA256,
		}
	}
	return nil
}

// These are the only [KeyType]s that are both defined in the TUF specification
// and are supported by the go-tuf logic for key handling (they hard-code each
// supported key-type).
var (
	KeyTypeEd25519           = KeyType{Type: tufmetadata.KeyTypeEd25519, Scheme: tufmetadata.KeySchemeEd25519}
	KeyTypeECDSA_SHA2_P256   = KeyType{Type: tufmetadata.KeyTypeECDSA_SHA2_P256, Scheme: tufmetadata.KeySchemeECDSA_SHA2_P256}     //nolint:revive // name is based on TUF name
	KeyTypeRSASSA_PSS_SHA256 = KeyType{Type: tufmetadata.KeyTypeRSASSA_PSS_SHA256, Scheme: tufmetadata.KeySchemeRSASSA_PSS_SHA256} //nolint:revive // name is based on TUF name
)

// GenericKey is the top-level structure used for referencing a private key
// managed by some keystore driver. This is the primary thing that external
// packages should interface with.
type GenericKey struct {
	Driver string          `json:"driver"`
	Public PublicKey       `json:"publickey"`
	Data   json.RawMessage `json:"keydata,omitzero"`
}

// String returns an informative string about the key (usually its [KeyId]).
func (k *GenericKey) String() string {
	return string(k.niceID())
}

// KeyType returns the [KeyType] subset of a TUF "KEY" structure. It is
// shorthand for [PublicKeyType].
func (k *GenericKey) KeyType() KeyType {
	return PublicKeyType(k.Public)
}

func (k *GenericKey) driver() (Driver, error) {
	driver, ok := GetDriver(k.Driver)
	if !ok {
		return nil, fmt.Errorf("no such driver %q", k.Driver)
	}
	return driver, nil
}

// KeyID is a TUF key id string for a public key. All keys are referenced by
// this ID in this package.
type KeyID string

// BadKeyID is an invalid [KeyID] that is returned by functions when an error
// occurs.
const BadKeyID KeyID = "<bad key>"

// ID returns the [KeyID] for the given key, or [BadKeyID] if the key id cannot
// be derived from this [GenericKey].
func (k *GenericKey) ID() (KeyID, error) {
	id, err := k.Public.ID()
	if err != nil {
		// Make sure we always return BadKeyID for errors.
		id = string(BadKeyID)
	}
	return KeyID(id), err
}

// niceID returns the same thing as [ID], except that a dummy value is returned
// if [ID] fails. The dummy value is guaranteed to not be a valid [KeyID] so
// [KeyID.Valid] will always fail.
func (k *GenericKey) niceID() KeyID {
	id, err := k.ID()
	if err != nil {
		id = KeyID(fmt.Sprintf("<unknown key %#v>", k.Public))
	}
	return id
}

// GetSigner is just a convenience wrapper around [Driver.GetSigner]. It
// returns a [crypto.Signer] interface for the driver that this [GenericKey] is
// tied to.
func (k *GenericKey) GetSigner(ctx context.Context) (crypto.Signer, error) {
	driver, err := k.driver()
	if err != nil {
		return nil, fmt.Errorf("failed to get signer for key %s: %w", k, err)
	}
	return driver.GetSigner(ctx, k)
}
