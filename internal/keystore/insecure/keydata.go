//go:build insecure

// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package insecure

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"

	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/cryptoext"
	"go.amutable.dev/quarry/internal/keystore"
)

// The key data is stored as an ASN.1-encoded form of the key. At the moment
// this is just PKCS#8, but PKCS#5 (PBES2) could be supported by just
// marshalling into a different structure.
type keyData []byte

func parseGenericKey(key *keystore.GenericKey) (crypto.PrivateKey, error) {
	// Sanity check.
	if key.Driver != Driver.Name() {
		return nil, fmt.Errorf("[internal error] cannot parse %q driver key", key.Driver)
	}
	pubKey, err := key.Public.ToPublicKey()
	if err != nil {
		return nil, fmt.Errorf("[internal error] cannot compute crypto.PublicKey for generic key: %w", err)
	}
	keyID, err := key.Public.ID()
	if err != nil {
		return nil, fmt.Errorf("[internal error] cannot compute ID for generic key: %w", err)
	}

	var keyData keyData
	if err := json.Unmarshal(key.Data, &keyData); err != nil {
		return nil, fmt.Errorf("failed to parse JSON key data: %w", err)
	}

	privKey, err := x509.ParsePKCS8PrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#8 key data: %w", err)
	}

	// Sanity check to make sure that the parsed key actually matches the key
	// type and public key included in the generic section of GenericKey. This
	// is done implicitly by using the stdlib equal check.
	checkPubKey := privKey.(cryptoext.CommonPrivateKey).Public().(cryptoext.CommonPublicKey) //nolint:forcetypeassert // guaranteed by the stdlib
	if !checkPubKey.Equal(pubKey) {
		err := fmt.Errorf("saved public key for key id %s (%v) does not match private key", keyID, key.Public)
		checkTufKey, err2 := tufmetadata.KeyFromPublicKey(checkPubKey)
		if err2 != nil {
			return nil, fmt.Errorf("%w: unsupported public key type %T: %w", err, checkPubKey, err2)
		}
		checkKeyID, err2 := checkTufKey.ID()
		if err2 != nil {
			return nil, fmt.Errorf("%w: cannot compute ID for public key type %T: %w", err, checkPubKey, err2)
		}
		return nil, fmt.Errorf("%w: private key is id %s (%v)", err, checkKeyID, checkTufKey)
	}
	return privKey, nil
}

func toGenericKey(privKey crypto.PrivateKey) (*keystore.GenericKey, error) {
	keyData, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to PKCS#8 marshal private key: %w", err)
	}

	keyDataJSON, err := json.Marshal(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to JSON marshal private key: %w", err)
	}

	pubKey := privKey.(cryptoext.CommonPrivateKey).Public() //nolint:forcetypeassert // guaranteed by the stdlib
	tufKey, err := tufmetadata.KeyFromPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("unsupported public key type %T: %w", pubKey, err)
	}

	return &keystore.GenericKey{
		Driver: Driver.Name(),
		Public: *tufKey,
		Data:   json.RawMessage(keyDataJSON),
	}, nil
}
