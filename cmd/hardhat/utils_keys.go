// Copyright (C) 2026 Amutable GmbH

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/keystore"
)

// parsePublicKey takes public key specifications of the form <type>:<key> *or*
// [keyid:]<keyid> and returns the corresponding public key.
func parsePublicKey(ctx context.Context, store *keystore.Store, keySpec string) (*keystore.PublicKey, error) {
	keyType, key, hadType := strings.Cut(keySpec, ":")
	if !hadType {
		keyType, key = "keyid", keyType
	}

	switch keyType {
	case "keyid":
		keyID := keystore.KeyID(key)
		// TODO: We need a mechanism to only fetch public keys.
		key, err := store.GetKey(ctx, keyID)
		if err != nil {
			return nil, err
		}
		return &key.Public, nil

	case "ed25519", "ed":
		pubKeyBytes, err := hex.DecodeString(key)
		if err != nil {
			return nil, fmt.Errorf("parse ed25519 key bytes: %w", err)
		}
		pubKey := ed25519.PublicKey(pubKeyBytes)
		return tufmetadata.KeyFromPublicKey(pubKey)

	case "pkix":
		// Take it as a base64-encoded PKIX blob (*not* PEM encoded!).
		der, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			return nil, fmt.Errorf("decode base64 pkix blob: %w", err)
		}
		pubKey, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			return nil, fmt.Errorf("parse pkix key: %w", err)
		}
		return tufmetadata.KeyFromPublicKey(pubKey)

	// TODO: RSA.

	default:
		return nil, fmt.Errorf("unsupported public key type %s", keyType)
	}
}
