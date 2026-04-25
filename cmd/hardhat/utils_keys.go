// Copyright (C) 2026 Amutable GmbH

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"

	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/keystore"
)

// parsePublicKey takes public key specifications of the form <type>:<key> *or*
// [keyid:]<keyid> and returns the corresponding public key.
func parsePublicKey(ctx context.Context, store *keystore.Store, keySpec string) (*keystore.PublicKey, error) {
	parts := strings.SplitN(keySpec, ":", 2)
	// <keyid>
	if len(parts) == 1 {
		parts = append([]string{"keyid"}, parts...)
	}
	keyType, key := parts[0], parts[1]

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

	// TODO: RSA.

	default:
		return nil, fmt.Errorf("unsupported public key type %s", keyType)
	}
}
