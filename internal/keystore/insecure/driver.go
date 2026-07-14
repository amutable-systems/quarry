//go:build insecure

// Copyright (C) 2026 Amutable GmbH

// Package insecure implements a very insecure [keystore.Driver] with raw
// PKCS#8-encoded private keys. This driver is INSECURE and should only be used
// for TESTING.
package insecure

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"go.amutable.dev/quarry/internal/cryptoext"
	"go.amutable.dev/quarry/internal/keystore"
)

type driver struct{}

func (d *driver) Name() string { return "insecure" }

// GenerateKey generates a new key using this driver.
func (d *driver) GenerateKey(_ context.Context, _ *keystore.Resolver) (*keystore.GenericKey, error) {
	// TODO: Make this configurable (with options). For now, just default to
	// ed25519.
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("keystore driver %s: key generation failed: %w", d.Name(), err)
	}
	return toGenericKey(privKey)
}

// ImportKey imports an existing key into the driver.
func (d *driver) ImportKey(_ context.Context, key any, _ *keystore.Resolver) (*keystore.GenericKey, error) {
	privKey, ok := key.(cryptoext.CommonPrivateKey)
	if !ok {
		return nil, fmt.Errorf("keystore driver %s: unsupported private key %T", d.Name(), key)
	}
	return toGenericKey(privKey)
}

// ExportKey exports a key from the driver.
func (d *driver) ExportKey(ctx context.Context, key *keystore.GenericKey, _ *keystore.Resolver) (any, error) {
	// In the insecure driver, the signing interface is identical to an
	// exported key.
	return d.GetSigner(ctx, key)
}

// GetSigner takes a given [GenericKey] and produces a [crypto.Signer] which is
// backed by the driver.
func (d *driver) GetSigner(_ context.Context, key *keystore.GenericKey) (crypto.Signer, error) {
	privKey, err := parseGenericKey(key)
	if err != nil {
		return nil, fmt.Errorf("keystore driver %s: %w", d.Name(), err)
	}
	signer, ok := privKey.(crypto.Signer)
	if !ok {
		// Should never happen.
		return nil, fmt.Errorf("key type %T does not implement crypto.Signer", privKey)
	}
	return signer, nil
}

// Driver is an implementation of [keystore.Driver] with raw PKCS#8-encoded
// private keys. This driver is INSECURE and should only be used for TESTING.
var Driver keystore.Driver = &driver{}

func init() {
	keystore.MustRegisterDriver(Driver)
}
