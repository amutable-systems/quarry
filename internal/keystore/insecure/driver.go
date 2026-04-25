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
	"go.amutable.dev/quarry/internal/keystore/keyopts"
)

type driver struct{}

func (d *driver) Name() string { return "insecure" }

// GenerateKey generates a new key using this driver.
func (d *driver) GenerateKey(_ context.Context, opts ...keyopts.GenerateOption) (*keystore.GenericKey, error) {
	if len(opts) != 0 {
		panic("TODO: implement GenerateOption")
	}
	// TODO: Make this configurable (with GenerateOption). For now, just
	// default to ed25519.
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("keystore driver %s: key generation failed: %w", d.Name(), err)
	}
	return toGenericKey(privKey)
}

// ImportKey imports an existing key into the driver.
func (d *driver) ImportKey(_ context.Context, key any, opts ...keyopts.ImportOption) (*keystore.GenericKey, error) {
	if len(opts) != 0 {
		panic("TODO: implement ImportOption")
	}
	privKey, ok := key.(cryptoext.CommonPrivateKey)
	if !ok {
		return nil, fmt.Errorf("keystore driver %s: unsupported private key %T", d.Name(), key)
	}
	return toGenericKey(privKey)
}

// ExportKey exports a key from the driver.
func (d *driver) ExportKey(ctx context.Context, key *keystore.GenericKey, opts ...keyopts.ExportOption) (any, error) {
	if len(opts) != 0 {
		panic("TODO: implement ExportOption")
	}
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
