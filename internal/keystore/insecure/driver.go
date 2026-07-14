//go:build insecure

// Copyright (C) 2026 Amutable GmbH

// Package insecure implements a very insecure [keystore.Driver] with raw
// PKCS#8-encoded private keys. This driver is INSECURE and should only be used
// for TESTING.
package insecure

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/cryptoext"
	"go.amutable.dev/quarry/internal/keystore"
)

// defaultRSABits is the RSA modulus length used when the caller asks for
// an RSA key without specifying a size.
const defaultRSABits = 3072

type driver struct{}

func (d *driver) Name() string { return "insecure" }

// GenerateKey generates a new key using this driver. The keytype is taken
// from [keystore.Resolver.KeyTypeName], with ed25519 as the default.
func (d *driver) GenerateKey(_ context.Context, res *keystore.Resolver) (_ *keystore.GenericKey, Err error) {
	defer func() {
		if Err != nil {
			Err = fmt.Errorf("keystore driver %s: %w", d.Name(), Err)
		}
	}()

	kt := res.KeyTypeName()
	if kt == "" {
		kt = tufmetadata.KeyTypeEd25519
	}

	var privKey crypto.PrivateKey
	switch kt {
	case tufmetadata.KeyTypeEd25519:
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("ed25519 key generation: %w", err)
		}
		privKey = k
	case tufmetadata.KeyTypeECDSA_SHA2_P256:
		var esState keystore.ECDSAState
		if err := keystore.ApplyOptions(res, &esState); err != nil {
			return nil, err
		}
		curve := esState.Curve
		if curve == nil {
			curve = elliptic.P256()
		}
		k, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("ECDSA %s key generation: %w", curve.Params().Name, err)
		}
		privKey = k
	case tufmetadata.KeyTypeRSASSA_PSS_SHA256:
		var rsState keystore.RSAState
		if err := keystore.ApplyOptions(res, &rsState); err != nil {
			return nil, err
		}
		bits := rsState.Bits
		if bits == 0 {
			bits = defaultRSABits
		}
		k, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, fmt.Errorf("RSA-%d key generation: %w", bits, err)
		}
		privKey = k
	default:
		return nil, fmt.Errorf("%w: %q", keystore.ErrUnsupportedKeyType, kt)
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
