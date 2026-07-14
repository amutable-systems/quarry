// Copyright (C) 2026 Amutable GmbH

package tufrepo

import (
	"context"
	"errors"
	"fmt"

	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/keystore"
	"go.amutable.dev/quarry/internal/tufext"
)

// ReplaceKeys replaces the set of keys defined for the given role with the
// provided [tufmetadata.Role].
func ReplaceKeys(roleName string, keys map[keystore.KeyID]*keystore.PublicKey, role tufmetadata.Role) (TxnOp, error) {
	if !tufext.IsCoreRole(roleName) {
		// TODO: Implement the replacement of delegated role keys.
		return nil, fmt.Errorf("cannot replace keys for role %q: delegated role key replacement is not implemented", roleName)
	}
	return NewTxnOp(
		fmt.Sprintf("replace keys for role %s", roleName),
		func(ctx context.Context, tx *Transaction) error {
			root, err := tx.RootRoleData(ctx)
			if err != nil {
				return err
			}
			root.Signed.Roles[roleName] = &role
			for _, keyID := range role.KeyIDs {
				tufKey, ok := keys[keystore.KeyID(keyID)]
				if !ok {
					return fmt.Errorf("public key not available for new key %s", keyID)
				}
				root.Signed.Keys[keyID] = tufKey
			}
			if err := tufext.GCRoleKeys(&root.Signed); err != nil {
				return err
			}
			return tx.UpdateRoleData(tufmetadata.ROOT, root)
		},
	), nil
}

// rotateRoleKeys rotates a roles' keys with a new set of keys generated with
// the same parameters.
//
// The provided options can either be [keystore.RotateOption]s (used when a key
// is managed by the given [keystore.Store]) or [keystore.GenerateOption] (used
// when a key is not available and thus a new key needs to be generated).
func (tx *Transaction) rotateRoleKeys(ctx context.Context, roleName string, store *keystore.Store, opts ...any) (_ []keystore.KeyID, Err error) {
	// Copy the option sets (note that some options may be valid generation and
	// rotation options).
	var (
		rotateOpts   = make([]keystore.RotateOption, 0, len(opts))
		generateOpts = make([]keystore.GenerateOption, 0, len(opts))
	)
	for _, opt := range opts {
		rotateOpt, isRotateOpt := opt.(keystore.RotateOption)
		if isRotateOpt {
			rotateOpts = append(rotateOpts, rotateOpt)
		}
		generateOpt, isGenerateOpt := opt.(keystore.GenerateOption)
		if isGenerateOpt {
			generateOpts = append(generateOpts, generateOpt)
		}
		if !isRotateOpt && !isGenerateOpt {
			return nil, fmt.Errorf("unsupported option type %T", opt)
		}
	}

	root, err := tx.RootRoleData(ctx)
	if err != nil {
		return nil, err
	}

	role, ok := root.Signed.Roles[roleName]
	if !ok {
		return nil, fmt.Errorf("unknown role %q", roleName)
	}

	newKeyIDs := make([]keystore.KeyID, 0, len(role.KeyIDs))
	defer func() { //nolint:contextcheck // ctx is not passed intentionally
		// Make sure to clean up any generated keys in case of an error.
		if Err != nil {
			// TODO: We want to force the removal even if the context was
			// cancelled, but we might also want to have some kind of deadline
			// here just in case? Or maybe we should use context.WithoutCancel?
			ctx := context.TODO()
			for _, keyID := range newKeyIDs {
				_ = store.UnlinkKey(ctx, keyID)
			}
			newKeyIDs = nil
		}
	}()
	for idx, oldKeyID := range role.KeyIDs {
		// If the key is locally managed, we can rotate the keys.
		newKeyID, newKey, err := store.RotateKey(ctx, keystore.KeyID(oldKeyID), rotateOpts...)
		if errors.Is(err, keystore.ErrNoSuchKey) {
			// The key is not locally managed, we need to generate a new one...
			// TODO: If this is a root key we should probably error out here...
			// Store.GenerateKey falls back to keystore.DefaultDriver when no
			// keystore.WithDriver option is supplied, matching the previous
			// explicit behavior.
			newKeyID, newKey, err = store.GenerateKey(ctx, generateOpts...)
		}
		if err != nil {
			return nil, fmt.Errorf("could not generate a new key to replace key %s: %w", oldKeyID, err)
		}

		root.Signed.Keys[string(newKeyID)] = &newKey.Public
		role.KeyIDs[idx] = string(newKeyID)
		newKeyIDs = append(newKeyIDs, newKeyID)
	}
	if err := tufext.GCRoleKeys(&root.Signed); err != nil {
		return nil, err
	}
	if err := tx.UpdateRoleData(tufmetadata.ROOT, root); err != nil {
		return nil, err
	}
	return newKeyIDs, nil
}

// RotateRoleKeys rotates a roles' keys with a new set of keys generated with
// the same parameters (akin to [keystore.Store.RotateKey]). In order to
// retrieve the new [keystore.KeyID]s you will need to fetch the information
// from [Transaction.RootRoleData] separately.
//
// The provided options can either be [keystore.RotateOption]s (used when a key
// is managed by the given [keystore.Store]) or [keystore.GenerateOption] (used
// when a key is not available and thus a new key needs to be generated).
//
// This method is NOT recommended for rotation of root keys, because it
// requires that the root keys be stored in the local keystore for an
// indeterminate period of time. Replacing the root keys should be done on an
// offline machine (where the new root is signed) and then included in the
// repository using [Transaction.UpdateRoleData].
func RotateRoleKeys(roleName string, store *keystore.Store, opts ...any) (TxnOp, error) {
	if !tufext.IsCoreRole(roleName) {
		// TODO: Implement the replacement of delegated role keys.
		return nil, fmt.Errorf("cannot rotate keys for role %q: delegated role key rotation is not implemented", roleName)
	}
	return NewTxnOp(
		fmt.Sprintf("rotate keys for role %s", roleName),
		func(ctx context.Context, tx *Transaction) error {
			_, err := tx.rotateRoleKeys(ctx, roleName, store, opts...)
			// TODO: We probably want to provide this information to the
			// manager via a channel or something? Otherwise, if the
			// transaction fails later (or is retried) there is no real way to
			// clean up the old keys.
			return err
		},
	), nil
}
