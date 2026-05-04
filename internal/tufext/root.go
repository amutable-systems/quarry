// Copyright (C) 2026 Amutable GmbH

package tufext

import (
	"context"
	"fmt"
	"maps"
	"sync"
	"time"

	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/generics"
	"go.amutable.dev/quarry/internal/keystore"
	"go.amutable.dev/quarry/internal/keystore/keyopts"
)

// RootBuilder is a wrapper type for building an initial TUF root.json object.
type RootBuilder struct {
	mu sync.Mutex

	inner tufmetadata.RootType

	// RefTime is the reference time used for calculating expiries based on
	// ExpireAfter.
	//
	// TODO: Maybe we should remove these and allow the caller to manage them?
	RefTime     time.Time
	ExpireAfter time.Duration

	// Options for configurating the on-demand generation of keys in Sign.
	GenerateKeyDriver string
	GenerateKeyOpts   []keyopts.GenerateOption
}

// NewRootBuilder constructs a new [RootBuilder] with default values.
func NewRootBuilder() *RootBuilder {
	return &RootBuilder{
		inner:             DefaultRoot().Signed,
		RefTime:           time.Now().UTC(),
		ExpireAfter:       2 * 365 * 24 * time.Hour, // TODO: Merge this with Transaction.expiry?
		GenerateKeyDriver: keystore.DefaultDriver,
	}
}

// addRole is the internal implementation of [RootBuilder.AddRole].
// Must be called with builder.mu held!
func (builder *RootBuilder) addRole(roleName string, threshold int, keys ...keystore.PublicKey) (*tufmetadata.Role, error) {
	// TODO: Should we generate additional keys if there are fewer than the
	// threshold? hardhat open-codes this but it might be a useful thing to
	// do...
	if threshold <= 0 || len(keys) < threshold {
		return nil, fmt.Errorf("threshold %d is invalid with %d keys", threshold, len(keys))
	}

	keyMap := make(map[string]*keystore.PublicKey, len(keys))
	keyIDs := make([]string, 0, len(keys))
	for _, key := range keys {
		keyID, err := key.ID()
		if err != nil {
			return nil, fmt.Errorf("cannot compute keyid: %w", err)
		}
		keyMap[keyID] = &key
		keyIDs = append(keyIDs, keyID)
	}
	role := &tufmetadata.Role{
		Threshold: threshold,
		KeyIDs:    keyIDs,
	}

	maps.Copy(builder.inner.Keys, keyMap)
	builder.inner.Roles[roleName] = role
	return role, nil
}

// AddRole configures the given role to use the given set of keys.
//
// TODO: Should we return the old value if we're replacing it...?
func (builder *RootBuilder) AddRole(roleName string, threshold int, keys ...keystore.PublicKey) (*tufmetadata.Role, error) {
	builder.mu.Lock()
	defer builder.mu.Unlock()

	return builder.addRole(roleName, threshold, keys...)
}

// RootType returns the inner partially-built root.json structure for further
// manipulation.
//
// While [RootBuilder] is safe against racing access, the returned type is not
// and so callers will need to serialise access against external accesses *and*
// with [RootBuilder] operations.
func (builder *RootBuilder) RootType() *tufmetadata.RootType {
	return &builder.inner
}

// Sign self-signs the built root.json with the set of root keys (as well as
// any additional keys provided). If any role is missing keys, new keys are
// generated on-demand (the default threshold of roles is 1). The returned
// [tufmetadata.Metadata] object contains a deep copy of the targets data, and
// so can be manipulated independently of this RootBuilder.
func (builder *RootBuilder) Sign(ctx context.Context, store *keystore.Store, extraKeys ...*keystore.GenericKey) (_ *SignedRoot, _ []keystore.KeyID, Err error) {
	inner := builder.RootType()

	builder.mu.Lock()
	defer builder.mu.Unlock()

	// TODO: Maybe we should just configure the defaults in NewRootBuilder?
	if inner.Expires.IsZero() {
		inner.Expires = builder.RefTime.Add(builder.ExpireAfter)
	}

	// Make sure that every core role has an associated key. If they don't,
	// generate a new key with a threshold of 1. This matches the logic from
	// [Transaction.rotateRoleKeys].
	var newKeyIDs []keystore.KeyID
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
	for _, roleName := range tufmetadata.TOP_LEVEL_ROLE_NAMES {
		if role := builder.inner.Roles[roleName]; role != nil {
			continue // role is already defined
		}
		newKeyID, newKey, err := store.GenerateKey(ctx, builder.GenerateKeyDriver, builder.GenerateKeyOpts...)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot generate default key for role %s: %w", roleName, err)
		}
		newKeyIDs = append(newKeyIDs, newKeyID)
		if _, err := builder.addRole(roleName, 1, newKey.Public); err != nil {
			return nil, nil, fmt.Errorf("cannot add default key %s to role %s: %w", newKeyID, roleName, err)
		}
	}
	rootThreshold := inner.Roles[tufmetadata.ROOT].Threshold

	// If there were any new keys added by the user manually (i.e., through
	// RootType()), make sure that they are included and GC'd as necessary.
	if err := FillRoleKeys(ctx, store, inner); err != nil {
		return nil, nil, err
	}

	// Make a copy to make sure that any future manipulations don't mess with
	// the builder.
	innerClone, err := generics.DeepCopy(*inner)
	if err != nil {
		return nil, nil, err
	}
	meta := &SignedRoot{
		Signed:     innerClone,
		Signatures: make([]tufmetadata.Signature, 0, rootThreshold+len(extraKeys)),
	}

	// We first sign with all of the extraKeys -- the caller might be managing
	// GenericKeys themselves and thus have included all the necessary signing
	// keys there.
	validSignatures := make(map[keystore.KeyID]struct{}, rootThreshold+len(extraKeys))
	for _, key := range extraKeys {
		sig, err := SignRole(ctx, meta, key)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot sign root with key %s: %w", key, err)
		}
		validSignatures[keystore.KeyID(sig.KeyID)] = struct{}{}
	}
	// Now sign with all of the listed key IDs in the root role, *if* there is
	// no such signature already.
	for _, keyID := range inner.Roles[tufmetadata.ROOT].KeyIDs {
		keyID := keystore.KeyID(keyID)
		if _, hasSig := validSignatures[keyID]; hasSig {
			continue
		}
		key, err := store.GetKey(ctx, keyID)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot get key %s to self-sign root: %w", keyID, err)
		}
		if _, err := SignRole(ctx, meta, key); err != nil {
			return nil, nil, fmt.Errorf("cannot self-sign root with key %s: %w", key, err)
		}
		validSignatures[keyID] = struct{}{}
	}
	return meta, newKeyIDs, nil
}
