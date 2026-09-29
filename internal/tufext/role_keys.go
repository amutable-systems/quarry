// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package tufext

import (
	"context"
	"fmt"
	"iter"

	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/keystore"
)

// KeyedRoles is the set of TUF types which contain delegations to keys.
type KeyedRoles interface {
	tufmetadata.RootType | tufmetadata.TargetsType
}

// iterRoleKeys is a helper for writing functions that need to modify the
// top-level key map and iterate over a delegator role's keyids.
func iterRoleKeys[T KeyedRoles](meta *T) (*map[string]*tufmetadata.Key, iter.Seq2[string, keystore.KeyID], error) {
	switch meta := any(meta).(type) {
	case *tufmetadata.RootType:
		return &meta.Keys, func(yield func(roleName string, keyID keystore.KeyID) bool) {
			for roleName, role := range meta.Roles {
				for _, keyID := range role.KeyIDs {
					if !yield(roleName, keystore.KeyID(keyID)) {
						return
					}
				}
			}
		}, nil

	case *tufmetadata.TargetsType:
		if meta.Delegations == nil {
			// Nothing to do.
			return nil, nil, nil
		}
		if meta.Delegations.SuccinctRoles != nil {
			// TODO: These would actually be easy to support here but better to
			// keep them uniformly unsupported for now.
			return nil, nil, fmt.Errorf("succinct roles are currently unsupported")
		}
		return &meta.Delegations.Keys, func(yield func(roleName string, keyID keystore.KeyID) bool) {
			for _, role := range meta.Delegations.Roles {
				for _, keyID := range role.KeyIDs {
					if !yield(role.Name, keystore.KeyID(keyID)) {
						return
					}
				}
			}
		}, nil

	default:
		panic(fmt.Sprintf("unreachable code -- %T is not a keyed role", meta))
	}
}

// GCRoleKeys takes any [KeyedRoles] role and garbage-collects any keys in the
// top-level key list that are not referenced by key-id in any delegated role.
func GCRoleKeys[T KeyedRoles](meta *T) error {
	keySlot, keyIDs, err := iterRoleKeys(meta)
	if err != nil {
		return err
	}
	if keySlot == nil || keyIDs == nil {
		// Nothing to do.
		return nil
	}
	keys := make(map[string]*tufmetadata.Key, len(*keySlot))
	for roleName, keyID := range keyIDs {
		key, ok := (*keySlot)[string(keyID)]
		if !ok {
			return fmt.Errorf("key %s referenced by role %s but not in the key set", keyID, roleName)
		}
		// Only copy keys that are actually referenced.
		keys[string(keyID)] = key
	}
	*keySlot = keys
	return nil
}

// FillRoleKeys fills any missing keys in a [KeyedRoles] from the given
// [keystore.Store]. This operation also implicitly does a [GCRoleKeys].
func FillRoleKeys[T KeyedRoles](ctx context.Context, store *keystore.Store, meta *T) error {
	keySlot, keyIDs, err := iterRoleKeys(meta)
	if err != nil {
		return err
	}
	if keySlot == nil || keyIDs == nil {
		// Nothing to do.
		return nil
	}
	keys := make(map[string]*tufmetadata.Key, len(*keySlot))
	for roleName, keyID := range keyIDs {
		key, ok := (*keySlot)[string(keyID)]
		if !ok {
			genericKey, err := store.GetKey(ctx, keyID)
			if err != nil {
				return fmt.Errorf("key %s referenced by role %s but cannot be retreived from key store: %w", keyID, roleName, err)
			}
			key = &genericKey.Public
		}
		// Only copy keys that are actually referenced.
		keys[string(keyID)] = key
	}
	*keySlot = keys
	return nil
}
