// Copyright (C) 2026 Amutable GmbH

package tufext

import (
	"context"
	"encoding/hex"
	"fmt"
	"maps"
	"time"

	"github.com/opencontainers/go-digest"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/generics"
	"go.amutable.dev/quarry/internal/keystore"
)

// TargetsBuilder is a wrapper type for building a signed TUF targets.json (or
// delegated target) object.
type TargetsBuilder struct {
	inner tufmetadata.TargetsType

	// RefTime is the reference time used for calculating expiries based on
	// ExpireAfter and for calculating the time-based version number.
	//
	// TODO: Maybe we should remove these and allow the caller to manage them?
	RefTime     time.Time
	ExpireAfter time.Duration

	// Local copy of [tufmetadata.TargetsType.Delegations.Roles] so that
	// pointers returned by [AddDelegation] don't get invalidated by subsequent
	// [AddDelegation] calls.
	delegatedRoles []*tufmetadata.DelegatedRole
}

// NewTargetsBuilder constructs a new [TargetsBuilder] with default values.
func NewTargetsBuilder() *TargetsBuilder {
	return &TargetsBuilder{
		inner: tufmetadata.TargetsType{
			Type:        tufmetadata.TARGETS,
			SpecVersion: tufmetadata.SPECIFICATION_VERSION,
			Targets:     make(map[string]*tufmetadata.TargetFiles),
		},
		RefTime:     time.Now().UTC(),
		ExpireAfter: (7*24 + 6) * time.Hour, // TODO: Merge this with Transaction.expiry?
	}
}

// AddTargetFile adds a given file to the set of files in this targets role. To
// configure the target file entry you can modify the returned
// [tufmetadata.TargetFiles] reference directly.
func (builder *TargetsBuilder) AddTargetFile(filename string, size int64, hashes ...digest.Digest) (*tufmetadata.TargetFiles, error) {
	fileMeta := &tufmetadata.TargetFiles{
		Length: size,
		Hashes: make(tufmetadata.Hashes, len(hashes)),
	}
	for _, hash := range hashes {
		if err := hash.Validate(); err != nil {
			return nil, fmt.Errorf("hash %s is invalid: %w", hash, err)
		}
		// TODO: Grrr, go-tuf forces us to store the hash as a byte slice.
		digestBytes, err := hex.DecodeString(hash.Encoded())
		if err != nil {
			return nil, fmt.Errorf("hash %s has non-hex hash section: %w", hash, err)
		}
		fileMeta.Hashes[string(hash.Algorithm())] = digestBytes
	}
	builder.inner.Targets[filename] = fileMeta
	return fileMeta, nil
}

// AddDelegation creates a new delegated role with the given threshold and
// keys. To configure the delegation you can modify the returned
// [tufmetadata.DelegatedRole] reference directly.
func (builder *TargetsBuilder) AddDelegation(roleName string, threshold int, keys ...keystore.PublicKey) (*tufmetadata.DelegatedRole, error) {
	if builder.inner.Delegations == nil {
		builder.inner.Delegations = new(tufmetadata.Delegations)
	}
	if builder.inner.Delegations.SuccinctRoles != nil {
		return nil, fmt.Errorf("succinct roles unsupported")
	}
	delegations := builder.inner.Delegations

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

	// TODO: If there is already a role defined with this name, we should
	// probably return that instead, but the caller is generating a new TUF
	// targets file so they should be able to handle that themselves...

	if delegations.Keys == nil {
		delegations.Keys = make(map[string]*keystore.PublicKey, len(keys))
	}
	maps.Copy(delegations.Keys, keyMap)

	role := &tufmetadata.DelegatedRole{
		Name:      roleName,
		Threshold: threshold,
		KeyIDs:    keyIDs,
	}
	builder.delegatedRoles = append(builder.delegatedRoles, role)

	delegations.Roles = append(delegations.Roles, *role)
	return role, nil
}

// TargetsType returns a pointer to the inner [tufmetadata.TargetsType] for
// this builder, to allow for arbitrary modification.
//
// NOTE: You **MUST NOT** use both [AddDelegation] and this method to do slice
// manipulations on the delegated roles slice (such changes will be
// overwritten, and would be a poor design because it will cause pointers
// returned from [AddDelegation] to become invalid).
func (builder *TargetsBuilder) TargetsType() *tufmetadata.TargetsType {
	// Replace the slice of delegated roles with the one stored internally to
	// make sure it has the correct values.
	if builder.delegatedRoles != nil {
		if builder.inner.Delegations == nil {
			builder.inner.Delegations = new(tufmetadata.Delegations)
		}
		delegations := builder.inner.Delegations

		delegations.Roles = make([]tufmetadata.DelegatedRole, 0, len(builder.delegatedRoles))
		for _, role := range builder.delegatedRoles {
			delegations.Roles = append(delegations.Roles, *role)
		}
	}
	return &builder.inner
}

// SignWith signs the designed targets file with the given set of keys. The
// returned [tufmetadata.Metadata] object contains a deep copy of the targets
// data, and so can be manipulated independently of this TargetsBuilder.
func (builder *TargetsBuilder) SignWith(ctx context.Context, store *keystore.Store, keys ...*keystore.GenericKey) (*tufmetadata.Metadata[tufmetadata.TargetsType], error) {
	inner := builder.TargetsType() // to regenerate delegated roles slice
	// TODO: Maybe we should just configure the defaults in NewTargetsBuilder?
	if inner.Version == 0 {
		inner.Version = builder.RefTime.UnixMilli()
	}
	if inner.Expires.IsZero() {
		inner.Expires = builder.RefTime.Add(builder.ExpireAfter)
	}

	// If there were any new keys added by the user manually (i.e., through
	// TargetsType()), make sure that they are included and GC'd as necessary.
	if err := FillRoleKeys(ctx, store, inner); err != nil {
		return nil, err
	}

	// Make a copy to make sure that any future manipulations don't mess with
	// the builder.
	innerClone, err := generics.DeepCopy(*inner)
	if err != nil {
		return nil, err
	}
	meta := &tufmetadata.Metadata[tufmetadata.TargetsType]{
		Signed:     innerClone,
		Signatures: make([]tufmetadata.Signature, 0, len(keys)),
	}
	for _, key := range keys {
		if _, err := SignRole(ctx, meta, key); err != nil {
			return nil, fmt.Errorf("cannot sign targets with key %s: %w", key, err)
		}
	}
	return meta, nil
}
