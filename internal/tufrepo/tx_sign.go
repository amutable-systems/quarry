// Copyright (C) 2026 Amutable GmbH

package tufrepo

import (
	"context"
	"crypto"
	_ "crypto/sha256" // crypto.SHA256
	"errors"
	"fmt"
	"io/fs"
	"iter"
	"maps"
	"slices"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/cryptoext"
	"go.amutable.dev/quarry/internal/generics"
	"go.amutable.dev/quarry/internal/keystore"
	"go.amutable.dev/quarry/internal/tufext"
)

// tufDelegatorType is an interface version of the methods needed from
// [*tufmetadata.Metadata].
type tufDelegatorType interface {
	VerifyDelegate(delegatedRole string, delegatedMetadata any) error
}

// findRoleDelegators returns the set of roles which need to validate the given
// role name in order for the repository to be valid.
func (tx *Transaction) findRoleDelegators(ctx context.Context, roleName string) iter.Seq2[tufDelegatorType, error] {
	return generics.ErrorIter(func(yield func(tufDelegatorType) bool) error {
		if roleName == tufmetadata.ROOT && tx.newRoot != nil {
			// root.json needs to be signed by the original and new roots.
			// However, if tx.root is nil then we are coming from InitTxn and
			// there is no previous root.
			if tx.root != nil && !yield(tx.root) {
				return nil
			}
		}
		if tufext.IsCoreRole(roleName) {
			// The newest root matters for all top-level roles.
			root, err := tx.RootRoleData(ctx)
			if err != nil {
				return err
			}
			yield(root)
			return nil // top-level roles cannot be treated like delegated targets
		}

		// In theory, the same delegated role could be delegated to by more
		// than one so we need to collect them all.
		var matches int
		roleMatches := func(role tufmetadata.DelegatedRole) bool {
			return role.Name == roleName
		}
		for _, role := range tx.targets {
			delegations := role.Signed.Delegations
			if delegations == nil {
				continue
			}
			if !generics.SeqAny(slices.Values(delegations.Roles), roleMatches) {
				continue
			}
			if !yield(role) {
				return nil
			}
			matches++
		}
		// There must be at least one delegator for this role, otherwise we
		// might incorrectly assume that an object is signed.
		if matches < 1 {
			return fmt.Errorf("could not find any delegators for role %s", roleName)
		}
		return nil
	})
}

type tufKeyVerifier struct {
	verifier cryptoext.Verifier
	keyType  keystore.KeyType
}

type keyQuorum struct {
	keys      map[keystore.KeyID]tufKeyVerifier
	threshold int
}

func collateKeys(knownKeys map[string]*tufmetadata.Key, keyIDs []string) (map[keystore.KeyID]tufKeyVerifier, error) {
	pubKeys := make(map[keystore.KeyID]tufKeyVerifier, len(keyIDs))
	for _, keyID := range keyIDs {
		tufKey, ok := knownKeys[keyID]
		if !ok {
			return nil, fmt.Errorf("signing key %s referenced but no associated TUF public key data found", keyID)
		}
		verifier, err := keystore.PublicKeyVerifier(tufKey)
		if err != nil {
			return nil, fmt.Errorf("signing key %s cannot be parsed as crypto.PublicKey: %w", keyID, err)
		}
		pubKeys[keystore.KeyID(keyID)] = tufKeyVerifier{
			verifier: verifier,
			keyType:  keystore.PublicKeyType(*tufKey),
		}
	}
	return pubKeys, nil
}

func computeDelegatorKeyQuorums(delegator any, roleName string) iter.Seq2[keyQuorum, error] {
	return generics.ErrorIter(func(yield func(keyQuorum) bool) error {
		switch delegator := delegator.(type) {
		case *tufext.SignedRoot:
			root := delegator
			role, ok := root.Signed.Roles[roleName]
			if !ok {
				return fmt.Errorf("unknown role %s: %w", roleName, fs.ErrNotExist)
			}
			pubKeys, err := collateKeys(root.Signed.Keys, role.KeyIDs)
			if err != nil {
				return fmt.Errorf("role %s has invalid key data: %w", roleName, err)
			}
			kq := keyQuorum{
				keys:      pubKeys,
				threshold: role.Threshold,
			}
			// Root-delegated roles only have a single quorum.
			yield(kq)
			return nil

		case *tufext.SignedTargets:
			delegations := delegator.Signed.Delegations
			if delegations == nil || len(delegations.Roles) < 1 {
				// NOTE: Should not be reachable -- findRoleDelegators will by
				// definition not find a delegator for a role if it has no
				// delegations.
				return fmt.Errorf("targets role has no delegations")
			}

			var matches int
			for _, role := range delegations.Roles {
				if role.Name != roleName {
					continue
				}
				pubKeys, err := collateKeys(delegations.Keys, role.KeyIDs)
				if err != nil {
					return fmt.Errorf("role %s has invalid key data: %w", roleName, err)
				}
				kq := keyQuorum{
					keys:      pubKeys,
					threshold: role.Threshold,
				}
				if !yield(kq) {
					return nil
				}
				matches++
			}
			// There must be at least one delegation for this role, otherwise
			// we might incorrectly assume that an object is signed.
			//
			// NOTE: Should not be reachable for the same reason as above --
			// findRoleDelegators will not yield a delegator without at least
			// one delegation matching this role name.
			if matches < 1 {
				return fmt.Errorf("targets role has no delegations for role %s", roleName)
			}
			return nil

		default:
			return fmt.Errorf("invalid delegator type %T for role %s", delegator, roleName)
		}
	})
}

// checkRoleSignatures returns whether the given data (for the given role name)
// has valid signatures. If the signatures are invalid, this method returns
// (false, nil).
func (tx *Transaction) checkRoleSignatures(ctx context.Context, roleName string, roleData any) (_ bool, Err error) {
	for delegator, err := range tx.findRoleDelegators(ctx, roleName) {
		if err != nil {
			return false, fmt.Errorf("failed to find delegator for role %s: %w", roleName, err)
		}
		err := delegator.VerifyDelegate(roleName, roleData)
		if errors.Is(err, tufext.ErrUnsignedMetadata) {
			// Signature failure.
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("internal error while trying to verify signatures for role %s: %w", roleName, err)
		}
	}
	return true, nil
}

func signRoleWith[T tufmetadata.Roles](ctx context.Context, store *keystore.Store, meta *tufmetadata.Metadata[T], quorum keyQuorum) error {
	validSignatures := make(map[keystore.KeyID]struct{})

	// TODO: Should we cache this in signRole()...?
	payload, err := cjson.EncodeCanonical(meta.Signed)
	if err != nil {
		return fmt.Errorf("failed to encode metadata to sign: %w", err)
	}

	// Empty the signatures so we can re-insert the valid ones while dropping
	// outdated ones efficiently.
	oldSigs := meta.Signatures
	meta.Signatures = make([]tufmetadata.Signature, 0, quorum.threshold+len(oldSigs))

	// First try to re-sign with any pre-existing signatures (and if a
	// signature is already valid, just keep it). While we're at it, remove any
	// invalid signatures.
	for _, oldSig := range oldSigs {
		keyID := keystore.KeyID(oldSig.KeyID)

		// Is this quorum aware of the public key for this signature?
		if tufVerifier, known := quorum.keys[keyID]; known {
			verifier := tufVerifier.verifier
			opts := tufVerifier.keyType.SignerOpts()

			signed, err := cryptoext.VerifyMessage(verifier, payload, oldSig.Signature, opts)
			if err == nil && signed {
				meta.Signatures = append(meta.Signatures, oldSig)
				validSignatures[keyID] = struct{}{}
				continue
			}
			// If we know enough to validate the key but the validation errored
			// out, we should just drop the key. But don't make this a fatal
			// error.
			// TODO: Add logging...
		}

		// If this is a key we have locally, we may as well re-sign with it.
		if key, err := store.GetKey(ctx, keyID); err == nil {
			if _, err := tufext.SignRole(ctx, meta, key); err != nil {
				// TODO: Should this just be logged instead?
				return fmt.Errorf("unable to sign with keystore key %s: %w", keyID, err)
			}
			// NOTE: SignRole updates meta.Signatures itself
			if _, known := quorum.keys[keyID]; known {
				// Only add the set of trusted signatures if it is part of this
				// quorum.
				validSignatures[keyID] = struct{}{}
			}
			continue
		}

		// Fallback to re-inserting the signature if we cannot verify nor sign
		// with the key id, it must've been signed by a different key store or
		// mechanism.
		meta.Signatures = append(meta.Signatures, oldSig)
	}

	// We already satisfy this quorum, nothing left to do.
	if len(validSignatures) >= quorum.threshold {
		return nil
	}

	// Finally, go through the set of keys defined by the role and try to sign
	// with those.
	for keyID := range quorum.keys {
		if _, ok := validSignatures[keyID]; ok {
			// Already signed with this key.
			continue
		}

		if key, err := store.GetKey(ctx, keyID); err == nil {
			if _, err := tufext.SignRole(ctx, meta, key); err != nil {
				// TODO: Should this just be logged instead?
				return fmt.Errorf("unable to sign with keystore key %s: %w", keyID, err)
			}
			validSignatures[keyID] = struct{}{}
		}

		// TODO: Should we actually break out here early or just sign with as
		// many keys as we can?
		if len(validSignatures) >= quorum.threshold {
			break
		}
	}
	if len(validSignatures) < quorum.threshold {
		return fmt.Errorf("could not sign role: only could produce %d of required %d signatures", len(validSignatures), quorum.threshold)
	}
	return nil
}

// signRoleGeneric is just a wrapper around [signRoleWith] that takes [any]
// rather than [*tufmetadata.Metadata] as an argument to allow for generic
// handling.
func signRoleGeneric(ctx context.Context, store *keystore.Store, meta any, quorum keyQuorum) error {
	switch meta := meta.(type) {
	case *tufext.SignedRoot:
		return signRoleWith(ctx, store, meta, quorum)
	case *tufext.SignedTimestamp:
		return signRoleWith(ctx, store, meta, quorum)
	case *tufext.SignedSnapshot:
		return signRoleWith(ctx, store, meta, quorum)
	case *tufext.SignedTargets:
		return signRoleWith(ctx, store, meta, quorum)
	default:
		return fmt.Errorf("cannot sign unknown metadata type %T", meta)
	}
}

func (tx *Transaction) signRole(ctx context.Context, store *keystore.Store, roleName string) (Err error) {
	roleData, err := tx.RoleData(ctx, roleName)
	if err != nil {
		return fmt.Errorf("failed to fetch role %s data: %w", roleName, err)
	}

	// Before we do anything, check that we actually need to sign this role.
	// For certain roles (namely the root and targets roles) it is expected for
	// Quarry to be handed a pre-signed metafile and thus the signatures should
	// already match.
	if signed, err := tx.checkRoleSignatures(ctx, roleName, roleData); err != nil {
		return fmt.Errorf("failed to detect changes in role %s data: %w", roleName, err)
	} else if signed {
		// This role is already fully trusted, no need to do anything.
		return nil
	}

	// TODO: We probably should cache the output of findRoleDelegators.
	for delegator, err := range tx.findRoleDelegators(ctx, roleName) {
		if err != nil {
			return fmt.Errorf("failed to find delegator for role %s: %w", roleName, err)
		}
		for quorum, err := range computeDelegatorKeyQuorums(delegator, roleName) {
			if err != nil {
				return fmt.Errorf("failed to compute key quorum for role %s: %w", roleName, err)
			}
			if err := signRoleGeneric(ctx, store, roleData, quorum); err != nil {
				return fmt.Errorf("failed to sign key quorum for role %s: %w", roleName, err)
			}
		}
	}

	// TODO: Should we clear any signatures not in the set of known keys here?
	// On paper the nicest solution is to clear signatures that are no longer
	// valid but that requires us to create a list of public keys and check
	// against them all (and it's not clear what to do with key references we
	// don't have a public key for or are for the wrong role -- I guess we keep
	// them?)

	return tx.UpdateRoleData(roleName, roleData)
}

// checkNeedsBump returns whether the data for the given role in this
// transaction has been changed in a way that requires bumping its metadata.
func (tx *Transaction) checkNeedsBump(ctx context.Context, roleName string, roleData any) (_ bool, Err error) {
	ok, err := tx.checkRoleSignatures(ctx, roleName, roleData)
	if err != nil {
		return false, fmt.Errorf("failed to detect changes in role %s data: %w", roleName, err)
	}
	return !ok, nil
}

// bumpRevisions updates the version numbers of every role that has been
// changed in this transaction.
//
// TODO: This is quite ugly, especially when considering the snapshot and
// timestamp roles (which have their own version / expiry update logic in their
// update routines...).
func (tx *Transaction) bumpRevisions(ctx context.Context) (Err error) {
	timeVersion := tx.RefTime.UnixMilli()
	for roleName := range tx.dirty {
		roleData, err := tx.RoleData(ctx, roleName)
		if err != nil {
			return fmt.Errorf("failed to fetch role %s data: %w", roleName, err)
		}
		if needsBump, err := tx.checkNeedsBump(ctx, roleName, roleData); err != nil {
			return fmt.Errorf("failed to check if version bump for role %s is needed: %w", roleName, err)
		} else if !needsBump {
			// If the signed portion has not been modified we do not need to
			// bump the version and we will not need to re-sign it either.
			//
			// TODO: We almost certainly want to detect if the file is expired
			// and bump the version and expiry automatically in that case
			// (though ideally that should be configurable).
			continue
		}

		versionSlot, err := metaVersion(roleData)
		if err != nil {
			return fmt.Errorf("could not get role %s version slot: %w", roleName, err)
		}
		var newVersion int64
		if roleName == tufmetadata.ROOT {
			// root.json version numbers *must* strictly increase by one each
			// time. If tx.root == nil then we are coming from InitTxn and so
			// we do not touch the version number.
			newVersion = *versionSlot
			if tx.root != nil {
				newVersion = tx.root.Signed.Version + 1
			}
		} else {
			// TODO: Make the mechanism for updating version numbers
			// configurable. We would need to cache an old copy of snapshot to
			// make this work...
			newVersion = timeVersion
		}
		// TODO: We should probably check if a TxnOp touched the version number.
		// If the revision is newer than the old snapshot then we shouldn't
		// modify it again...
		*versionSlot = newVersion

		if err := tx.UpdateRoleData(roleName, roleData); err != nil {
			return err
		}
	}

	// If any roles that are referenced by the snapshot role were modified
	// (i.e., anything other than root and timestamp), we need to update the
	// snapshot role version.
	if generics.SeqAny(maps.Keys(tx.dirty), func(roleName string) bool {
		return roleName != tufmetadata.ROOT && roleName != tufmetadata.TIMESTAMP
	}) {
		tx.snapshot.Signed.Version = timeVersion
		tx.markDirty(tufmetadata.SNAPSHOT)
	}

	// If any roles were changed *at all*, we need to update the timestamp role
	// version. Note that while root is not linked from timestamp, Sign will
	// rotate the timestamp keys so we will need to push a new version, and our
	// atomic update scheme relies on timestamp always being updated.
	if len(tx.dirty) > 0 {
		tx.timestamp.Signed.Version = timeVersion
		tx.markDirty(tufmetadata.TIMESTAMP)
	}
	return nil
}

// Default expiries for different role types.
var (
	DefaultRootExpiry      = 2 * 365 * 24 * time.Hour // 2 years
	DefaultTimestampExpiry = (24 + 6) * time.Hour     // 1 day
	DefaultSnapshotExpiry  = DefaultTargetsExpiry     // 1 week
	DefaultTargetsExpiry   = (7*24 + 6) * time.Hour   // 1 week
)

// expiry returns the duration to use when extending the expiry for the given
// role.
//
// TODO: This should be configurable (both the expiry of individual roles but
// also the expiry when we need to bump the expiry in a transaction). We might
// even want to allow users to configure the expiries to be manually-managed...
func (tx *Transaction) expiry(roleName string) time.Duration {
	switch roleName {
	case tufmetadata.ROOT:
		return DefaultRootExpiry
	case tufmetadata.TIMESTAMP:
		return DefaultTimestampExpiry
	case tufmetadata.SNAPSHOT:
		return DefaultSnapshotExpiry
	case tufmetadata.TARGETS:
		fallthrough
	default:
		return DefaultTargetsExpiry
	}
}

func metaExpiry(meta any) (*time.Time, error) {
	switch meta := meta.(type) {
	case *tufext.SignedRoot:
		return &meta.Signed.Expires, nil
	case *tufext.SignedTimestamp:
		return &meta.Signed.Expires, nil
	case *tufext.SignedSnapshot:
		return &meta.Signed.Expires, nil
	case *tufext.SignedTargets:
		return &meta.Signed.Expires, nil
	default:
		return nil, fmt.Errorf("unsupported type %T", meta)
	}
}

// BumpExpiry is shorthand to make bumping the expiry for a role (with flexible
// policies) easier.
//
// The expiryFn closure is used to configure the new expiry, if it returns nil
// then the blob is left unmodified with its original expiry. If you return a
// non-nil new expiry, any other changes to the provided role data structure
// are also included in the updated role data.
//
// If expiryFn is nil then the default expiry is used unconditionally.
func (tx *Transaction) BumpExpiry(ctx context.Context, roleName string, expiryFn func(oldExpiry time.Time, roleData any) (*time.Time, error)) (Err error) {
	if expiryFn == nil {
		expiryFn = func(_ time.Time, _ any) (*time.Time, error) {
			expiresAfter := tx.expiry(roleName)
			newExpiry := tx.RefTime.Add(expiresAfter)
			return &newExpiry, nil
		}
	}

	roleData, err := tx.RoleData(ctx, roleName)
	if err != nil {
		return fmt.Errorf("failed to fetch role %s data: %w", roleName, err)
	}
	expiresSlot, err := metaExpiry(roleData)
	if err != nil {
		return fmt.Errorf("could not get role %s expiry slot: %w", roleName, err)
	}

	newExpiry, err := expiryFn(*expiresSlot, roleData)
	if err != nil {
		return err
	}
	if newExpiry != nil {
		*expiresSlot = *newExpiry
		if err := tx.UpdateRoleData(roleName, roleData); err != nil {
			return err
		}
	}
	return nil
}

// bumpExpiries updates the expiries of all dirty metafiles that need to be
// re-signed.
//
// TODO: This should be configurable.
//
// TODO: This is quite ugly, especially when considering the snapshot and
// timestamp roles (which have their own version / expiry update logic in their
// update routines...).
func (tx *Transaction) bumpExpiries(ctx context.Context) (Err error) {
	for roleName := range tx.dirty {
		if err := tx.BumpExpiry(ctx, roleName, func(oldExpiry time.Time, roleData any) (*time.Time, error) {
			if needsBump, err := tx.checkNeedsBump(ctx, roleName, roleData); err != nil {
				return nil, fmt.Errorf("failed to check if expiry bump for role %s is needed: %w", roleName, err)
			} else if !needsBump {
				// If the signed portion has not been modified we do not need to
				// bump the expiries and we will not need to re-sign it either.
				return nil, nil //nolint:nilnil // nil indicates no change needed
			}

			// TODO: We shouldn't update the timestamp if a TxnOp did it for us
			// already. Unfortunately, to detect this we would need to cache
			// the old version of every target file. The best we can do here is
			// not *shorten* the expiry.

			newExpiry := tx.RefTime.Add(tx.expiry(roleName))
			if newExpiry.Before(oldExpiry) {
				return nil, nil //nolint:nilnil // nil indicates no change needed
			}
			return &newExpiry, nil
		}); err != nil {
			return fmt.Errorf("failed to bump expiry for role %s: %w", roleName, err)
		}
	}
	return nil
}

// TODO: Make the set of hash functions used configurable.
var hashTypes = map[string]crypto.Hash{
	"sha256": crypto.SHA256,
}

func hashMetaFile[T tufmetadata.Roles](ctx context.Context, meta *tufmetadata.Metadata[T]) (*tufmetadata.MetaFiles, error) {
	version, err := metaVersion(meta)
	if err != nil {
		return nil, fmt.Errorf("could not get %T version: %w", meta, err)
	}

	payload, err := cjson.EncodeCanonical(meta)
	if err != nil {
		return nil, fmt.Errorf("failed to encode metadata to sign: %w", err)
	}

	hashes := make(tufmetadata.Hashes, len(hashTypes))
	for name, hash := range hashTypes {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("transaction cancelled: %w", ctx.Err())
		default:
			h := hash.New()
			h.Write(payload)
			hashes[name] = h.Sum(nil)
		}
	}

	return &tufmetadata.MetaFiles{
		Version: *version,
		Hashes:  hashes,
		Length:  int64(len(payload)),
	}, nil
}

func (tx *Transaction) updateSnapshot(ctx context.Context) (Err error) {
	if err := tx.valid(); err != nil {
		return err
	}
	defer tx.invalidateOnError(&Err)

	// The snapshot role only contains the hashes of target files.
	metaFiles := make(map[string]*tufmetadata.MetaFiles, len(tx.targets))
	for roleName, roleData := range tx.targets {
		hash, err := hashMetaFile(ctx, roleData)
		if err != nil {
			return fmt.Errorf("could not hash role %s for snapshot: %w", roleName, err)
		}
		rolePath := roleName + ".json"
		metaFiles[rolePath] = hash
	}
	tx.snapshot.Signed.Meta = metaFiles

	// TODO: This implicitly wipes any delegated roles that got removed, but we
	// should probably implement the key repository-related bits of
	// <https://github.com/theupdateframework/specification/issues/262>.

	if needsBump, err := tx.checkNeedsBump(ctx, tufmetadata.SNAPSHOT, tx.snapshot); err != nil {
		return fmt.Errorf("could not check if role %s needs bumps: %w", tufmetadata.SNAPSHOT, err)
	} else if needsBump {
		tx.snapshot.Signed.Version = tx.RefTime.UnixMilli()
		tx.snapshot.Signed.Expires = tx.RefTime.Add(tx.expiry(tufmetadata.SNAPSHOT))
		tx.markDirty(tufmetadata.SNAPSHOT)
	}
	return nil
}

func (tx *Transaction) updateTimestamp(ctx context.Context) (Err error) {
	if err := tx.valid(); err != nil {
		return err
	}
	defer tx.invalidateOnError(&Err)

	snapshotHash, err := hashMetaFile(ctx, tx.snapshot)
	if err != nil {
		return fmt.Errorf("could not hash role %s for timestamp: %w", tufmetadata.SNAPSHOT, err)
	}
	tx.timestamp.Signed.Meta = map[string]*tufmetadata.MetaFiles{
		tufmetadata.SNAPSHOT + ".json": snapshotHash,
	}

	// TODO: Should we check if the actual timestamp data is different as well?

	if tx.isDirty(tufmetadata.SNAPSHOT) || tx.isDirty(tufmetadata.ROOT) {
		tx.timestamp.Signed.Version = tx.RefTime.UnixMilli()
		tx.timestamp.Signed.Expires = tx.RefTime.Add(tx.expiry(tufmetadata.TIMESTAMP))
		tx.markDirty(tufmetadata.TIMESTAMP)
	}
	return nil
}

// Sign signs the current set of repository data in this transaction.
func (tx *Transaction) Sign(ctx context.Context, store *keystore.Store) (newKeyIDs []keystore.KeyID, Err error) {
	// Refuse to sign invalidated transactions.
	if err := tx.valid(); err != nil {
		return nil, err
	}

	// TODO: We call checkRoleSignatures several times here, we almost
	// certainly should be caching the results (such as caching in
	// checkRoleSignatures and invalidating the cache when the internal copy
	// gets dirtied).

	if err := tx.bumpRevisions(ctx); err != nil {
		return nil, fmt.Errorf("could not bump TUF metadata revisions: %w", err)
	}
	if err := tx.bumpExpiries(ctx); err != nil {
		return nil, fmt.Errorf("could not bump TUF metadata expiries: %w", err)
	}

	// If there is a new root, we need to rotate the timestamp role keys.
	// See <https://github.com/theupdateframework/specification/pull/316>.
	//
	// TODO: Maybe we should only do this if the keys were actually changed. If
	// the root was rotated purely to bump the expiry then this isn't really
	// necessary. Then again, maybe churning keys is a good idea...?
	if tx.isDirty(tufmetadata.ROOT) {
		// If tx.root is nil then we are coming from InitTxn and there is
		// no previous root so no need to rotate anything.
		if tx.root != nil {
			// Don't touch the new root if it is already signed.
			if signed, err := tx.checkRoleSignatures(ctx, tufmetadata.ROOT, tx.newRoot); err != nil {
				return nil, fmt.Errorf("failed to detect if role root is already signed: %w", err)
			} else if !signed {
				newTimestampKeys, err := tx.rotateRoleKeys(ctx, tufmetadata.TIMESTAMP, store)
				if err != nil {
					return nil, fmt.Errorf("could not rotate timestamp keys: %w", err)
				}
				newKeyIDs = append(newKeyIDs, newTimestampKeys...)
				defer func() { //nolint:contextcheck // ctx is not passed intentionally
					// Make sure to clean up any generated keys in case of an
					// error.
					if Err != nil {
						// TODO: We want to force the removal even if the
						// context was cancelled, but we might also want to
						// have some kind of deadline here just in case? Or
						// maybe we should use context.WithoutCancel?
						ctx := context.TODO()
						for _, keyID := range newKeyIDs {
							_ = store.UnlinkKey(ctx, keyID)
						}
						newKeyIDs = nil
					}
				}()
			}
		}
		// Sign the new root data -- for online repos this should effectively
		// be a no-op (because users should provide a pre-signed blob) but for
		// the offline case this will need access to the root keys.
		if err := tx.signRole(ctx, store, tufmetadata.ROOT); err != nil {
			return nil, err
		}
	}

	// Now sign all of the modified target roles.
	for roleName := range tx.targets {
		if !tx.isDirty(roleName) {
			continue
		}
		if err := tx.signRole(ctx, store, roleName); err != nil {
			return nil, err
		}
	}

	// Once all targets are updated, update the snapshot.
	if err := tx.updateSnapshot(ctx); err != nil {
		return nil, err
	}
	if err := tx.signRole(ctx, store, tufmetadata.SNAPSHOT); err != nil {
		return nil, err
	}

	// Finally, bump the timestamp.
	if err := tx.updateTimestamp(ctx); err != nil {
		return nil, err
	}
	if err := tx.signRole(ctx, store, tufmetadata.TIMESTAMP); err != nil {
		return nil, err
	}

	return newKeyIDs, nil
}
