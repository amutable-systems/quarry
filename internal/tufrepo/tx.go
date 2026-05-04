// Copyright (C) 2026 Amutable GmbH

package tufrepo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"iter"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/generics"
	"go.amutable.dev/quarry/internal/third_party/funchelpers"
	"go.amutable.dev/quarry/internal/tufext"
	storeopts "go.amutable.dev/quarry/internal/tufrepo/opts"
)

// TxnOp is a single operation that can be applied to a [Repository]
// [Transaction]. Note that [TxnOp]s are re-usable -- if applying a
// [Transaction] fails, you can re-apply the same operation again.
type TxnOp interface {
	// Description returns a textual description of the transaction (for error
	// messages). When implementing this interface, do not include any private
	// information in the returned description string.
	Description() string

	// ApplyToTxn applies this operation to a live [Transaction]. Operations may
	ApplyToTxn(context.Context, *Transaction) error
}

type txOpFn struct {
	description string
	applyFn     func(context.Context, *Transaction) error
}

func (op *txOpFn) Description() string {
	return op.description
}

func (op *txOpFn) ApplyToTxn(ctx context.Context, tx *Transaction) error {
	return op.applyFn(ctx, tx)
}

// NewTxnOp returns a minimal [TxnOp] implementation that just applies the
// given function on any [Transaction]. This primarily useful as shorthand for
// constructing a [TxnOp] inline or for very simple operations.
func NewTxnOp(description string, applyFn func(ctx context.Context, tx *Transaction) error) TxnOp {
	return &txOpFn{
		description: description,
		applyFn:     applyFn,
	}
}

// Transaction stores the current state of a repository while undergoing some
// series of transactions.
//
// TODO: I guess we probably want to make all of the backing data be accessible
// via getters rather than pre-loading it? In principle we just need the
// timestamp, as everything is pinned from there.
type Transaction struct {
	// err contains a saved error when a transaction has failed due to an
	// unrecoverable error. Any subsequent operations will return this error
	// and refuse to do any operations.
	err error

	// dirty is the set of role files that have been modified by
	dirty map[string]struct{}

	// RefTime is the time when the transaction was started, and all
	// time-related calculations in the transaction (such as updating expiries)
	// should be based on it.
	RefTime time.Time

	// root is the original root metadata, which we always keep around in order
	// for Sign to be able to sign the new root metadata with old keys (if it
	// was changed).
	root, newRoot *tufext.SignedRoot

	timestamp *tufext.SignedTimestamp
	snapshot  *tufext.SignedSnapshot

	// oldTimestampETag is the [storeopts.ETag] of the timestamp role at
	// [TxnStart] time, used to detect racing writes at [TxnCommit] time.
	oldTimestampETag storeopts.ETag

	// targets includes the top-level target role (key "targets") and any
	// delegated target roles (key is the delegated role name).
	targets map[string]*tufext.SignedTargets
}

var errFailedTransaction = fmt.Errorf("cannot operate on a failed transaction")

// valid returns an error iff the transaction is in a failed state.
func (tx *Transaction) valid() error {
	err := tx.err
	if err != nil {
		err = fmt.Errorf("%w: %w", errFailedTransaction, err)
	}
	return err
}

// invalidateOnError is a defer helper to invalidate the transaction if the
// passed error pointer is non-nil (the pointer itself must be non-nil). It
// also updates the pointer error if it is unset but the transaction failed
// (though you should avoid doing this -- pre-flight checks are cheaper).
func (tx *Transaction) invalidateOnError(Err *error) {
	// If the returned error is a superset of the transaction error then this
	// is almost certainly being called in a caller function and so the new
	// error has more detail and should be favoured.
	if *Err != nil && (tx.err == nil || errors.Is(*Err, tx.err)) {
		tx.err = *Err
	}
	if *Err == nil && tx.err != nil {
		*Err = tx.valid()
	}
}

// TODO: We need to be more selective with invalidating transactions, at the
// moment any error in a Transction method results in the transaction becoming
// invalidated when this is only needed for operations where the internal state
// has been modified and an error occurred during the modification.

// Apply applies a set of [TxnOp]s to this transaction. If any operation fails
// to apply, the entire transaction will fail (if you wish to detect errors
// without failing the transaction, call [TxnOp.ApplyToTxn] manually).
func (tx *Transaction) Apply(ctx context.Context, txOps ...TxnOp) (Err error) {
	if err := tx.valid(); err != nil {
		return err
	}
	defer tx.invalidateOnError(&Err)

	for _, txOp := range txOps {
		select {
		case <-ctx.Done():
			return fmt.Errorf("transaction cancelled: %w", ctx.Err())
		default:
			if err := txOp.ApplyToTxn(ctx, tx); err != nil {
				return fmt.Errorf("transaction operation %q failed: %w", txOp.Description(), err)
			}
		}
	}
	return nil
}

// markDirty adds the given role name to the set of "dirty" metadata files that
// will be updated when the transaction is committed.
func (tx *Transaction) markDirty(roleName string) {
	if tx.dirty == nil {
		tx.dirty = make(map[string]struct{})
	}
	tx.dirty[roleName] = struct{}{}
}

// isDirty returns whether the given role name is marked as dirty.
func (tx *Transaction) isDirty(roleName string) bool {
	if tx.dirty == nil {
		return false
	}
	_, ok := tx.dirty[roleName]
	return ok
}

// RootRoleData returns the root role data for this transaction.
//
// This method is intended to be called from [TxnOp.ApplyToTxn].
func (tx *Transaction) RootRoleData(_ context.Context) (_ *tufext.SignedRoot, Err error) {
	root := tx.newRoot
	if root == nil {
		root = tx.root
	}
	return generics.DeepCopy(root)
}

// TimestampRoleData returns the timestamp role data for this transaction.
//
// This method is intended to be called from [TxnOp.ApplyToTxn].
func (tx *Transaction) TimestampRoleData(_ context.Context) (_ *tufext.SignedTimestamp, Err error) {
	return generics.DeepCopy(tx.timestamp)
}

// SnapshotRoleData returns the snapshot role data for this transaction.
//
// This method is intended to be called from [TxnOp.ApplyToTxn].
func (tx *Transaction) SnapshotRoleData(_ context.Context) (_ *tufext.SignedSnapshot, Err error) {
	return generics.DeepCopy(tx.snapshot)
}

// TargetsRoleData returns the targets role data for this transaction for the
// given role name (for the top-level targets data, pass [tufmetadata.TARGETS]
// as the role name).
//
// This method is intended to be called from [TxnOp.ApplyToTxn].
func (tx *Transaction) TargetsRoleData(_ context.Context, roleName string) (_ *tufext.SignedTargets, Err error) {
	data, ok := tx.targets[roleName]
	if !ok {
		return nil, fmt.Errorf("unknown role %s: %w", roleName, fs.ErrNotExist)
	}
	return generics.DeepCopy(data)
}

// RoleData returns the role data for any TUF role name. This is just a wrapper
// around the other [Transaction].FooRoleData methods, and you should use those
// if you know at compile-time which role data you need.
//
// This method is intended to be called from [TxnOp.ApplyToTxn].
func (tx *Transaction) RoleData(ctx context.Context, roleName string) (_ any, Err error) {
	switch roleName {
	case tufmetadata.ROOT:
		root, err := tx.RootRoleData(ctx)
		return generics.PtrToAny(root), err
	case tufmetadata.TIMESTAMP:
		timestamp, err := tx.TimestampRoleData(ctx)
		return generics.PtrToAny(timestamp), err
	case tufmetadata.SNAPSHOT:
		snapshot, err := tx.SnapshotRoleData(ctx)
		return generics.PtrToAny(snapshot), err
	case tufmetadata.TARGETS:
		fallthrough
	default:
		targets, err := tx.TargetsRoleData(ctx, roleName)
		return generics.PtrToAny(targets), err
	}
}

// parseRoleData parses generic data passed to UpdateRoleData. It accepts both
// pre-parsed [tufmetadata.Metadata] structures, as well as []byte and
// [json.RawMessage].
//
// TODO: This should arguably take a context.Context but consuming an
// [io.Reader] is a little annoying ot cancel.
func parseRoleData[T tufmetadata.Roles](roleName string, roleData any) (*tufmetadata.Metadata[T], error) {
	if rdr, ok := roleData.(io.Reader); ok {
		// TODO: We probably should use io.LimitReader here (or write a
		// MaxReader that errors out if there is more data after a given length
		// -- kinda like VerifiedReadCloser?).
		data, err := io.ReadAll(rdr)
		if err != nil {
			return nil, err
		}
		roleData = data
	}
	if data, ok := roleData.(json.RawMessage); ok {
		roleData = []byte(data)
	}
	var parsed *tufmetadata.Metadata[T]
	switch roleData := roleData.(type) {
	case []byte:
		var meta tufmetadata.Metadata[T]
		if err := json.Unmarshal(roleData, &meta); err != nil {
			return nil, fmt.Errorf("failed to decode JSON role data as %T: %w", &meta, err)
		}
		parsed = &meta
	case tufmetadata.Metadata[T]:
		meta, err := generics.DeepCopy(&roleData)
		if err != nil {
			return nil, err
		}
		parsed = meta
	case *tufmetadata.Metadata[T]:
		meta, err := generics.DeepCopy(roleData)
		if err != nil {
			return nil, err
		}
		parsed = meta
	// TODO: We should probably support passing the inner T data directly.
	default:
		return nil, fmt.Errorf("unsupported data type %T", roleData)
	}
	if err := tufext.CheckMetadataType(roleName, parsed); err != nil {
		return nil, fmt.Errorf("error while parsing %s role data: %w", roleName, err)
	}
	return parsed, nil
}

var errMismatchedRole = errors.New("mismatched role data")

// UpdateRoleData updates the role data for the given role name in this
// transaction. You should only call this method if your [TxnOp] is actually
// modifying the given role name -- otherwise you may cause needless updates to
// metadata when the transaction is committed.
//
// This method is intended to be called from [TxnOp.ApplyToTxn].
func (tx *Transaction) UpdateRoleData(roleName string, roleData any) (Err error) {
	switch roleName {
	case tufmetadata.ROOT:
		root, err := parseRoleData[tufmetadata.RootType](roleName, roleData)
		if err != nil {
			return fmt.Errorf("%w for role %s: %w", errMismatchedRole, roleName, err)
		}
		tx.newRoot = root
	case tufmetadata.SNAPSHOT:
		snapshot, err := parseRoleData[tufmetadata.SnapshotType](roleName, roleData)
		if err != nil {
			return fmt.Errorf("%w for role %s: %w", errMismatchedRole, roleName, err)
		}
		tx.snapshot = snapshot
	case tufmetadata.TIMESTAMP:
		timestamp, err := parseRoleData[tufmetadata.TimestampType](roleName, roleData)
		if err != nil {
			return fmt.Errorf("%w for role %s: %w", errMismatchedRole, roleName, err)
		}
		tx.timestamp = timestamp
	case tufmetadata.TARGETS:
		fallthrough
	default:
		targets, err := parseRoleData[tufmetadata.TargetsType](roleName, roleData)
		if err != nil {
			return fmt.Errorf("%w for role %s: %w", errMismatchedRole, roleName, err)
		}
		tx.targets[roleName] = targets
	}
	tx.markDirty(roleName)
	return nil
}

// Roles returns an iterator over all roles that are actually included in the
// repository data.
func (tx *Transaction) Roles(ctx context.Context) iter.Seq[string] {
	return func(yield func(string) bool) {
		seen := make(map[string]struct{})
		// Return the top-level roles first.
		for _, role := range tufmetadata.TOP_LEVEL_ROLE_NAMES {
			seen[role] = struct{}{}
			// Skip missing roles in case we are in a partially-initialised
			// InitTxn.
			if data, err := tx.RoleData(ctx, role); err != nil || data == nil {
				continue
			}
			if !yield(role) {
				return
			}
		}
		// Return all of the target-delegated roles.
		for role := range tx.targets {
			if _, skip := seen[role]; skip {
				continue
			}
			if !yield(role) {
				return
			}
			seen[role] = struct{}{}
		}
	}
}

// DefinedRoles returns an iterator over all role names that are referenced by
// the repository (either in the root data or a target file).
//
// NOTE: This function does not validate that any delegated roles are actually
// reachable from the top-level targets role.
func (tx *Transaction) DefinedRoles(ctx context.Context) iter.Seq2[string, error] {
	return generics.ErrorIter(func(yield func(string) bool) error {
		seen := make(map[string]struct{})
		root, err := tx.RootRoleData(ctx)
		if err != nil {
			return err
		}
		for role := range root.Signed.Roles {
			if !yield(role) {
				return nil
			}
			seen[role] = struct{}{}
		}
		for _, target := range tx.targets {
			if target.Signed.Delegations == nil {
				continue
			}
			for _, role := range target.Signed.Delegations.Roles {
				if _, skip := seen[role.Name]; skip {
					continue
				}
				if !yield(role.Name) {
					return nil
				}
			}
		}
		return nil
	})
}

// ClearRole removes the given delegated role name from the set of files
// included in the repository. Note that this method *does not* remove
// delegation references to the role in target files (as we cannot be sure that
// we can sign them). If you wish to remove them, you will need to manually do
// it with [Transaction.UpdateRoleData].
//
// This method is intended to be called from [TxnOp.ApplyToTxn].
func (tx *Transaction) ClearRole(_ context.Context, roleName string) (Err error) {
	if tufext.IsCoreRole(roleName) {
		return fmt.Errorf("cannot remove top-level role %q", roleName)
	}
	delete(tx.targets, roleName)
	tx.markDirty(tufmetadata.SNAPSHOT)

	// If the role was modified in this transaction then cleared, we need to
	// clear it from the dirty set. This will mean that TxnCommit cannot delete
	// the role file, but this is not an issue because we use consistent
	// snapshots and so all of our changes are purely additive anyway.
	delete(tx.dirty, roleName)

	// TODO: This should probably implement the key repository-related bits of
	// <https://github.com/theupdateframework/specification/issues/262>.

	// TODO: We probably want to remove the same role name from the targets?
	// Unfortunately we are unlikely to be able to resign the target or
	// delegated target files, so this would need to be a best-effort thing
	// done during Sign...?
	return nil
}

// TxnStart starts a new [Transaction] with the latest state of the repository.
// Changes made to the [Transaction] do not affect the live repository until
// [Repository.TxnCommit] is called.
func (r *Repository) TxnStart(ctx context.Context) (_ *Transaction, Err error) {
	tx := &Transaction{
		RefTime: time.Now().UTC(),
		targets: make(map[string]*tufext.SignedTargets),
	}

	// Step 0. Get the latest root. (Must always exist.)

	root, _, err := r.GetLatestRoot(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get root.json: %w", err)
	}
	tx.root = root

	// Step 1. Fetch the timestamp, which pins the tree of objects we need to
	// fetch. (Might not exist.)

	timestamp, timestampMeta, err := r.GetLatestTimestamp(ctx)
	if errors.Is(err, fs.ErrNotExist) {
		// If there was no timestamp.json, then there are no other blobs for us
		// to load. Live repositories are not in this state normally, but a
		// repository created with InitTxn might be in this state if they
		// didn't set up any other parts.
		// TODO: Add logging.
		return tx, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get timestamp.json: %w", err)
	}
	tx.timestamp = timestamp
	tx.oldTimestampETag = timestampMeta.ETag

	// Step 2. Fetch the timestamp-pinned snapshot, which pins all of the
	// targets. (Might not exist.)

	// TODO: The logic between fetching timestamp-pinned and snapshot-pinned
	// objects is basically identical (except for which field in Transaction
	// stores the copy), so it really should be unified into one thing (maybe a
	// queue of things to pull?).

	snapshotMetaRef, hasSnapshotRef := timestamp.Signed.Meta[tufmetadata.SNAPSHOT+".json"]
	switch {
	case len(timestamp.Signed.Meta) == 0:
		// If snapshot is not present then there is nothing left for us to
		// fetch. Again, this might happen for InitTxn-committed repos.
		// TODO: If we made the snapshot and timestamp fetching generic we
		// wouldn't have to handle this case explicitly...
		// TODO: Add logging.
		return tx, nil
	case hasSnapshotRef && len(timestamp.Signed.Meta) == 1:
		// Timestamp *only* contains snapshot.json (as we expect), so
		// fallthrough to fetching.
	default:
		// TODO: Not sure whether we want to support this?
		return nil, fmt.Errorf("%w: timestamp.json contains roles other than snapshot: %v",
			ErrInvalidRepoState, slices.Collect(maps.Keys(timestamp.Signed.Meta)))
	}
	snapshotRdr, _, err := r.GetVersionedFile(ctx, tufmetadata.SNAPSHOT, snapshotMetaRef.Version)
	if err != nil {
		return nil, fmt.Errorf("failed to get %d.snapshot.json (referenced by timestamp.json): %w",
			snapshotMetaRef.Version, err)
	}
	defer funchelpers.VerifyClose(&Err, snapshotRdr)

	var snapshot tufext.SignedSnapshot
	if err := json.NewDecoder(snapshotRdr).Decode(&snapshot); err != nil {
		return nil, fmt.Errorf("failed to parse snapshot.json: %w", err)
	}
	if err := tufext.CheckMetadataType(tufmetadata.SNAPSHOT, &snapshot); err != nil {
		return nil, fmt.Errorf("invalid snapshot blob: %w", err)
	}
	tx.snapshot = &snapshot

	// Step 3. Load all of the snapshot-pinned targets. (Each one must exist if
	// they are referenced.)

	tx.targets = make(map[string]*tufext.SignedTargets, len(snapshot.Signed.Meta))
	for rolePath, roleMetaRef := range snapshot.Signed.Meta {
		roleName, ok := strings.CutSuffix(rolePath, ".json")
		if !ok {
			return nil, fmt.Errorf("%d.snapshot.json metapath %q does not have .json suffix",
				snapshot.Signed.Version, rolePath)
		}
		targetRdr, _, err := r.GetVersionedFile(ctx, roleName, roleMetaRef.Version)
		if err != nil {
			return nil, fmt.Errorf("failed to get %d.%s.json (referenced by %d.snapshot.json): %w",
				roleMetaRef.Version, roleName, snapshot.Signed.Version, err)
		}
		var target tufext.SignedTargets
		err = json.NewDecoder(targetRdr).Decode(&target)
		_ = targetRdr.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to parse %s role data: %w", roleName, err)
		}
		if err := tufext.CheckMetadataType(roleName, &target); err != nil {
			return nil, fmt.Errorf("invalid %s blob: %w", roleName, err)
		}
		tx.targets[roleName] = &target
	}

	return tx, nil
}

// InitTxn starts a dummy "initial" transaction that can be used for
// initialising a new repository.
func InitTxn(initRoot *tufext.SignedRoot) *Transaction {
	tx := &Transaction{
		RefTime:          time.Now().UTC(),
		newRoot:          initRoot,
		targets:          map[string]*tufext.SignedTargets{},
		oldTimestampETag: storeopts.ETag(""), // equivalent to NoClobber
	}
	// Only mark the root as dirty -- the snapshot and timestamp roles will
	// only be added if a user explicitly adds them (and they will get signed
	// in Sign if necessary).
	tx.markDirty(tufmetadata.ROOT)
	return tx
}

// ErrClobberedTransaction is returned from [Repository.TxnCommit] if the
// transaction fails because the top-level timestamp of the repository changed
// since [Repository.TxnStart].
var ErrClobberedTransaction = errors.New("transaction rejected because repository state has changed")

// ErrInvalidTransactionState is returned from [Repository.TxnCommit] if a
// transaction has an internally invalid state that means it cannot committed
// to a repository.
var ErrInvalidTransactionState = errors.New("transaction is in an invalid state")

// timestampRevisionAttribute is the name of the attribute for the top-level
// timestamp.json that indicates the version of this timestamp.json file.
//
// TODO: This will be quite important when we start to encrypt metafiles with a
// one-time key derived partially from the metadata revision number, in order
// to allow us to decrypt everything when making changes without an external
// database.
const timestampRevisionAttribute = "quarry-timestamp-revision"

// TxnCommit commits the given [Transaction] to the repository, updating the
// state of the repository to the one configured in the [Transaction]. If the
// repository has changed since the transaction was started, the transaction
// will be aborted and [ErrTransactionFailed] will be returned.
func (r *Repository) TxnCommit(ctx context.Context, tx *Transaction) (_ *tufext.SignedTimestamp, Err error) {
	// Refuse to commit invalidated transactions.
	if err := tx.valid(); err != nil {
		return nil, err
	}
	defer tx.invalidateOnError(&Err)

	// TODO: We should check that all of the blobs have valid signatures to
	// make sure the user did not forget to call Sign.

	// If we got here from an InitTxn (tx.root is nil), then the root needs to
	// have a version of 1 to create a valid repository.
	if tx.root == nil && tx.newRoot.Signed.Version != 1 {
		return nil, fmt.Errorf("%w: initial root version must be 1", ErrInvalidTransactionState)
	}

	type uploadedBlob struct {
		filename string
		metadata *BlobMetadata
	}

	// If an error occurs, we want to get rid of any of the temporary files we
	// created.
	newBlobs := make([]uploadedBlob, 0, len(tx.dirty))
	defer func() { //nolint:contextcheck // ctx is not passed intentionally
		if Err != nil {
			// TODO: We want to force the removal even if the context was
			// cancelled, but we might also want to have some kind of deadline
			// here just in case? Or maybe we should use context.WithoutCancel?
			ctx := context.TODO()
			for _, file := range newBlobs {
				_ = r.DeleteBlob(ctx, file.filename,
					// This really should not happen, but just in case...
					storeopts.IfETagMatches(file.metadata.ETag))
			}
		}
	}()

	// Apply all of our new data files to the root. This includes the
	// N.timestamp.json so we can keep historical copies in case we want to use
	// them for something else.
	for role := range tx.dirty {
		roleData, err := tx.RoleData(ctx, role)
		if err != nil {
			return nil, fmt.Errorf("failed to get role data for %s: %w", role, err)
		}
		version, blobMeta, err := r.PutVersionedFile(ctx, role, roleData, storeopts.NoClobber)
		if err != nil {
			return nil, fmt.Errorf("failed to upload %s.json: %w", role, err)
		}
		newBlobs = append(newBlobs, uploadedBlob{
			filename: fmt.Sprintf("%d.%s.json", version, role),
			metadata: blobMeta,
		})
	}

	// Atomically swap over the timestamp.json last. If this fails then we fail
	// the entire transaction (and remove all of the previous objects we
	// uploaded).
	if tx.isDirty(tufmetadata.TIMESTAMP) {
		payload, err := cjson.EncodeCanonical(tx.timestamp)
		if err != nil {
			return nil, fmt.Errorf("failed to encode timestamp.json: %w", err)
		}
		filename := tufmetadata.TIMESTAMP + ".json"
		buf := bytes.NewReader(payload)

		blobMeta, err := r.PutBlob(ctx, filename, buf,
			// Make sure the repo hasn't changed underneath us.
			storeopts.ClobberIfMatches(tx.oldTimestampETag),
			// TODO: Will be useful when we start encrypting metafiles.
			storeopts.WithAttribute(
				timestampRevisionAttribute,
				strconv.FormatInt(tx.timestamp.Signed.Version, 10),
			),
		)
		if err != nil {
			if errors.Is(err, storeopts.ErrETagMismatch) {
				err = fmt.Errorf("%w: %w", ErrClobberedTransaction, err)
			}
			return nil, fmt.Errorf("failed to upload timestamp.json: %w", err)
		}
		newBlobs = append(newBlobs, uploadedBlob{
			filename: filename,
			metadata: blobMeta,
		})
	}

	// TODO: We should probably update the oldTimestampETag once the update is
	// successful, in order to make sure that chained TxnCommits succeed.

	return tx.timestamp, nil
}
