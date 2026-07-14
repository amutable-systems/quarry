//go:build insecure

// Copyright (C) 2026 Amutable GmbH

package tufrepo_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/keystore"
	_ "go.amutable.dev/quarry/internal/keystore/insecure"
	"go.amutable.dev/quarry/internal/tufext"
	"go.amutable.dev/quarry/internal/tufrepo"
	storeopts "go.amutable.dev/quarry/internal/tufrepo/opts"
)

// bootstrap is a fully-signed initial TUF repository, along with the
// [keystore.Store] and role keys that were used to sign it. All tests that
// need a live transaction start from a [bootstrap].
type bootstrap struct {
	repo  *tufrepo.Repository
	store *keystore.Store

	// storeDir is the on-disk directory backing `store`. Tests that want to
	// introspect keystore state (e.g. by counting files) can use this.
	storeDir string

	// initialRefTime is the wall-clock time at bootstrap time -- used by
	// tests that want to assert on expiry/version relationships.
	initialRefTime time.Time

	// Role keys used to seed the repository. The ed25519 [keystore.KeyID] is
	// derived from the TUF [tufmetadata.Key] and is stable across the
	// lifetime of the bootstrap.
	rootKey, targetsKey, snapshotKey, timestampKey *keystore.GenericKey

	// delegatedKeys is indexed by delegated role name, populated by
	// [withDelegation].
	delegatedKeys map[string]*keystore.GenericKey
}

// bootstrapOption configures [bootstrapRepo].
type bootstrapOption func(*bootstrapConfig)

type bootstrapConfig struct {
	delegations []string
}

// withDelegation instructs [bootstrapRepo] to create a (properly signed and
// properly referenced) delegated targets role with the given name. The name
// must be unique across all [withDelegation] options passed to a single
// [bootstrapRepo] call.
func withDelegation(name string) bootstrapOption {
	return func(c *bootstrapConfig) {
		for _, existing := range c.delegations {
			if existing == name {
				panic("withDelegation: duplicate delegation name " + name)
			}
		}
		c.delegations = append(c.delegations, name)
	}
}

// bootstrapRepo creates a fully-signed, consistent initial TUF repository with
// root, top-level targets, snapshot, and timestamp roles. Each role is signed
// by a single insecure-driver ed25519 key stored in the returned [keystore.Store].
func bootstrapRepo(t *testing.T, opts ...bootstrapOption) *bootstrap {
	t.Helper()
	ctx := context.Background()

	var cfg bootstrapConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	repo := newTestRepo(t)
	store, storeDir := newTestKeystore(t)

	rootKey := generateInsecureKey(ctx, t, store)
	targetsKey := generateInsecureKey(ctx, t, store)
	snapshotKey := generateInsecureKey(ctx, t, store)
	timestampKey := generateInsecureKey(ctx, t, store)

	refTime := time.Now().UTC()

	// Top-level targets (possibly with delegations).
	targets := tufext.DefaultTargets(refTime.Add(tufrepo.DefaultTargetsExpiry))
	targets.Signed.Version = 1
	delegatedKeys := make(map[string]*keystore.GenericKey, len(cfg.delegations))
	if len(cfg.delegations) > 0 {
		targets.Signed.Delegations = &tufmetadata.Delegations{
			Keys:  map[string]*tufmetadata.Key{},
			Roles: []tufmetadata.DelegatedRole{},
		}
		for _, roleName := range cfg.delegations {
			key := generateInsecureKey(ctx, t, store)
			keyID, err := key.ID()
			require.NoError(t, err)
			targets.Signed.Delegations.Keys[string(keyID)] = &key.Public
			targets.Signed.Delegations.Roles = append(targets.Signed.Delegations.Roles, tufmetadata.DelegatedRole{
				Name:      roleName,
				KeyIDs:    []string{string(keyID)},
				Threshold: 1,
				Paths:     []string{roleName + "/*"},
			})
			delegatedKeys[roleName] = key
		}
	}
	signMeta(ctx, t, targets, targetsKey)
	_, _, err := repo.PutVersionedFile(ctx, tufmetadata.TARGETS, targets)
	require.NoError(t, err)

	// Root, referencing all top-level role keys, self-signed by the root key.
	rootBuilder := tufext.NewRootBuilder()
	rootBuilder.RefTime = refTime
	_, err = rootBuilder.AddRole(tufmetadata.ROOT, 1, rootKey.Public)
	require.NoError(t, err)
	_, err = rootBuilder.AddRole(tufmetadata.TARGETS, 1, targetsKey.Public)
	require.NoError(t, err)
	_, err = rootBuilder.AddRole(tufmetadata.SNAPSHOT, 1, snapshotKey.Public)
	require.NoError(t, err)
	_, err = rootBuilder.AddRole(tufmetadata.TIMESTAMP, 1, timestampKey.Public)
	require.NoError(t, err)
	root, _, err := rootBuilder.Sign(ctx, store)
	require.NoError(t, err)
	_, _, err = repo.PutVersionedFile(ctx, tufmetadata.ROOT, root)
	require.NoError(t, err)

	// Build snapshot metadata referencing every target (including delegations).
	snapshot := tufext.DefaultSnapshot(refTime.Add(tufrepo.DefaultSnapshotExpiry))
	snapshot.Signed.Version = 1
	snapshot.Signed.Meta = map[string]*tufmetadata.MetaFiles{}
	targetsMeta, err := tufrepo.HashMetaFile(ctx, targets)
	require.NoError(t, err)
	snapshot.Signed.Meta[tufmetadata.TARGETS+".json"] = targetsMeta

	for _, roleName := range cfg.delegations {
		delegated := tufext.DefaultTargets(refTime.Add(tufrepo.DefaultTargetsExpiry))
		delegated.Signed.Version = 1
		signMeta(ctx, t, delegated, delegatedKeys[roleName])
		_, _, err := repo.PutVersionedFile(ctx, roleName, delegated)
		require.NoError(t, err)

		meta, err := tufrepo.HashMetaFile(ctx, delegated)
		require.NoError(t, err)
		snapshot.Signed.Meta[roleName+".json"] = meta
	}
	signMeta(ctx, t, snapshot, snapshotKey)
	_, _, err = repo.PutVersionedFile(ctx, tufmetadata.SNAPSHOT, snapshot)
	require.NoError(t, err)

	// Timestamp, referencing the snapshot.
	timestamp := tufext.DefaultTimestamp(refTime.Add(tufrepo.DefaultTimestampExpiry))
	timestamp.Signed.Version = 1
	snapshotMeta, err := tufrepo.HashMetaFile(ctx, snapshot)
	require.NoError(t, err)
	timestamp.Signed.Meta = map[string]*tufmetadata.MetaFiles{
		tufmetadata.SNAPSHOT + ".json": snapshotMeta,
	}
	signMeta(ctx, t, timestamp, timestampKey)
	_, err = repo.PutBlob(ctx, tufmetadata.TIMESTAMP+".json",
		bytes.NewReader(mustEncode(t, timestamp)))
	require.NoError(t, err)

	return &bootstrap{
		repo:           repo,
		store:          store,
		storeDir:       storeDir,
		initialRefTime: refTime,
		rootKey:        rootKey,
		targetsKey:     targetsKey,
		snapshotKey:    snapshotKey,
		timestampKey:   timestampKey,
		delegatedKeys:  delegatedKeys,
	}
}

// newTestKeystore opens a fresh [keystore.Store] backed by a temp dir. The
// store is automatically closed at test teardown. The on-disk directory
// path is returned so tests can introspect the store (e.g. count keys).
func newTestKeystore(t *testing.T) (*keystore.Store, string) {
	t.Helper()
	dir := t.TempDir()
	store, err := keystore.OpenStore(dir)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	return store, dir
}

// countKeystoreEntries reports the number of key files currently stored in
// the given keystore directory.
func countKeystoreEntries(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	return len(entries), nil
}

// generateInsecureKey generates a new ed25519 key via the insecure driver and
// stores it in the given [keystore.Store].
func generateInsecureKey(ctx context.Context, t *testing.T, store *keystore.Store) *keystore.GenericKey {
	t.Helper()
	_, key, err := store.GenerateKey(ctx, keystore.WithDriver("insecure"))
	require.NoError(t, err)
	return key
}

// signMeta signs the given metadata with each provided key.
func signMeta[T tufmetadata.Roles](ctx context.Context, t *testing.T, meta *tufmetadata.Metadata[T], keys ...*keystore.GenericKey) {
	t.Helper()
	for _, key := range keys {
		_, err := tufext.SignRole(ctx, meta, key)
		require.NoError(t, err)
	}
}

// currentTimestamp fetches the live timestamp.json from the repository -- used
// by tests to assert commit side-effects.
func currentTimestamp(ctx context.Context, t *testing.T, repo *tufrepo.Repository) *tufext.SignedTimestamp {
	t.Helper()
	ts, _, err := repo.GetLatestTimestamp(ctx)
	require.NoError(t, err)
	return ts
}

// decodeJSON decodes the raw JSON bytes into a fresh instance of the given
// role type.
func decodeJSON[T tufmetadata.Roles](t *testing.T, payload []byte) *tufmetadata.Metadata[T] {
	t.Helper()
	var meta tufmetadata.Metadata[T]
	require.NoError(t, json.Unmarshal(payload, &meta))
	return &meta
}

// mustKeyIDs extracts the stringified key IDs for the given keys. Panics via
// [require] on error.
func mustKeyIDs(t *testing.T, keys ...*keystore.GenericKey) []string {
	t.Helper()
	ids := make([]string, 0, len(keys))
	for _, key := range keys {
		id, err := key.ID()
		require.NoError(t, err)
		ids = append(ids, string(id))
	}
	return ids
}

// mustRootRoleKeyIDs fetches the currently-configured set of key ids for the
// given top-level role out of the transaction's [tufmetadata.RootType] view.
func mustRootRoleKeyIDs(ctx context.Context, t *testing.T, tx *tufrepo.Transaction, roleName string) []string {
	t.Helper()
	root, err := tx.RootRoleData(ctx)
	require.NoError(t, err)
	role, ok := root.Signed.Roles[roleName]
	require.True(t, ok, "role %s missing from root", roleName)
	return role.KeyIDs
}

// addTargetOp returns a [tufrepo.TxnOp] that inserts a stub target file
// entry on the top-level targets role.
func addTargetOp(path string, length int64) tufrepo.TxnOp {
	return tufrepo.NewTxnOp(
		"add target "+path,
		func(ctx context.Context, tx *tufrepo.Transaction) error {
			targets, err := tx.TargetsRoleData(ctx, tufmetadata.TARGETS)
			if err != nil {
				return err
			}
			if targets.Signed.Targets == nil {
				targets.Signed.Targets = map[string]*tufmetadata.TargetFiles{}
			}
			targets.Signed.Targets[path] = &tufmetadata.TargetFiles{
				Length: length,
				Hashes: tufmetadata.Hashes{
					"sha256": bytes.Repeat([]byte{0xAB}, 32),
				},
			}
			return tx.UpdateRoleData(tufmetadata.TARGETS, targets)
		},
	)
}

// assertRootDelegates asserts that the transaction's current root correctly
// verifies the given role's metadata. Use with `roleName = tufmetadata.ROOT`
// and `meta = root` to assert root self-verification.
func assertRootDelegates[T tufmetadata.Roles](ctx context.Context, t *testing.T, tx *tufrepo.Transaction, roleName string, meta *tufmetadata.Metadata[T]) {
	t.Helper()
	root, err := tx.RootRoleData(ctx)
	require.NoError(t, err)
	require.NoError(t, root.VerifyDelegate(roleName, meta))
}

// errReader is a throwaway [io.Reader] that returns a preset error.
type errReader struct {
	err error
}

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

// withRefreshWindow swaps [tufrepo.DefaultExpiryRefreshWindow] for one test.
// Tests in this package do not run with t.Parallel(), so this is safe.
func withRefreshWindow(t *testing.T, d time.Duration) {
	t.Helper()
	orig := tufrepo.DefaultExpiryRefreshWindow
	tufrepo.DefaultExpiryRefreshWindow = d
	t.Cleanup(func() { tufrepo.DefaultExpiryRefreshWindow = orig })
}

// rewriteDelegatedExpiry overwrites a delegated targets role on disk with a
// fresh copy carrying `expiry` and re-stitches snapshot+timestamp. Lets tests
// install states Sign would refuse to produce (e.g. already-expired roles).
func rewriteDelegatedExpiry(ctx context.Context, t *testing.T, bs *bootstrap, roleName string, expiry time.Time) {
	t.Helper()

	delegated := tufext.DefaultTargets(expiry)
	delegated.Signed.Version = 1
	signMeta(ctx, t, delegated, bs.delegatedKeys[roleName])
	_, _, err := bs.repo.PutVersionedFile(ctx, roleName, delegated, storeopts.Clobber)
	require.NoError(t, err)

	rdr, _, err := bs.repo.GetVersionedFile(ctx, tufmetadata.SNAPSHOT, 1)
	require.NoError(t, err)
	body, err := io.ReadAll(rdr)
	require.NoError(t, rdr.Close())
	require.NoError(t, err)
	snap := decodeJSON[tufmetadata.SnapshotType](t, body)

	delegatedHash, err := tufrepo.HashMetaFile(ctx, delegated)
	require.NoError(t, err)
	snap.Signed.Meta[roleName+".json"] = delegatedHash
	snap.Signatures = nil
	signMeta(ctx, t, snap, bs.snapshotKey)
	_, _, err = bs.repo.PutVersionedFile(ctx, tufmetadata.SNAPSHOT, snap, storeopts.Clobber)
	require.NoError(t, err)

	ts := currentTimestamp(ctx, t, bs.repo)
	snapHash, err := tufrepo.HashMetaFile(ctx, snap)
	require.NoError(t, err)
	ts.Signed.Meta[tufmetadata.SNAPSHOT+".json"] = snapHash
	ts.Signatures = nil
	signMeta(ctx, t, ts, bs.timestampKey)
	_, err = bs.repo.PutBlob(ctx, "timestamp.json", bytes.NewReader(mustEncode(t, ts)),
		storeopts.Clobber)
	require.NoError(t, err)
}
