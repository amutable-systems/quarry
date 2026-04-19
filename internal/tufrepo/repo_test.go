// Copyright (C) 2026 Amutable GmbH

package tufrepo_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/tufrepo"
	"go.amutable.dev/quarry/internal/tufrepo/localrepo"
	storeopts "go.amutable.dev/quarry/internal/tufrepo/opts"
)

func newTestRepo(t *testing.T) *tufrepo.Repository {
	t.Helper()
	store, err := localrepo.Open(t.TempDir())
	require.NoError(t, err)
	repo, err := tufrepo.Open(store)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, repo.Close()) })
	return repo
}

func mustEncode(t *testing.T, v any) []byte {
	t.Helper()
	b, err := cjson.EncodeCanonical(v)
	require.NoError(t, err)
	return b
}

func TestRepository_PutGetVersionedFile_RoundTrip(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)

	root := tufmetadata.Root(time.Now().Add(time.Hour))
	root.Signed.Version = 3

	version, putMeta, err := repo.PutVersionedFile(ctx, tufmetadata.ROOT, root)
	require.NoError(t, err)
	assert.Equal(t, int64(3), version)
	require.NotNil(t, putMeta)

	rdr, getMeta, err := repo.GetVersionedFile(ctx, tufmetadata.ROOT, 3)
	require.NoError(t, err)
	defer rdr.Close() //nolint:errcheck // test code
	require.NotNil(t, getMeta)
	assert.Equal(t, putMeta.ETag, getMeta.ETag)

	body, err := io.ReadAll(rdr)
	require.NoError(t, err)
	assert.Equal(t, mustEncode(t, root), body)
}

func TestRepository_PutVersionedFile_AcceptsAllCoreRoles(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)

	expires := time.Now().Add(time.Hour)
	for _, tc := range []struct {
		role string
		meta any
	}{
		{tufmetadata.ROOT, tufmetadata.Root(expires)},
		{tufmetadata.TIMESTAMP, tufmetadata.Timestamp(expires)},
		{tufmetadata.SNAPSHOT, tufmetadata.Snapshot(expires)},
		{tufmetadata.TARGETS, tufmetadata.Targets(expires)},
	} {
		t.Run(tc.role, func(t *testing.T) {
			version, _, err := repo.PutVersionedFile(ctx, tc.role, tc.meta)
			require.NoError(t, err)
			assert.Equal(t, int64(1), version)
		})
	}
}

func TestRepository_PutVersionedFile_LandsAtExpectedFilename(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)

	root := tufmetadata.Root(time.Now().Add(time.Hour))
	root.Signed.Version = 7
	_, _, err := repo.PutVersionedFile(ctx, tufmetadata.ROOT, root)
	require.NoError(t, err)

	rdr, _, err := repo.GetBlob(ctx, "7.root.json")
	require.NoError(t, err)
	require.NoError(t, rdr.Close())
}

func TestRepository_PutVersionedFile_PutOption_WithAttribute(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)

	root := tufmetadata.Root(time.Now().Add(time.Hour))
	root.Signed.Version = 1

	_, _, err := repo.PutVersionedFile(ctx, tufmetadata.ROOT, root,
		storeopts.WithAttribute("purpose", "forward-check"))
	require.NoError(t, err)

	rdr, meta, err := repo.GetVersionedFile(ctx, tufmetadata.ROOT, 1)
	require.NoError(t, err)
	require.NoError(t, rdr.Close())
	assert.Equal(t, "forward-check", meta.Attributes["purpose"])

	// A second put at the same version must honour the no-clobber default.
	_, _, err = repo.PutVersionedFile(ctx, tufmetadata.ROOT, root)
	require.ErrorIs(t, err, storeopts.ErrETagMismatch)

	// And succeed when storeopts.Clobber is forwarded.
	_, _, err = repo.PutVersionedFile(ctx, tufmetadata.ROOT, root, storeopts.Clobber)
	require.NoError(t, err)
}

func TestRepository_PutVersionedFile_UnsupportedType(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)

	_, _, err := repo.PutVersionedFile(ctx, "bogus", "not-a-metadata-struct")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported type")
}

func TestRepository_GetVersionedFile_InvalidVersion(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)

	for _, v := range []int64{0, -1} {
		t.Run(fmt.Sprintf("v=%d", v), func(t *testing.T) {
			_, _, err := repo.GetVersionedFile(ctx, tufmetadata.ROOT, v)
			require.Error(t, err)
		})
	}
}

// recordingGetOpt is a test-only [storeopts.GetBlobOption] that records
// whether it was applied.
type recordingGetOpt struct {
	called *bool
}

func (r recordingGetOpt) ApplyGetBlob(_ *storeopts.GetBlobConfig) error {
	*r.called = true
	return nil
}

func TestRepository_GetBlob_DummyOption(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)

	ts := tufmetadata.Timestamp(time.Now().Add(time.Hour))
	_, err := repo.PutBlob(ctx, "timestamp.json", bytes.NewReader(mustEncode(t, ts)))
	require.NoError(t, err)

	root := tufmetadata.Root(time.Now().Add(time.Hour))
	_, _, err = repo.PutVersionedFile(ctx, tufmetadata.ROOT, root)
	require.NoError(t, err)

	t.Run("GetVersionedFile", func(t *testing.T) {
		var called bool
		rdr, _, err := repo.GetVersionedFile(ctx, tufmetadata.ROOT, 1, recordingGetOpt{called: &called})
		require.NoError(t, err)
		require.NoError(t, rdr.Close())
		assert.True(t, called)
	})
	t.Run("GetLatestTimestamp", func(t *testing.T) {
		var called bool
		_, _, err := repo.GetLatestTimestamp(ctx, recordingGetOpt{called: &called})
		require.NoError(t, err)
		assert.True(t, called)
	})
	t.Run("GetLatestRoot", func(t *testing.T) {
		var called bool
		_, _, err := repo.GetLatestRoot(ctx, recordingGetOpt{called: &called})
		require.NoError(t, err)
		assert.True(t, called)
	})
}

func TestRepository_GetLatestTimestamp(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)

	ts := tufmetadata.Timestamp(time.Now().Add(time.Hour))
	ts.Signed.Version = 5
	_, err := repo.PutBlob(ctx, "timestamp.json", bytes.NewReader(mustEncode(t, ts)))
	require.NoError(t, err)

	got, _, err := repo.GetLatestTimestamp(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(5), got.Signed.Version)
}

func TestRepository_GetLatestTimestamp_NotExist(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)

	_, _, err := repo.GetLatestTimestamp(ctx)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestRepository_GetLatestTimestamp_WrongRole(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)

	// Store a root.json payload as timestamp.json to make sure validate this
	// at GetLatestTimestamp time.
	root := tufmetadata.Root(time.Now().Add(time.Hour))
	_, err := repo.PutBlob(ctx, "timestamp.json", bytes.NewReader(mustEncode(t, root)))
	require.NoError(t, err)

	_, _, err = repo.GetLatestTimestamp(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid timestamp blob")
}

func TestRepository_GetLatestTimestamp_InvalidJSON(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)

	_, err := repo.PutBlob(ctx, "timestamp.json", bytes.NewReader([]byte("not json")))
	require.NoError(t, err)

	_, _, err = repo.GetLatestTimestamp(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse")
}

func TestRepository_GetLatestRoot_PicksHighestVersion(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)

	for _, v := range []int64{1, 2, 3} {
		root := tufmetadata.Root(time.Now().Add(time.Hour))
		root.Signed.Version = v
		_, _, err := repo.PutVersionedFile(ctx, tufmetadata.ROOT, root)
		require.NoError(t, err)
	}

	got, _, err := repo.GetLatestRoot(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(3), got.Signed.Version)
}

func TestRepository_GetLatestRoot_NoRoot(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)

	_, _, err := repo.GetLatestRoot(ctx)
	require.ErrorIs(t, err, tufrepo.ErrInvalidRepoState)
}

func TestRepository_GetLatestRoot_WrongRole(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)

	// Store a timestamp.json payload as root.json to make sure validate this
	// at GetLatestRoot time.
	ts := tufmetadata.Timestamp(time.Now().Add(time.Hour))
	_, err := repo.PutBlob(ctx, "1.root.json", bytes.NewReader(mustEncode(t, ts)))
	require.NoError(t, err)

	_, _, err = repo.GetLatestRoot(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid root blob")
}

// errorInjectingStore wraps a [tufrepo.RepoStore] and fails GetBlob for the
// keys in getBlobErrors. Used to exercise GetBlob error paths that aren't
// reachable through the public API otherwise.
type errorInjectingStore struct {
	tufrepo.RepoStore
	getBlobErrors map[string]error
}

func (s *errorInjectingStore) GetBlob(ctx context.Context, key string, opts ...storeopts.GetBlobOption) (io.ReadCloser, *tufrepo.BlobMetadata, error) {
	if err, ok := s.getBlobErrors[key]; ok {
		return nil, nil, err
	}
	return s.RepoStore.GetBlob(ctx, key, opts...)
}

func TestRepository_GetLatestRoot_IterationError(t *testing.T) {
	ctx := context.Background()

	inner, err := localrepo.Open(t.TempDir())
	require.NoError(t, err)

	boom := errors.New("injected boom")
	repo, err := tufrepo.Open(&errorInjectingStore{
		RepoStore:     inner,
		getBlobErrors: map[string]error{"2.root.json": boom},
	})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, repo.Close()) })

	root := tufmetadata.Root(time.Now().Add(time.Hour))
	_, _, err = repo.PutVersionedFile(ctx, tufmetadata.ROOT, root)
	require.NoError(t, err)

	// The iteration sees 1.root.json then hits the injected non-ErrNotExist
	// error on 2.root.json, which should abort rather than truncate.
	_, _, err = repo.GetLatestRoot(ctx)
	require.ErrorIs(t, err, boom)
}

// GetLatestRoot (by design) acts like a client and so if the repository
// somehow has a gap in the version numbers of root.json it will stop at the
// first gap.
func TestRepository_GetLatestRoot_VersionGap(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)

	for _, v := range []int64{1, 3} {
		root := tufmetadata.Root(time.Now().Add(time.Hour))
		root.Signed.Version = v
		_, _, err := repo.PutVersionedFile(ctx, tufmetadata.ROOT, root)
		require.NoError(t, err)
	}

	got, _, err := repo.GetLatestRoot(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), got.Signed.Version)
}
