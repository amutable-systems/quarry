// Copyright (C) 2026 Amutable GmbH

package localrepo_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.amutable.dev/quarry/internal/tufrepo"
	"go.amutable.dev/quarry/internal/tufrepo/localrepo"
	storeopts "go.amutable.dev/quarry/internal/tufrepo/opts"
)

func newTestRepo(t *testing.T) tufrepo.RepoStore {
	t.Helper()
	repo, err := localrepo.Open(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, repo.Close()) })
	return repo
}

// readAllClose reads the full contents of rdr and closes it.
func readAllClose(t *testing.T, rdr io.ReadCloser) []byte {
	t.Helper()
	defer rdr.Close() //nolint:errcheck // test code
	data, err := io.ReadAll(rdr)
	require.NoError(t, err)
	return data
}

func TestOpen_BadPath(t *testing.T) {
	_, err := localrepo.Open("/nonexistent/path/to/repo")
	assert.Error(t, err)
}

func TestPutGetBlob_RoundTrip(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)

	payload := []byte("hello world")
	putMeta, err := repo.PutBlob(ctx, "hello.txt", bytes.NewReader(payload))
	require.NoError(t, err)
	require.NotNil(t, putMeta)
	assert.NotEmpty(t, putMeta.ETag)

	rdr, getMeta, err := repo.GetBlob(ctx, "hello.txt")
	require.NoError(t, err)
	require.NotNil(t, getMeta)
	assert.Equal(t, putMeta.ETag, getMeta.ETag)
	assert.Equal(t, payload, readAllClose(t, rdr))
}

func TestGetBlob_NotExist(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)

	_, _, err := repo.GetBlob(ctx, "missing.txt")
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestPutBlob_NoClobberByDefault(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)

	_, err := repo.PutBlob(ctx, "a.txt", bytes.NewReader([]byte("v1")))
	require.NoError(t, err)

	_, err = repo.PutBlob(ctx, "a.txt", bytes.NewReader([]byte("v2")))
	require.ErrorIs(t, err, storeopts.ErrETagMismatch)

	rdr, _, err := repo.GetBlob(ctx, "a.txt")
	require.NoError(t, err)
	assert.Equal(t, []byte("v1"), readAllClose(t, rdr))
}

func TestPutBlob_Clobber(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)

	_, err := repo.PutBlob(ctx, "a.txt", bytes.NewReader([]byte("v1")))
	require.NoError(t, err)

	_, err = repo.PutBlob(ctx, "a.txt", bytes.NewReader([]byte("v2")), storeopts.Clobber)
	require.NoError(t, err)

	rdr, _, err := repo.GetBlob(ctx, "a.txt")
	require.NoError(t, err)
	assert.Equal(t, []byte("v2"), readAllClose(t, rdr))
}

func TestPutBlob_IfETagMatches(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)

	meta, err := repo.PutBlob(ctx, "a.txt", bytes.NewReader([]byte("v1")))
	require.NoError(t, err)

	// Matching ETag clobbers.
	newMeta, err := repo.PutBlob(ctx, "a.txt", bytes.NewReader([]byte("v2")),
		storeopts.IfETagMatches(meta.ETag))
	require.NoError(t, err)

	// Stale ETag now fails.
	_, err = repo.PutBlob(ctx, "a.txt", bytes.NewReader([]byte("v3")),
		storeopts.IfETagMatches(meta.ETag))
	require.ErrorIs(t, err, storeopts.ErrETagMismatch)

	rdr, getMeta, err := repo.GetBlob(ctx, "a.txt")
	require.NoError(t, err)
	assert.Equal(t, newMeta.ETag, getMeta.ETag)
	assert.Equal(t, []byte("v2"), readAllClose(t, rdr))
}

func TestPutBlob_WithAttributes(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)

	want := map[string]string{"role": "root", "version": "1"}
	_, err := repo.PutBlob(ctx, "a.txt", bytes.NewReader([]byte("data")),
		storeopts.WithAttribute("role", "root"),
		storeopts.WithAttribute("version", "1"),
	)
	require.NoError(t, err)

	_, meta, err := repo.GetBlob(ctx, "a.txt")
	require.NoError(t, err)
	require.NotNil(t, meta)
	assert.Equal(t, want, meta.Attributes)
}

func TestDeleteBlob_NotExist(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)

	assert.NoError(t, repo.DeleteBlob(ctx, "missing.txt"))
	assert.NoError(t, repo.DeleteBlob(ctx, "missing.txt",
		storeopts.IfETagMatches(storeopts.WildcardETag)))
}

func TestDeleteBlob_RequiresPolicy(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)

	_, err := repo.PutBlob(ctx, "a.txt", bytes.NewReader([]byte("data")))
	require.NoError(t, err)

	err = repo.DeleteBlob(ctx, "a.txt")
	require.ErrorIs(t, err, storeopts.ErrETagMismatch)

	_, _, err = repo.GetBlob(ctx, "a.txt")
	require.NoError(t, err)
}

func TestDeleteBlob_IfETagMatches(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)

	meta, err := repo.PutBlob(ctx, "a.txt", bytes.NewReader([]byte("data")))
	require.NoError(t, err)

	// Stale ETag -> delete fails and the file survives.
	err = repo.DeleteBlob(ctx, "a.txt", storeopts.IfETagMatches(storeopts.ETag("stale")))
	require.ErrorIs(t, err, storeopts.ErrETagMismatch)
	_, _, err = repo.GetBlob(ctx, "a.txt")
	require.NoError(t, err)

	// Matching ETag -> delete succeeds.
	err = repo.DeleteBlob(ctx, "a.txt", storeopts.IfETagMatches(meta.ETag))
	require.NoError(t, err)
	_, _, err = repo.GetBlob(ctx, "a.txt")
	assert.ErrorIs(t, err, os.ErrNotExist)
}

// Races PutBlob(Clobber) against DeleteBlob(wildcard) to exercise the retry
// path when linkat-EEXIST is followed by Open returning ErrNotExist.
func TestPutBlob_RetriesWhenUnlinked(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	repo := newTestRepo(t)

	// Seed so the first DeleteBlob iteration has something to delete.
	_, err := repo.PutBlob(ctx, "race", bytes.NewReader([]byte("seed")))
	require.NoError(t, err)

	const iters = 100
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for range iters {
			_, err := repo.PutBlob(ctx, "race", bytes.NewReader([]byte("put")), storeopts.Clobber)
			if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				assert.NoError(t, err, "concurrent PutBlob")
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for range iters {
			err := repo.DeleteBlob(ctx, "race", storeopts.IfETagMatches(storeopts.WildcardETag))
			if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				assert.NoError(t, err, "concurrent DeleteBlob")
				return
			}
		}
	}()
	wg.Wait()
	require.NoError(t, ctx.Err(), "race operations did not complete within deadline")
}

// failingReader yields prefix bytes then fails.
type failingReader struct {
	prefix []byte
	err    error
}

func (r *failingReader) Read(p []byte) (int, error) {
	if len(r.prefix) > 0 {
		n := copy(p, r.prefix)
		r.prefix = r.prefix[n:]
		return n, nil
	}
	return 0, r.err
}

func TestPutBlob_ReaderError(t *testing.T) {
	ctx := context.Background()

	dir := t.TempDir()
	repo, err := localrepo.Open(dir)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, repo.Close()) })

	boom := errors.New("reader boom")
	_, err = repo.PutBlob(ctx, "dead.txt", &failingReader{prefix: []byte("partial"), err: boom})
	require.ErrorIs(t, err, boom)

	_, _, err = repo.GetBlob(ctx, "dead.txt")
	require.ErrorIs(t, err, os.ErrNotExist)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Empty(t, entries, "failed PutBlob leaked files")
}

func TestPutBlob_ConflictingOptions(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)

	_, err := repo.PutBlob(ctx, "x.txt", bytes.NewReader([]byte("data")),
		storeopts.IfETagMatches("one"),
		storeopts.IfETagMatches("two"),
	)
	assert.ErrorIs(t, err, storeopts.ErrIncompatibleOptions)
}

func TestDeleteBlob_ConflictingOptions(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)

	err := repo.DeleteBlob(ctx, "x.txt",
		storeopts.IfETagMatches("one"),
		storeopts.IfETagMatches("two"),
	)
	assert.ErrorIs(t, err, storeopts.ErrIncompatibleOptions)
}

func TestDeleteBlob_WildcardClobber(t *testing.T) {
	ctx := context.Background()
	repo := newTestRepo(t)

	_, err := repo.PutBlob(ctx, "a.txt", bytes.NewReader([]byte("data")))
	require.NoError(t, err)

	err = repo.DeleteBlob(ctx, "a.txt", storeopts.IfETagMatches(storeopts.WildcardETag))
	require.NoError(t, err)

	_, _, err = repo.GetBlob(ctx, "a.txt")
	assert.ErrorIs(t, err, os.ErrNotExist)
}
