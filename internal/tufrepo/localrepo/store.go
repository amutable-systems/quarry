// Copyright (C) 2026 Amutable GmbH

// Package localrepo implements a basic local directory-backed
// [storeopts.RepoStore] for debugging and testing purposes.
package localrepo

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"

	"cyphar.com/go-pathrs"
	"golang.org/x/sys/unix"

	"go.amutable.dev/quarry/internal/pathrsext"
	"go.amutable.dev/quarry/internal/third_party/fdutils"
	"go.amutable.dev/quarry/internal/third_party/funchelpers"
	"go.amutable.dev/quarry/internal/tufrepo"
	storeopts "go.amutable.dev/quarry/internal/tufrepo/opts"
)

type localRepository struct {
	rootDir *pathrs.Root
}

var _ tufrepo.RepoStore = &localRepository{}

func fileMeta(file *os.File) (*tufrepo.BlobMetadata, error) {
	// TODO: Should we include the hash of the file contents in the ETag...?
	etag, err := fileEtag(file)
	if err != nil {
		return nil, fmt.Errorf("could not generate etag for %s: %w", file.Name(), err)
	}
	attrs, err := getFileAttrs(file)
	if err != nil {
		return nil, fmt.Errorf("could not get xattrs for %s: %w", file.Name(), err)
	}
	return &tufrepo.BlobMetadata{
		ETag:       etag,
		Attributes: attrs,
	}, nil
}

func (repo *localRepository) GetBlob(_ context.Context, filename string, opts ...storeopts.GetBlobOption) (_ io.ReadCloser, _ *tufrepo.BlobMetadata, Err error) {
	var cfg storeopts.GetBlobConfig
	for _, opt := range opts {
		if err := opt.ApplyGetBlob(&cfg); err != nil {
			return nil, nil, err
		}
	}

	file, err := repo.rootDir.Open(filename)
	if err != nil {
		return nil, nil, err
	}
	defer funchelpers.CloseOnError(Err, file)

	meta, err := fileMeta(file)
	if err != nil {
		return nil, nil, err
	}
	return file, meta, nil
}

const putBlobMaxRetries = 256

// TODO: XFS has XFS_IOC_START_COMMIT / XFS_IOC_COMMIT_RANGE which is even more
// powerful than ETags but is obviously not generic. Should we use it?

func (repo *localRepository) PutBlob(ctx context.Context, filename string, rdr io.Reader, opts ...storeopts.PutBlobOption) (_ *tufrepo.BlobMetadata, Err error) {
	var cfg storeopts.PutBlobConfig
	for _, opt := range opts {
		if err := opt.ApplyPutBlob(&cfg); err != nil {
			return nil, err
		}
	}

	blobFile, err := repo.rootDir.Create(".", unix.O_TMPFILE|unix.O_NOFOLLOW|unix.O_RDWR, 0o644)
	if err != nil {
		return nil, fmt.Errorf("could not open temporary file for new key data: %w", err)
	}
	defer funchelpers.VerifyClose(&Err, blobFile)

	// TODO: Make this cancellable with ctx?
	if _, err := io.Copy(blobFile, rdr); err != nil {
		return nil, err
	}

	etag, err := fileEtag(blobFile)
	if err != nil {
		return nil, fmt.Errorf("failed to get etag for %s tmpfile: %w", filename, err)
	}
	if err := setFileAttrs(blobFile, cfg.Attributes); err != nil {
		return nil, fmt.Errorf("failed to set attributes for %s tmpfile: %w", filename, err)
	}
	blobMeta := &tufrepo.BlobMetadata{
		ETag:       etag,
		Attributes: cfg.Attributes,
	}

	if err := blobFile.Sync(); err != nil {
		return nil, err
	}

	// We cannot handle both the non-existent and existent cases atomically.
	// O_CREAT (with O_EXCL) would let us create-or-open the target file but
	// then readers would see an empty file until we write to it in the
	// creation case.

	var oldBlobFile *os.File
	defer func() {
		if oldBlobFile != nil {
			_ = oldBlobFile.Close()
		}
	}()

	var tries uint
	for {
		if oldBlobFile != nil {
			// Clear oldBlobFile from a previous iteration.
			_ = oldBlobFile.Close()
			oldBlobFile = nil
		}

		tries++
		if tries > putBlobMaxRetries {
			return nil, fmt.Errorf("too many tmpfile attach attempts for %s: putblob aborted", filename)
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		// First try the happy path (no clobbering) -- linkat(AT_EMPTY_PATH).
		if err := pathrsext.AttachIntoRoot(repo.rootDir, filename, blobFile); err == nil {
			// Nothing left to do, we managed to attach the file atomically.
			return blobMeta, nil
		} else if !errors.Is(err, os.ErrExist) {
			// If a non-EEXIST, some other error occurred.
			return nil, fmt.Errorf("unexpected error when attaching tmpfile to %s: %w", filename, err)
		}

		// Okay, there was a file there already. Let's try to get a handle to
		// the existing file.
		oldBlobFile, err = repo.rootDir.Open(filename)
		if errors.Is(err, os.ErrNotExist) {
			// The file was unlinked, try again.
			// TODO: Log this.
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("unexpected error when getting current %s file: %w", filename, err)
		}

		// This is not enough -- a racing DeleteBlob could unlink it at any
		// point after we got a handle to it. So grab a read (shared) lock and
		// then verify that nlink > 0.

		if err := flockCtx(ctx, oldBlobFile, unix.LOCK_SH); err != nil {
			return nil, fmt.Errorf("get shared lock on %s: %w", filename, err)
		}
		stat, err := fdutils.Fstat(oldBlobFile)
		if err != nil {
			return nil, fmt.Errorf("failed to fstat %s: %w", filename, err)
		}
		if stat.Nlink > 0 {
			// The file is still linked while we have a shared lock, meaning we
			// are guaranteed the file will not change nor get deleted.
			break
		}
	}

	// Check the ETag against the PutBlobOption policy.
	oldETag, err := fileEtag(oldBlobFile)
	if err != nil {
		return nil, fmt.Errorf("failed to get etag for old blob %s: %w", filename, err)
	}
	if err := etagMatches(oldETag, cfg.ClobberIfMatches); err != nil {
		return nil, err
	}

	// Okay, we are safe to grab a write lock and overwrite the file.
	if err := flockCtx(ctx, oldBlobFile, unix.LOCK_EX); err != nil {
		return nil, fmt.Errorf("upgrade to exclusive lock on %s: %w", filename, err)
	}

	// As mentioned above, we cannot clobber the target file with
	// linkat(AT_EMPTY_PATH) so we need to link to a temporary file first and
	// then overwrite the file with rename.
	var tmpFilename string
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		tmpFilename = "." + filename + "." + rand.Text()
		if err := pathrsext.AttachIntoRoot(repo.rootDir, tmpFilename, blobFile); err == nil {
			break
		} else if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("failed to attack to temporary file: %w", err)
		}
	}
	if err := repo.rootDir.Rename(tmpFilename, filename, 0); err != nil {
		return nil, fmt.Errorf("overwrite %s: %w", filename, err)
	}
	return blobMeta, nil
}

func (repo *localRepository) DeleteBlob(ctx context.Context, filename string, opts ...storeopts.DeleteBlobOption) (Err error) {
	var cfg storeopts.DeleteBlobConfig
	for _, opt := range opts {
		if err := opt.ApplyDeleteBlob(&cfg); err != nil {
			return err
		}
	}

	oldBlobFile, err := repo.rootDir.Open(filename)
	if errors.Is(err, os.ErrNotExist) {
		// Blob is gone, our job is already done!
		return nil
	}
	if err != nil {
		return fmt.Errorf("unexpected error when getting current %s file: %w", filename, err)
	}
	defer funchelpers.VerifyClose(&Err, oldBlobFile)

	// This blob could get removed by a racing DeleteBlob so get a shared lock
	// and make sure the nlink > 0. This mirrors the same logic in PutBlob.
	if err := flockCtx(ctx, oldBlobFile, unix.LOCK_SH); err != nil {
		return fmt.Errorf("get shared lock on %s: %w", filename, err)
	}
	stat, err := fdutils.Fstat(oldBlobFile)
	if err != nil {
		return fmt.Errorf("failed to fstat %s: %w", filename, err)
	}
	if stat.Nlink <= 0 {
		// Blob is gone, our job is already done!
		return nil
	}

	// Check the ETag against the DeleteBlobOption policy.
	oldETag, err := fileEtag(oldBlobFile)
	if err != nil {
		return fmt.Errorf("failed to get etag for old blob %s: %w", filename, err)
	}
	if err := etagMatches(oldETag, cfg.IfMatches); err != nil {
		return err
	}

	// Okay, we are safe to grab a write lock and unlink the file.
	if err := flockCtx(ctx, oldBlobFile, unix.LOCK_EX); err != nil {
		return fmt.Errorf("upgrade to exclusive lock on %s: %w", filename, err)
	}
	if err := repo.rootDir.Remove(filename); err != nil {
		return fmt.Errorf("unlink %s: %w", filename, err)
	}
	return nil
}

// Close releases the underlying directory handle.
func (repo *localRepository) Close() error {
	return repo.rootDir.Close()
}

// Open returns a [tufrepo.RepoStore], backed by the given local directory.
func Open(dirPath string) (tufrepo.RepoStore, error) {
	root, err := pathrs.OpenRoot(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open localrepo %q: %w", dirPath, err)
	}
	return &localRepository{rootDir: root}, nil
}
