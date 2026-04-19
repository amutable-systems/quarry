// Copyright (C) 2026 Amutable GmbH

// Package tufrepo provides helpers for managing a TUF repo directory.
package tufrepo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"

	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/third_party/funchelpers"
	"go.amutable.dev/quarry/internal/tufext"
	storeopts "go.amutable.dev/quarry/internal/tufrepo/opts"
)

// ErrInvalidRepoState is returned from operations which find that a
// repository's state is invalid or cannot be interpreted in a sane way.
var ErrInvalidRepoState = errors.New("invalid repository state")

// BlobMetadata is a generic set of metadata that is associated with keys in
// [RepoStore].
type BlobMetadata struct {
	// ETag is the object's entity tag, an opaque string that can be used to
	// detect whether an object has changed (and can be combined with
	// [ClobberIfMatches] to implement an atomic compare-and-swap operation
	// when uploading).
	ETag storeopts.ETag

	// Attributes is a map of custom attributes associated with the object.
	Attributes map[string]string
}

// RepoStore is the base set of operations needed to use [Repository] and
// [Transaction] operations. It is only really intended for storing the TUF
// *metadata* repository, not target files.
type RepoStore interface {
	// GetBlob returns a reader for a given key in the repo.
	GetBlob(ctx context.Context, key string, opts ...storeopts.GetBlobOption) (io.ReadCloser, *BlobMetadata, error)

	// PutBlob updates the given key with the contents of the given reader. The
	// passed [storeopts.PutBlobOption]s can be used to control the cloberring
	// semantics of the upload.
	PutBlob(ctx context.Context, key string, data io.Reader, opts ...storeopts.PutBlobOption) (*BlobMetadata, error)

	// DeleteBlob deletes the key. The passed [storeopts.DeleteBlobOption] can
	// be used to control the deletion semantics of the upload.
	DeleteBlob(ctx context.Context, key string, opts ...storeopts.DeleteBlobOption) error

	// Close releases any resources held by the store.
	Close() error
}

// Repository is a representation of the metadata in a TUF repository for
// management purposes. Target file blobs are not intended to be managed
// through this API.
type Repository struct {
	RepoStore
}

// GetLatestTimestamp returns the latest copy of the repository timestamp file.
func (repo *Repository) GetLatestTimestamp(ctx context.Context, opts ...storeopts.GetBlobOption) (_ *tufmetadata.Metadata[tufmetadata.TimestampType], _ *BlobMetadata, Err error) {
	const timestampFile = tufmetadata.TIMESTAMP + ".json"

	rdr, fileMeta, err := repo.GetBlob(ctx, timestampFile, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("could not get latest timestamp: %w", err)
	}
	defer funchelpers.VerifyClose(&Err, rdr)

	var timestamp tufmetadata.Metadata[tufmetadata.TimestampType]
	// TODO: Should we use a HardenedLimitReader here?
	if err := json.NewDecoder(rdr).Decode(&timestamp); err != nil {
		return nil, nil, fmt.Errorf("failed to parse latest timestamp: %w", err)
	}
	if err := tufext.CheckMetadataType(tufmetadata.TIMESTAMP, &timestamp); err != nil {
		return nil, nil, fmt.Errorf("invalid timestamp blob: %w", err)
	}
	return &timestamp, fileMeta, nil
}

// GetLatestRoot returns the latest version of the repository root file.
func (repo *Repository) GetLatestRoot(ctx context.Context, opts ...storeopts.GetBlobOption) (*tufmetadata.Metadata[tufmetadata.RootType], *BlobMetadata, error) {
	// TODO: We probably need to implement some kind of ListObjects API to
	// RepoStore, this is not particularly efficient and while it is necessary
	// for clients to do it this way, we have privileged access to the backing
	// store.

	var (
		latestRdr      io.ReadCloser
		latestBlobMeta *BlobMetadata
	)
	defer func() {
		if latestRdr != nil {
			_ = latestRdr.Close()
		}
	}()
	for version := 1; version < math.MaxInt32; version++ {
		filename := fmt.Sprintf("%d.root.json", version)
		rdr, fileMeta, err := repo.GetBlob(ctx, filename, opts...)
		// TODO: Make sure this works with s3repo...?
		if errors.Is(err, fs.ErrNotExist) {
			// We hit the latest root.json in the last iteration.
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("expected error while iterating for latest root.json: get %s failed: %w", filename, err)
		}
		if latestRdr != nil {
			_ = latestRdr.Close()
		}
		latestRdr, latestBlobMeta = rdr, fileMeta
	}
	if latestRdr == nil {
		return nil, nil, fmt.Errorf("repository has no root: %w", ErrInvalidRepoState)
	}

	var root tufmetadata.Metadata[tufmetadata.RootType]
	// TODO: Should we use a HardenedLimitReader here?
	if err := json.NewDecoder(latestRdr).Decode(&root); err != nil {
		return nil, nil, fmt.Errorf("failed to parse latest root: %w", err)
	}
	if err := tufext.CheckMetadataType(tufmetadata.ROOT, &root); err != nil {
		return nil, nil, fmt.Errorf("invalid root blob: %w", err)
	}
	return &root, latestBlobMeta, nil
}

func metaVersion(meta any) (*int64, error) {
	switch meta := meta.(type) {
	case *tufmetadata.Metadata[tufmetadata.RootType]:
		return &meta.Signed.Version, nil
	case *tufmetadata.Metadata[tufmetadata.TimestampType]:
		return &meta.Signed.Version, nil
	case *tufmetadata.Metadata[tufmetadata.SnapshotType]:
		return &meta.Signed.Version, nil
	case *tufmetadata.Metadata[tufmetadata.TargetsType]:
		return &meta.Signed.Version, nil
	default:
		return nil, fmt.Errorf("unsupported type %T", meta)
	}
}

// GetVersionedFile is shorthand for [RepoStore.GetBlob] to get a versioned TUF
// metadata file. The fetched key will be "version.role-name.json".
func (repo *Repository) GetVersionedFile(ctx context.Context, roleName string, version int64, opts ...storeopts.GetBlobOption) (io.ReadCloser, *BlobMetadata, error) {
	if version <= 0 {
		return nil, nil, fmt.Errorf("invalid version number %d", version)
	}
	filename := fmt.Sprintf("%d.%s.json", version, roleName)
	return repo.GetBlob(ctx, filename, opts...)
}

// PutVersionedFile is shorthand for [RepoStore.PutBlob] to store a versioned
// TUF metadata file. The stored key will be "version.role-name.json".
func (repo *Repository) PutVersionedFile(ctx context.Context, roleName string, roleData any, opts ...storeopts.PutBlobOption) (int64, *BlobMetadata, error) {
	// TODO: We can grab the version from the encoded data as well but that
	// seems less than ideal...

	version, err := metaVersion(roleData)
	if err != nil {
		return -1, nil, fmt.Errorf("cannot compute version for %s role (type %T): %w", roleName, roleData, err)
	}
	filename := fmt.Sprintf("%d.%s.json", *version, roleName)

	payload, err := cjson.EncodeCanonical(roleData)
	if err != nil {
		return -1, nil, fmt.Errorf("failed to encode %s role data (type %T): %w", roleName, roleData, err)
	}
	buf := bytes.NewReader(payload)

	meta, err := repo.PutBlob(ctx, filename, buf, opts...)
	return *version, meta, err
}

// Open returns a new [Repository] using the given [RepoStore] as a backend.
//
// Once a [Repository] is created, the ownership of the backing [RepoStore] is
// transferred to the repository and thus you should not call [Close] on the
// original [RepoStore].
// Once this function returns
//
// TODO: Should we have a keystore-like driver setup...?
func Open(store RepoStore) (*Repository, error) {
	return &Repository{RepoStore: store}, nil
}

// Close releases the underlying resources of the [Repository] and the
// underlying [RepoStore].
func (repo *Repository) Close() error {
	return repo.RepoStore.Close()
}
