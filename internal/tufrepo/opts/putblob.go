// Copyright (C) 2026 Amutable GmbH

package opts

import (
	"fmt"
)

// PutBlobConfig is the internal configuration structure used by
// RepoStore.PutBlob.
type PutBlobConfig struct {
	// ClobberIfMatches contains the ETag that the target object must match in
	// order for the [RepoStore.PutBlob] operation to succeed. The special
	// value [WildcardETag] indicates that PubBlob should clobber the target
	// file regardless of its contents, and the value "" or nil indicates that
	// PutBlob should not clobber the target file.
	ClobberIfMatches *ETag

	// Attributes is the map of metadata that should be stored.
	Attributes map[string]string
}

// TODO: We could probably have an ApplyPutBlob impl for PutBlobConfig.

// PutBlobOption is an argument to pass to RepoStore.PutBlob.
type PutBlobOption interface {
	ApplyPutBlob(*PutBlobConfig) error
}

type putBlobOptionFunc func(cfg *PutBlobConfig) error

func (fn putBlobOptionFunc) ApplyPutBlob(cfg *PutBlobConfig) error { return fn(cfg) }

// WithAttribute configures a key to be associated with the blob being pushed
// with [RepoStore.PutBlob]. When the blob is later fetched with
// [RepoStore.GetBlob], the returned [tufrepo.FileMetadata] will contain these
// attributes.
func WithAttribute(key, value string) PutBlobOption {
	return putBlobOptionFunc(func(cfg *PutBlobConfig) error {
		// TODO: We should probably check that the key is safe for URL headers
		// and xattrs names here?
		if cfg.Attributes == nil {
			cfg.Attributes = make(map[string]string)
		}
		if old, set := cfg.Attributes[key]; set {
			return fmt.Errorf("%w: cannot set attribute %q to value %q as it already has value %q", ErrIncompatibleOptions, key, value, old)
		}
		cfg.Attributes[key] = value
		return nil
	})
}

// Clobber will cause [RepoStore.PutBlob] to replace any existing value for the
// given key. By default, [RepoStore.PutBlob] will not clobber a target key if
// it exsts.
//
// This is equivalent to [ClobberIfMatches]([WildcardETag]).
var Clobber = ClobberIfMatches(WildcardETag)

// NoClobber will cause [RepoStore.PutBlob] to not replace a target key if it
// already exists. This is the default behaviour, and so this option only
// exists to allow callers to explicitly specify they want no-clobber
// behaviour.
//
// This is equivalent to [ClobberIfMatches]("").
var NoClobber = ClobberIfMatches("")

// ClobberIfMatches will cause [RepoStore.PutBlob] to clobber the target key
// iff. the ETag matches the one provided. [RepoStore] must guarantee that this
// operation is atomic with respect to other writers.
//
// This is just a wrapper around [IfETagMatches].
func ClobberIfMatches(etag ETag) PutBlobOption {
	return IfETagMatches(etag)
}
