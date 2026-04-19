// Copyright (C) 2026 Amutable GmbH

package opts

// GetBlobConfig is the internal configuration structure used by
// RepoStore.GetBlob.
//
// It is currently a no-op.
type GetBlobConfig struct{}

// GetBlobOption is an argument to pass to RepoStore.GetBlob.
type GetBlobOption interface {
	ApplyGetBlob(*GetBlobConfig) error
}
