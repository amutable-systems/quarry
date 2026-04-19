// Copyright (C) 2026 Amutable GmbH

package opts

// DeleteBlobConfig is the internal configuration structure used by
// RepoStore.DeleteBlob.
type DeleteBlobConfig struct {
	// IfMatches contains the ETag that the target object must match in order
	// for the [RepoStore.DeleteBlob] operation to succeed. The special value
	// [WildcardETag] indicates that DeleteBlob should delete the target
	// regardless of its contents.
	IfMatches *ETag
}

// DeleteBlobOption is an argument to pass to RepoStore.DeleteBlob.
type DeleteBlobOption interface {
	ApplyDeleteBlob(*DeleteBlobConfig) error
}
