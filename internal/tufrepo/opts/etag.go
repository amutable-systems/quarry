// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package opts

import (
	"fmt"
)

// WildcardETag is a special-case ETag value that indicates anything is
// allowed. It is used by [Clobber] to indicate that the target file should be
// clobbered regardless of its previous contents.
const WildcardETag ETag = "*"

// ETag is an opaque string that uniquely identifies a particular blob's state,
// for the purposes of implementing compare-and-swap operations (such as
// If-Matches with HTTP APIs). This tag only has meaning for the particular
// blob store that generated it.
type ETag string

type ifEtagMatchesOption struct {
	etag ETag
}

func (opt ifEtagMatchesOption) apply(etagSlot **ETag) error {
	etag := opt.etag // local copy for escape analysis
	if *etagSlot != nil && **etagSlot != etag {
		return fmt.Errorf("%w: conflicting clobber-if-matches rules: old %q and new %q are incompatible", ErrIncompatibleOptions, **etagSlot, etag)
	}
	*etagSlot = &etag
	return nil
}

var _ PutBlobOption = ifEtagMatchesOption{}

func (opt ifEtagMatchesOption) ApplyPutBlob(cfg *PutBlobConfig) error {
	return opt.apply(&cfg.ClobberIfMatches)
}

var _ DeleteBlobOption = ifEtagMatchesOption{}

func (opt ifEtagMatchesOption) ApplyDeleteBlob(cfg *DeleteBlobConfig) error {
	return opt.apply(&cfg.IfMatches)
}

// IfETagMatches indicates that this operation should only succeed if the
// target object has a matching ETag. This is roughly intended to be a generic
// representation of If-Matches for all RepoStore backends.
//
// The returned option implements both [PutBlobOption] and [DeleteBlobOption].
func IfETagMatches(etag ETag) interface {
	PutBlobOption
	DeleteBlobOption
} {
	return ifEtagMatchesOption{etag: etag}
}
