// Copyright (C) 2026 Amutable GmbH

package tufrepo

import (
	"context"

	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"
)

// HashMetaFile exposes hashMetaFile to tests in the external tufrepo_test
// package so the bootstrap helpers use the same hashing logic as the
// production code.
func HashMetaFile[T tufmetadata.Roles](ctx context.Context, meta *tufmetadata.Metadata[T]) (*tufmetadata.MetaFiles, error) {
	return hashMetaFile(ctx, meta)
}

// ErrMismatchedRole is exported for tests that want to assert the sentinel
// returned by [Transaction.UpdateRoleData] when the payload's _type does not
// match the target role.
var ErrMismatchedRole = errMismatchedRole
