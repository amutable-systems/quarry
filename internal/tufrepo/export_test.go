// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package tufrepo

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"
)

// HashMetaFile exposes hashMetaFile to tests in the external tufrepo_test
// package so the bootstrap helpers use the same hashing logic as the
// production code.
func HashMetaFile[T tufmetadata.Roles](ctx context.Context, meta *tufmetadata.Metadata[T]) (*tufmetadata.MetaFiles, error) {
	return hashMetaFile(ctx, meta)
}

// SignedVersion extracts the Signed.Version field from any of the four TUF
// role metadata types, delegating to [metaVersion].
func SignedVersion(t *testing.T, meta any) int64 {
	t.Helper()
	slot, err := metaVersion(meta)
	require.NoError(t, err)
	return *slot
}

// SignedExpires extracts the Signed.Expires field from any of the four TUF
// role metadata types, delegating to [metaExpiry].
func SignedExpires(t *testing.T, meta any) time.Time {
	t.Helper()
	slot, err := metaExpiry(meta)
	require.NoError(t, err)
	return *slot
}

// ErrMismatchedRole is exported for tests that want to assert the sentinel
// returned by [Transaction.UpdateRoleData] when the payload's _type does not
// match the target role.
var ErrMismatchedRole = errMismatchedRole
