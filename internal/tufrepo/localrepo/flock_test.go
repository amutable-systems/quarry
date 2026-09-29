// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package localrepo

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func openLockFile(t *testing.T, dir string) *os.File {
	t.Helper()
	path := filepath.Join(dir, "lock")                        //nolint:forbidigo // test code
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644) //nolint:forbidigo // test code
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func TestFlockCtx_ExclusiveAcquire(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	f := openLockFile(t, t.TempDir())
	require.NoError(t, flockCtx(ctx, f, unix.LOCK_EX))
}

func TestFlockCtx_SharedLocksCoexist(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	dir := t.TempDir()
	f1 := openLockFile(t, dir)
	f2 := openLockFile(t, dir)

	require.NoError(t, flockCtx(ctx, f1, unix.LOCK_SH))
	require.NoError(t, flockCtx(ctx, f2, unix.LOCK_SH))
}

func TestFlockCtx_CancelOnContention(t *testing.T) {
	dir := t.TempDir()

	// Hold LOCK_EX via a separate fd so flockCtx blocks on its non-blocking attempt.
	blocker := openLockFile(t, dir)
	require.NoError(t, unix.Flock(int(blocker.Fd()), unix.LOCK_EX))
	t.Cleanup(func() { _ = unix.Flock(int(blocker.Fd()), unix.LOCK_UN) })

	contender := openLockFile(t, dir)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	err := flockCtx(ctx, contender, unix.LOCK_EX)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}
