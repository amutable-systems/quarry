// Copyright (C) 2026 Amutable GmbH

package localrepo

import (
	"context"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"

	"go.amutable.dev/quarry/internal/chanhelpers"
	"go.amutable.dev/quarry/internal/third_party/fdutils"
)

// flockCtx tries to acquire the requested [unix.Flock] lock but in a way that
// is cancellable with [context.Context].
func flockCtx(ctx context.Context, file *os.File, flockFlags int) error {
	ch := chanhelpers.GoRetryCtx(ctx, func() *chanhelpers.Result[struct{}] {
		err := fdutils.WithFileFd(file, func(fd uintptr) error {
			err := unix.Flock(int(fd), flockFlags|unix.LOCK_NB)
			return os.NewSyscallError("flock", err)
		})
		if errors.Is(err, unix.EWOULDBLOCK) {
			// The lock failed, return nil so that GoRetryCtx will retry.
			return nil
		}
		return &chanhelpers.Result[struct{}]{Err: err} // ok is zero value
	})
	select {
	case result := <-ch:
		if _, err := result.Unwrap(); err != nil {
			return fmt.Errorf("failed to acquire lock on %s: %w", file.Name(), err)
		}
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}
