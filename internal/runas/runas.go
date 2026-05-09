// Copyright (C) 2026 Amutable GmbH

// Package runas provides a helper to run a function as a different user and
// then restoring privileges later.
package runas

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"

	"go.amutable.dev/quarry/internal/goext"
)

// setresuid is a version of [unix.Setresuid] which does not synchronise the
// change in uid with threads (this matches Go's behaviour until Go 1.16 and
// commit d1b1145cace8 ("syscall: support POSIX semantics for Linux
// syscalls")). This operation is unsafe to do without the right precautions.
func setresuid(uid, euid, suid int) error {
	_, _, errno := syscall.Syscall(syscall.SYS_SETRESUID,
		uintptr(uid), uintptr(euid), uintptr(suid))
	if errno != 0 {
		return os.NewSyscallError("setresuid", errno)
	}
	return nil
}

// setresgid is a version of [unix.Setresgid] which does not synchronise the
// change in gid with threads (this matches Go's behaviour until Go 1.16 and
// commit d1b1145cace8 ("syscall: support POSIX semantics for Linux
// syscalls")). This operation is unsafe to do without the right precautions.
func setresgid(gid, egid, sgid int) error {
	_, _, errno := syscall.Syscall(syscall.SYS_SETRESGID,
		uintptr(gid), uintptr(egid), uintptr(sgid))
	if errno != 0 {
		return os.NewSyscallError("setresgid", errno)
	}
	return nil
}

// User runs the given function as the uid and gid of the named user.
func User(ctx context.Context, name string, fn func() error) (Err error) {
	info, err := user.Lookup(name)
	if err != nil {
		// Fallback to doing a uid-based lookup.
		if _, err2 := strconv.Atoi(name); err2 == nil {
			info, err = user.LookupId(name)
		}
	}
	if err != nil {
		return fmt.Errorf("look up user %q: %w", name, err)
	}
	targetUID, err := strconv.Atoi(info.Uid)
	if err != nil {
		// Should never happen on Linux.
		return fmt.Errorf("user %q has non-numeric uid %q: %w", name, info.Uid, err)
	}
	targetGID, err := strconv.Atoi(info.Gid)
	if err != nil {
		// Should never happen on Linux.
		return fmt.Errorf("user %q has non-numeric gid %q: %w", name, info.Gid, err)
	}

	errCh := goext.GoErr(func() error {
		_, currentUID, _ := unix.Getresuid()
		_, currentGID, _ := unix.Getresgid()

		// Only switch users if we are not the target user already.
		if currentUID != targetUID || currentGID != targetGID {
			// Make sure the callback function doesn't get scheduled onto a
			// different OS thread that has different privileges (or vice-versa
			// -- a different goroutine gets scheduled on this thread and gets
			// weird permissions).
			//
			// By not calling [runtime.UnlockOSThread], we are guaranteed that
			// once this function returns the goroutine spawned will be killed.
			runtime.LockOSThread()

			// Keep the real uid and gid so we can switch back -- we only care
			// about fs{u,g}id here (which we set via effective {u,g}id).
			if err := setresgid(-1, targetGID, -1); err != nil {
				return fmt.Errorf("failed to set egid to %d: %w", targetGID, err)
			}
			if err := setresuid(-1, targetUID, -1); err != nil {
				return fmt.Errorf("failed to set euid to %d: %w", targetUID, err)
			}
		}
		return fn()
	})

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// TODO: Should we add a helper for spawning a subprocess with run0?
