// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

// Package systemdcmd provides minor wrappers for executing systemd-* commands.
package systemdcmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
)

const systemdCmdPrefix = "/usr/lib/systemd/systemd-"

// FindCmd returns the path to the given systemd-$cmdName binary.
func FindCmd(cmdName string) string {
	if cmdName == "systemctl" {
		return cmdName
	}
	path, err := exec.LookPath("systemd-" + cmdName) //nolint:forbidigo // We are running as root with a trusted PATH and looking up host binaries.
	if err != nil {
		// Assume it is in /usr/lib/systemd/systemd-* if not in PATH.
		path = systemdCmdPrefix + cmdName
	}
	return path
}

// Call calls the systemd-$cmdName command with the given arguments. No output
// is returned the caller, this call is intended only for fire-and-forget
// systemd-* command calls. If you need output, tailor a custom
// [exec.CommandContext] using [FindCmd].
func Call(ctx context.Context, cmdName string, args ...string) error {
	// systemd-$name ...
	cmdPath := FindCmd(cmdName)
	cmd := exec.CommandContext(ctx, cmdPath, args...)
	// Stream the output to our stdio.
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	slog.Info(fmt.Sprintf("[exec] %s", cmd))
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("(%s) failed to start: %w", cmd, err)
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("wait for (%s): %w", cmd, err)
	}
	return nil
}
