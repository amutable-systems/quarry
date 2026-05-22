// Copyright (C) 2026 Amutable GmbH

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"

	"go.amutable.dev/quarry/internal/jsonutils"
)

const (
	systemdCmdPrefix = "/usr/lib/systemd/systemd-"
	defaultComponent = "<default>" // copied from `systemd-sysupdate components`
)

func findSystemdCmd(cmdName string) string {
	path, err := exec.LookPath("systemd-" + cmdName) //nolint:forbidigo // We are running as root with a trusted PATH and looking up host binaries.
	if err != nil {
		// Assume it is in /usr/lib/systemd/systemd-* if not in PATH.
		path = systemdCmdPrefix + cmdName
	}
	return path
}

func listComponents(ctx context.Context) ([]string, error) {
	sysupdatePath := findSystemdCmd("sysupdate")
	// systemd-sysupdate --json=short components
	cmd := exec.CommandContext(ctx,
		sysupdatePath, "--json=short", "components")

	slog.Info(fmt.Sprintf("[exec] %s", cmd))
	data, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("get list of sysupdate components (%s): %w", cmd, err)
	}

	type outputType struct {
		Default    bool     `json:"default"`
		Components []string `json:"components"`
	}
	out, err := jsonutils.Parse[outputType](data)
	if err != nil {
		return nil, fmt.Errorf("(%s) produced invalid json: %w", cmd, err)
	}
	components := out.Components
	if out.Default {
		components = append(components, defaultComponent)
	}
	return components, nil
}

func systemdCmd(ctx context.Context, cmdName string, args ...string) error {
	// systemd-$name ...
	cmdPath := findSystemdCmd(cmdName)
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

func sysupdate(ctx context.Context, component string) error {
	// systemd-sysupdate [--component=$component] update
	args := make([]string, 0, 2)
	if component != defaultComponent {
		args = append(args, "--component="+component)
	}
	args = append(args, "update")
	return systemdCmd(ctx, "sysupdate", args...)
}

func sysupdateRefresh(ctx context.Context) error {
	errs := []error{
		// systemd-confext refresh
		systemdCmd(ctx, "confext", "refresh"),
		// systemd-sysext refresh
		systemdCmd(ctx, "sysext", "refresh"),
		// TODO: detect if we need to do systemd-sysupdate reboot...?
		// TODO: bootctl link
	}
	return errors.Join(errs...)
}
