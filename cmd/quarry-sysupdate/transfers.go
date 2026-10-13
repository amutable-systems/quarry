// Copyright (C) 2026 Amutable GmbH

package sysupdate

import (
	"context"
	"errors"
	"log/slog"

	"go.amutable.dev/quarry/internal/systemdcmd"
	"go.amutable.dev/quarry/internal/transferlayout"
	"go.amutable.dev/quarry/internal/xsysupdate"
)

// sysupdateRunArgs returns the systemd-run arguments that run systemd-sysupdate
// with the given arguments in a transient service that sees the staged
// definitions through read-only bind mounts (see
// [xsysupdate.StagedTransfers.BindPaths]).
func sysupdateRunArgs(bindPaths []string, args ...string) []string {
	runArgs := []string{"--collect", "--pipe"}
	for _, bind := range bindPaths {
		runArgs = append(runArgs, "-p", "BindReadOnlyPaths="+bind)
	}
	runArgs = append(runArgs, systemdcmd.FindCmd("sysupdate"))
	return append(runArgs, args...)
}

// updateStaged runs systemd-sysupdate once over all staged components. Their
// definitions are bind-mounted into a transient service, where
// "--component-all update" updates the default component and each enabled
// component.
func updateStaged(ctx context.Context, staged []*xsysupdate.StagedTransfers) (Err error) {
	var bindPaths []string
	for _, sc := range staged {
		bindPaths = append(bindPaths, sc.BindPaths()...)
	}
	defer func() {
		failed := Err != nil
		for _, sc := range staged {
			if failed {
				// Keep the staged definitions for debugging. They are pruned
				// at the start of the next run.
				slog.Warn("Keeping staged transfer definitions of failed update.",
					"component", transferlayout.ComponentDir(sc.Component), "path", sc.Path())
				Err = errors.Join(Err, sc.Close())
			} else {
				Err = errors.Join(Err, sc.Remove())
			}
		}
	}()

	// TODO: Pass --cleanup=yes to garbage-collect files that are no longer
	// covered by this component's transfers, and also explicitly run
	// "systemd-sysupdate -C <c> cleanup" for components that are no longer
	// enabled (or have no transfer definitions anymore) on the bare host,
	// which deletes everything recorded in their installdb. Both are blocked
	// on the sysupdate garbage collector taking "bootctl link" references
	// into account, as otherwise it would remove files still referenced from
	// the ESP.
	//
	// systemd-run --collect --pipe -p BindReadOnlyPaths=... systemd-sysupdate --component-all update
	return systemdcmd.Call(ctx, "run", sysupdateRunArgs(bindPaths, "--component-all", "update")...)
}
