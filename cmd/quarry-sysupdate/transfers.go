// Copyright (C) 2026 Amutable GmbH

package sysupdate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"

	"go.amutable.dev/quarry/internal/systemdcmd"
	"go.amutable.dev/quarry/internal/transferlayout"
	"go.amutable.dev/quarry/internal/uapi10"
	"go.amutable.dev/quarry/internal/xsysupdate"
)

// transferVersions are the transfer directories of each component, sorted by
// version (oldest first, see [xsysupdate.TransferFileExtension.Transfers]).
type transferVersions map[string][]*xsysupdate.TransferDir

// components returns the sorted list of components with transfer versions.
func (tvs transferVersions) components() []string {
	return slices.Sorted(maps.Keys(tvs))
}

// pinTagSuffix is appended to a component's tag to name the sibling tag whose
// value pins the component's version (e.g. "amutable.os.version=1.2.3").
const pinTagSuffix = ".version"

// tagSelection reads a component's machine tags. The tag itself (matched by
// key, in systemd's "key=value" format) enables the component. The sibling tag
// "<tag>.version=<version>" pins the component to that version. The two are
// kept apart so that the enablement tag stays a plain key that sysupdate's
// SuggestOnMachineTag= could match. A pin without the enablement tag is
// reported (pinned set, enabled false), and it is up to the caller whether it
// applies. An error is returned if the tags disagree on the pin.
func tagSelection(current []string, tag string) (enabled bool, pinned string, _ error) {
	pinTag := tag + pinTagSuffix
	for _, machineTag := range current {
		key, value, _ := strings.Cut(machineTag, "=")
		switch key {
		case tag:
			enabled = true
		case pinTag:
			if value == "" {
				return false, "", fmt.Errorf("machine tag %q pins no version", machineTag)
			}
			if pinned != "" && pinned != value {
				return false, "", fmt.Errorf("machine tags pin %s to both %s and %s", tag, pinned, value)
			}
			pinned = value
		}
	}
	return enabled, pinned, nil
}

// componentEnabled decides from the newest candidate's ATTR whether the
// component is updated on this machine. A pre-enabled component always is.
// Otherwise its tag has to be set (see [tagSelection]). The tag's ".version"
// sibling pins the version either way.
func componentEnabled(newest *xsysupdate.TransferDir, currentTags []string) (enabled bool, pinned string, _ error) {
	enabled = newest.Attr.PreEnabled
	if newest.Attr.Tag != "" {
		tagged, pinned, err := tagSelection(currentTags, newest.Attr.Tag)
		if err != nil {
			return false, "", err
		}
		return enabled || tagged, pinned, nil
	}
	return enabled, "", nil
}

// selectVersion picks the transfer version to update to. The goal is the
// newest candidate, or the pinned version if one is given. If a stepping-stone
// version newer than the running one (current) lies before the goal, the
// oldest such stepping stone is picked instead. A stepping stone that is
// installed but not booted yet is still newer than the running version, so it
// is picked again and the update never moves past it before the reboot. If the
// running version is unknown (current is ""), stepping stones are skipped.
//
// The chosen version may be the installed one. Re-running sysupdate for it is
// a no-op except for features whose enablement changed.
func selectVersion(candidates []*xsysupdate.TransferDir, current, pinned string) (*xsysupdate.TransferDir, error) {
	goal := candidates[len(candidates)-1]
	if pinned != "" {
		idx := slices.IndexFunc(candidates, func(c *xsysupdate.TransferDir) bool { return c.Version == pinned })
		if idx < 0 {
			return nil, fmt.Errorf("pinned version %s has no transfer definitions", pinned)
		}
		goal = candidates[idx]
	}
	if current == "" {
		return goal, nil
	}
	for _, c := range candidates {
		if c.SteppingStone() && uapi10.Compare(c.Version, current) > 0 && uapi10.Compare(c.Version, goal.Version) < 0 {
			return c, nil
		}
	}
	return goal, nil
}

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

// stagedComponent is one component resolved to a version and staged for the
// sysupdate run.
type stagedComponent struct {
	component string
	target    *xsysupdate.TransferDir
	staged    *xsysupdate.StagedTransfers
}

// stageComponent picks the version to update an enabled component (see
// [componentEnabled]) to from its version-sorted candidates and its running
// version (see [selectVersion]) and stages its definitions for
// [updateStaged].
//
// Staging stamps Enabled=true into the component file of a tag-gated
// component, keeps a pre-enabled one as shipped, and enables the features
// whose ATTR tags are set (see [xsysupdate.TransferFileExtension.Stage]).
//
// TODO: This stands in for a sysupdate setting such as "EnableOnMachineTag="
// in the component and feature files, which would let sysupdate decide the
// enablement from the machine tags itself.
func stageComponent(ctx context.Context, ext *xsysupdate.TransferFileExtension, candidates []*xsysupdate.TransferDir, current, pinned string, machineTags []string) (*stagedComponent, error) {
	component := candidates[0].Component
	componentDir := transferlayout.ComponentDir(component) // for log messages

	var target *xsysupdate.TransferDir
	// TODO(transition): Drop the unversioned branch once no repository ships
	// unversioned transfer directories.
	if len(candidates) == 1 && candidates[0].Version == "" {
		// This is the transition-period layout. It has no version to resolve
		// or pin, and sysupdate picks the newest it finds.
		target = candidates[0]
		if pinned != "" {
			slog.Warn("Ignoring version pin for a component with unversioned transfer definitions.",
				"component", componentDir, "pinned", pinned)
		}
	} else {
		var err error
		target, err = selectVersion(candidates, current, pinned)
		if err != nil {
			return nil, err
		}
		if target.SteppingStone() && target.Version != pinned && target != candidates[len(candidates)-1] {
			slog.Info("Updating to stepping-stone version first.",
				"component", componentDir, "version", target.Version, "running", current, "pinned", pinned)
		}
	}

	staged, err := ext.Stage(ctx, target, xsysupdate.StageOptions{MachineTags: machineTags})
	if err != nil {
		return nil, fmt.Errorf("stage transfer definitions of %s: %w", target, err)
	}
	slog.Info("Staged transfer definitions.",
		"component", componentDir, "version", target.Version, "path", staged.Path(),
		"enabledFeatures", staged.EnabledFeatures)
	return &stagedComponent{component: component, target: target, staged: staged}, nil
}

// updateStaged runs systemd-sysupdate once over all staged components. Their
// definitions are bind-mounted into a transient service, where
// "--component-all update" updates the default component and each enabled
// component. No version is passed, as the build bounds each definition to its
// own version with MinVersion=/MaxVersion=. Until systemd supports
// MaxVersion=, a newer instance in the repository still wins.
func updateStaged(ctx context.Context, staged []*stagedComponent) (Err error) {
	var bindPaths []string
	for _, sc := range staged {
		bindPaths = append(bindPaths, sc.staged.BindPaths()...)
	}
	defer func() {
		failed := Err != nil
		for _, sc := range staged {
			if failed {
				// Keep the staged definitions for debugging. They are pruned
				// at the start of the next run.
				slog.Warn("Keeping staged transfer definitions of failed update.",
					"component", transferlayout.ComponentDir(sc.component), "version", sc.target.Version, "path", sc.staged.Path())
				Err = errors.Join(Err, sc.staged.Close())
			} else {
				Err = errors.Join(Err, sc.staged.Remove())
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
