// Copyright (C) 2026 Amutable GmbH

package sysupdate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/urfave/cli/v3"

	"go.amutable.dev/quarry/internal/hostnamed"
	"go.amutable.dev/quarry/internal/transferlayout"
	"go.amutable.dev/quarry/internal/xsysupdate"
)

var updateCommand = withExtensionDirFlag(withQuarryUserFlag(withQuarryProxyFlag(&cli.Command{
	Name:  "update",
	Usage: "extended 'systemd-sysupdate update' wrapper",
	Action: func(ctx context.Context, _ *cli.Command) (Err error) {
		transfersExt := &xsysupdate.TransferFileExtension{
			OverrideSourcePathURL: ctxQuarryProxyURL(ctx),
		}
		exts := xsysupdate.ExtensionSet{
			transfersExt,
			&xsysupdate.TagsExtension{
				// TODO: There is no ownership model for machine tags yet, so
				// as a temporary workaround we take full control of the acp.*
				// and amutable.* tag namespaces. These tags always exactly
				// match the set shipped by the configured repositories, and
				// tags outside them are never touched.
				AllowedNamespaces: []string{"acp.", "amutable."},
			},
		}
		ctx, err := exts.DoInit(ctx)
		if err != nil {
			return fmt.Errorf("init extensions: %w", err)
		}
		slog.Info("Initialised extensions.",
			"extensions", exts.String())
		// A failure before the components are updated leaves nothing
		// installed, so the extensions are aborted (reverting the tags and
		// removing the staging directory). Afterwards the state is kept (see
		// the FIXME below) and the extensions are only closed.
		updating, closed := false, false
		defer func() {
			switch {
			case Err == nil || closed:
			case !updating:
				// A failed Do* call has aborted already, and aborting again
				// does nothing.
				if err := exts.DoAbort(context.WithoutCancel(ctx), Err); err != nil {
					Err = errors.Join(Err, fmt.Errorf("abort extensions: %w", err))
				}
			default:
				if err := exts.Close(); err != nil {
					Err = errors.Join(Err, fmt.Errorf("post-update extension cleanup: %w", err))
				}
			}
		}()
		for target, err := range unprivIterTargetFiles(ctx) {
			if err != nil {
				return fmt.Errorf("error while scanning repos: %w", err)
			}
			if !strings.HasPrefix(target.Path, xsysupdate.ExtensionTargetPrefix) {
				continue
			}
			slog.Info("Extension target found.",
				"target", target.Path, "repository", target.Repo.Name)
			if err := exts.DoApplyTarget(ctx, target); err != nil {
				return fmt.Errorf("apply extension target %s: %w", target.Path, err)
			}
			slog.Info("Extension target applied.",
				"target", target.Path, "repository", target.Repo.Name)
		}
		if err := exts.DoBeforeUpdate(ctx); err != nil {
			return fmt.Errorf("before update extensions: %w", err)
		}
		slog.Info("Completed pre-sysupdate extensions.")

		// TODO: Should we do runas.User("root") or use run0 here?

		// FIXME FIXME FIXME
		//
		// If these updates error out we are kind of in a messy position.
		// sysupdate updates the components one after the other, so one
		// component installation can fail after another succeeded. We
		// would ideally never want to allow execution with mixed repo states,
		// but fixing this requires having logic for cleanup so we can abort
		// the extension application, clean up the successfully installed
		// components, and force-downgrade to the old versions.

		var errs []error

		// Only components with transfer definitions are updated. The
		// definitions describe exactly which version to install and how. A
		// component without any is not managed by us.
		transfers := transferVersions(transfersExt.Transfers())
		if len(transfers) == 0 {
			slog.Info("No transfer definitions found -- nothing to update.")
		} else {
			// hostnamed tells us both what is booted (the running OS version)
			// and the machine tags.
			host, err := hostnamed.Describe(ctx, "")
			if err != nil {
				return fmt.Errorf("describe host: %w", err)
			}
			if host == nil {
				return errors.New("io.systemd.Hostname.Describe returned null data")
			}
			// The booted version only matters for choosing a version of the
			// default component "" (and the unversioned layout has none).
			if slices.ContainsFunc(transfers[""], func(dir *xsysupdate.TransferDir) bool { return dir.Version != "" }) {
				if host.OperatingSystemImageVersion == "" {
					return errors.New("hostnamed reports no OS image version (IMAGE_VERSION= missing from os-release)")
				}
			}

			// A component is pre-enabled (its ATTR says so) or gated by a machine
			// tag, and the sibling tag "<tag>.version=<version>" pins the version
			// to update to (see tagSelection). The tags also decide feature
			// enablement while staging the definitions.
			//
			// Enablement is decided here because sysupdate cannot match machine
			// tags yet. Only enabled components are staged, and a tag-gated one
			// is staged with Enabled=true stamped in (see stageComponent).
			currentTags := host.Tags()

			updating = true
			components := transfers.components()
			componentDirs := make([]string, 0, len(components)) // for log messages
			for _, component := range components {
				componentDirs = append(componentDirs, transferlayout.ComponentDir(component))
			}
			slog.Info("Staging transfer definitions for 'systemd-sysupdate update'...",
				"components", componentDirs, "machineTags", currentTags)
			var staged []*stagedComponent
			for i, component := range components {
				candidates := transfers[component]
				newest := candidates[len(candidates)-1]
				// The newest candidate's ATTR decides (see componentEnabled).
				tag := newest.Attr.Tag
				enabled, pinned, err := componentEnabled(newest, currentTags)
				if err != nil {
					slog.Error("Invalid machine tags for component.",
						"err", err.Error(), "component", componentDirs[i], "tag", tag)
					errs = append(errs, err)
					continue
				}
				if !enabled {
					slog.Info("Skipping component not enabled on this machine.",
						"component", componentDirs[i], "version", newest.Version, "missingTag", tag, "ignoredPin", pinned)
					continue
				}
				slog.Info("Component selected.",
					"component", componentDirs[i], "preEnabled", newest.Attr.PreEnabled, "tag", tag, "pinned", pinned)
				// Only the base OS reports its running version, which is the
				// booted IMAGE_VERSION. Other components are always updated to
				// their goal version, skipping stepping stones.
				// TODO: Let the components report themselves, e.g. through a
				// confext or sysext per component whose extension-release
				// metadata names the component, with its *_IMAGE_VERSION (or
				// *_VERSION_ID) as the version.
				current := ""
				if component == "" {
					current = host.OperatingSystemImageVersion
				}
				sc, err := stageComponent(ctx, transfersExt, candidates, current, pinned, currentTags)
				if err != nil {
					slog.Error("Staging the component's transfer definitions failed.",
						"err", err.Error(), "component", componentDirs[i])
					// FIXME: If we hit an error, continue on because we don't have
					// a decent revert story at the moment.
					errs = append(errs, err)
					continue
				}
				staged = append(staged, sc)
			}
			if len(staged) > 0 {
				// There is one run for everything staged. The hook units merge
				// the extensions and relink the UKI after each component.
				slog.Info("Spawning 'systemd-sysupdate update' with the staged transfer definitions...",
					"components", len(staged))
				if err := updateStaged(ctx, staged); err != nil {
					slog.Error("sysupdate failed.", "err", err.Error())
					errs = append(errs, err)
				}
			}
		}
		if err := errors.Join(errs...); err != nil {
			return fmt.Errorf("sysupdate failed: %w", err)
		}
		slog.Info("'systemd-sysupdate update' completed.")

		closed = true
		if err := exts.Close(); err != nil {
			return fmt.Errorf("post-update extension cleanup: %w", err)
		}

		// Do online-reload of sysexts and confexts.
		slog.Info("Trigger online-reload of new components.")
		if err := sysupdateRefresh(ctx); err != nil {
			return fmt.Errorf("online-reload components: %w", err)
		}

		return nil
	},
})))
