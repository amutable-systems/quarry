// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package sysupdate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"

	"github.com/urfave/cli/v3"

	"go.amutable.dev/quarry/internal/hostnamed"
	"go.amutable.dev/quarry/internal/third_party/assert"
	"go.amutable.dev/quarry/internal/transferlayout"
	"go.amutable.dev/quarry/internal/tufclient"
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
		// Legacy-prefixed targets are only applied after all other targets so
		// we can allow them to be overridden by the non-legacy prefix.
		// TODO: Drop this.
		var (
			applied       = map[string]struct{}{} // uses the stripped name
			legacyTargets []*tufclient.TargetInfo
		)
		applyTarget := func(target *tufclient.TargetInfo) error {
			slog.Info("Extension target found.",
				"target", target.Path, "repository", target.Repo.Name)
			name, legacy, ok := xsysupdate.CutExtensionTargetPrefix(target.Path)
			assert.Assertf(ok, "extension target path %q must have extension prefix", target.Path)
			if _, ok := applied[name]; ok {
				slog.Info("Skipping legacy extension target superseded by new prefix.",
					"target", target.Path, "repository", target.Repo.Name)
				assert.Assertf(!legacy, "extension target path %q must not be applied after legacy paths", target.Path)
				return nil
			}
			if err := exts.DoApplyTarget(ctx, target); err != nil {
				return fmt.Errorf("apply extension target %s: %w", target.Path, err)
			}
			applied[name] = struct{}{}
			slog.Info("Extension target applied.",
				"target", target.Path, "repository", target.Repo.Name)
			return nil
		}
		for target, err := range unprivIterTargetFiles(ctx) {
			if err != nil {
				return fmt.Errorf("error while scanning repos: %w", err)
			}
			if _, legacy, ok := xsysupdate.CutExtensionTargetPrefix(target.Path); !ok {
				// Not an extension target file.
				continue
			} else if legacy {
				// Defer application of legacy-prefixed extensions until we've
				// done everything else so we can skip them if there was a
				// non-legacy version of the same file.
				legacyTargets = append(legacyTargets, target)
				continue
			}
			// Otherwise, apply the extension target file.
			if err := applyTarget(target); err != nil {
				return err
			}
		}
		for _, target := range legacyTargets {
			if err := applyTarget(target); err != nil {
				return err
			}
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

		// Only components with transfer definitions are updated. A component
		// without any is not managed by us.
		transfers := transfersExt.Transfers()
		if len(transfers) == 0 {
			slog.Info("No transfer definitions found -- nothing to update.")
		} else {
			// The machine tags decide which components and features are
			// enabled while staging the definitions, because sysupdate does
			// not enable suggested ones by itself (see
			// xsysupdate.TransferFileExtension.Stage).
			currentTags, err := hostnamed.CurrentTags(ctx, "")
			if err != nil {
				return fmt.Errorf("get current machine tags: %w", err)
			}

			updating = true
			components := slices.Sorted(maps.Keys(transfers))
			slog.Info("Staging transfer definitions for 'systemd-sysupdate update'...",
				"components", len(components), "machineTags", currentTags)
			var staged []*xsysupdate.StagedTransfers
			for _, component := range components {
				componentDir := transferlayout.ComponentDir(component) // for log messages
				sc, err := transfersExt.Stage(ctx, transfers[component], xsysupdate.StageOptions{MachineTags: currentTags})
				if err != nil {
					slog.Error("Staging the component's transfer definitions failed.",
						"err", err.Error(), "component", componentDir)
					// FIXME: If we hit an error, continue on because we don't have
					// a decent revert story at the moment.
					errs = append(errs, err)
					continue
				}
				if sc == nil {
					continue // not enabled on this machine
				}
				slog.Info("Staged transfer definitions.",
					"component", componentDir, "path", sc.Path(), "enabledFeatures", sc.EnabledFeatures)
				staged = append(staged, sc)
			}
			if len(staged) > 0 {
				// There is one run for everything staged. The hook units merge
				// the extensions and relink the UKI after each component.
				// TODO: Make sure we control this better to only do it at the end
				// after everything was successfully updated.
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
