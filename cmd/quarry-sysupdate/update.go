// Copyright (C) 2026 Amutable GmbH

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/urfave/cli/v3"

	"go.amutable.dev/quarry/internal/xsysupdate"
)

var updateCommand = withExtensionDirFlag(withQuarryUserFlag(withQuarryProxyFlag(&cli.Command{
	Name:  "update",
	Usage: "extended 'systemd-sysupdate update' wrapper",
	Action: func(ctx context.Context, _ *cli.Command) (Err error) {
		exts := xsysupdate.ExtensionSet{
			&xsysupdate.TransferFileExtension{
				OverrideSourcePathURL: ctxQuarryProxyURL(ctx),
			},
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
		// Because we need to call sysupdate multiple times to update each
		// component, it is possible that one component installation fails. We
		// would ideally never want to allow execution with mixed repo states,
		// but fixing this requires having logic for cleanup so we can abort
		// the extension application, clean up the successfully installed
		// components, and force-downgrade to the old versions.

		components, err := listComponents(ctx)
		if err != nil {
			return fmt.Errorf("get list of sysupdate components: %w", err)
		}
		slog.Info("Spawning 'systemd-sysupdate update'...",
			"components", components)
		var errs []error
		for _, component := range components {
			if err := sysupdate(ctx, component); err != nil {
				slog.Error("sysupdate for component failed.",
					"err", err.Error(), "component", component)
				// FIXME: If we hit an error, continue on because we don't have
				// a decent revert story at the moment.
				errs = append(errs, err)
			}
		}
		if err := errors.Join(errs...); err != nil {
			return fmt.Errorf("sysupdate failed: %w", err)
		}
		slog.Info("'systemd-sysupdate update' completed.")

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
