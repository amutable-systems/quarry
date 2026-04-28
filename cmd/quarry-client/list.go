// Copyright (C) 2026 Amutable GmbH

package main

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/urfave/cli/v3"

	"go.amutable.dev/quarry/internal/tufext"
)

var listCommand = &cli.Command{
	Name:  "list",
	Usage: "get a list of available update files",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "uapi-16",
			Usage: "output the list as a UAPI.16 manifest (for sysupdate) to the given path ('-' for stdout)",
		},
	},
	Arguments: []cli.Argument{
		&cli.StringArgs{
			Name:      "repo-name",
			UsageText: "[repo-name]...",
			Min:       0,
			Max:       -1,
		},
	},
	Action: func(ctx context.Context, cmd *cli.Command) error {
		config := ctxConfig(ctx)
		cacheDir := ctxCacheDir(ctx)
		repoNames := cmd.StringArgs("repo-name")

		updaters, err := getUpdaters(ctx, cmd, repoNames...)
		if err != nil {
			return fmt.Errorf("get tuf-client updaters: %w", err)
		}
		if len(repoNames) == 0 {
			// Make sure we iterate over the repos in order.
			repoNames = slices.Sorted(maps.Keys(updaters))
		}
		for _, repoName := range repoNames {
			updater := updaters[repoName]
			repo := config.Repos[repoName]

			// Make sure to get a local copy of the core metadata.
			if err := updater.Refresh(); err != nil {
				return fmt.Errorf("update repo %s: %w", repoName, err)
			}

			meta := updater.GetTrustedMetadataSet()
			fetchFn := trustedMetadataTargetsFetcher(cacheDir, repo, &meta)

			for target, err := range tufext.IterTargetFiles(ctx, fetchFn) {
				if err != nil {
					return fmt.Errorf("error while scanning repo %s: %w", repoName, err)
				}
				// TODO: UAPI.16 output.
				pprintTargetFile("", repo, target.TargetFiles)
			}
		}
		return nil
	},
}
