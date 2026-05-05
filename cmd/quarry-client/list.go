// Copyright (C) 2026 Amutable GmbH

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"

	"github.com/urfave/cli/v3"

	"go.amutable.dev/quarry/internal/tufext"
	"go.amutable.dev/quarry/internal/uapi16"
)

var listCommand = withRefTimeFlag(&cli.Command{
	Name:  "list",
	Usage: "get a list of available update files",
	Flags: []cli.Flag{},
	Arguments: []cli.Argument{
		&cli.StringArgs{
			Name:      "repo-name",
			UsageText: "[repo-name]...",
			Min:       0,
			Max:       -1,
		},
	},
	MutuallyExclusiveFlags: []cli.MutuallyExclusiveFlags{
		{
			Flags: [][]cli.Flag{
				{
					&cli.BoolFlag{
						Name:    "verbose",
						Usage:   "output more textual information about each target file",
						Aliases: []string{"v"},
					},
				},
				{
					&cli.StringFlag{
						Name:    "format",
						Usage:   "output formatted text for each target file (%%R = repo, %%n = target name, %%s = size, %%h = sha256 hash, %%u = download URL)",
						Aliases: []string{"f"},
					},
				},
				{
					&cli.BoolFlag{
						Name:  "uapi-16",
						Usage: "output the list as a UAPI.16 manifest (for sysupdate) to the given path ('-' for stdout)",
					},
				},
			},
		},
	},
	Action: func(ctx context.Context, cmd *cli.Command) error {
		config := ctxConfig(ctx)
		cacheDir := ctxCacheDir(ctx)
		repoNames := cmd.StringArgs("repo-name")

		updaters, err := getUpdaters(ctx, repoNames...)
		if err != nil {
			return fmt.Errorf("get tuf-client updaters: %w", err)
		}
		if len(repoNames) == 0 {
			// Make sure we iterate over the repos in order.
			repoNames = slices.Sorted(maps.Keys(updaters))
		}
		var manifest *uapi16.Manifest
		if cmd.Bool("uapi-16") {
			manifest = uapi16.New()
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
				if manifest != nil {
					uapi16File, err := uapi16FromTargetFile(repo, target.TargetFiles)
					if err != nil {
						return fmt.Errorf("error while uapi16 formatting target file %s from repo %s: %w", target.Path, repoName, err)
					}
					manifest.Files = append(manifest.Files, uapi16File)
				} else if cmd.Bool("verbose") {
					pprintTargetFile("", repo, target.TargetFiles)
				} else if fmtStr := cmd.String("format"); cmd.IsSet("format") {
					if err := expandTargetFile(fmtStr, repo, target.TargetFiles); err != nil {
						return fmt.Errorf("error while %%-formatting target file %s from repo %s: %w", target.Path, repoName, err)
					}
				} else {
					fmt.Println(target.Path)
				}
			}
		}
		if manifest != nil {
			if err := json.NewEncoder(os.Stdout).Encode(manifest); err != nil {
				return fmt.Errorf("write uapi16 manifest: %w", err)
			}
		}
		return nil
	},
})
