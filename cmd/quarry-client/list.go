// Copyright (C) 2026 Amutable GmbH

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"

	"github.com/opencontainers/go-digest"
	"github.com/urfave/cli/v3"

	"go.amutable.dev/quarry/internal/tufext"
	"go.amutable.dev/quarry/internal/uapi16"
)

var listCommand = withRefTimeFlag(&cli.Command{
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

		updaters, err := getUpdaters(ctx, repoNames...)
		if err != nil {
			return fmt.Errorf("get tuf-client updaters: %w", err)
		}
		if len(repoNames) == 0 {
			// Make sure we iterate over the repos in order.
			repoNames = slices.Sorted(maps.Keys(updaters))
		}

		var manifest *uapi16.Manifest
		if cmd.IsSet("uapi-16") {
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
					manifest.Files = append(manifest.Files, &uapi16.File{
						// TODO: What should we do about separators here?
						Name:     target.Path,
						DataURL:  repo.DataBaseURL.JoinPath(target.Path).String(),
						DataSize: uint64(target.Length),
						SHA256:   digest.SHA256.Encode(target.Hashes["sha256"]),
					})
				} else {
					pprintTargetFile("", repo, target.TargetFiles)
				}
			}
		}
		if manifest != nil {
			var output io.Writer
			if outPath := cmd.String("uapi-16"); outPath != "-" {
				outFile, err := os.Create(outPath) //nolint:forbidigo // user-controlled host path
				if err != nil {
					return fmt.Errorf("invalid --output argument: %w", err)
				}
				defer outFile.Close() //nolint:errcheck // poc cli code
				output = outFile
			} else {
				output = os.Stdout
			}
			if err := json.NewEncoder(output).Encode(manifest); err != nil {
				return fmt.Errorf("write uapi16 manifest: %w", err)
			}
			if output != os.Stdout {
				fmt.Printf("Wrote UAPI.16 manifest to %q.", cmd.String("uapi-16"))
			} else {
				fmt.Printf("\n")
			}
		}
		return nil
	},
})
