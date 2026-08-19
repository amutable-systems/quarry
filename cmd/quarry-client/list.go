// Copyright (C) 2026 Amutable GmbH

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/urfave/cli/v3"

	"go.amutable.dev/quarry/internal/third_party/funchelpers"
	"go.amutable.dev/quarry/internal/uapi16"
)

var listCommand = &cli.Command{
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
						Usage:   "output formatted text for each target file (%R = repo, %n = target name, %s = size, %h = sha256 hash, %u = download URL)",
						Aliases: []string{"f"},
					},
				},
				{
					&cli.BoolFlag{
						Name:  "uapi-16",
						Usage: "output the list as a UAPI.16 manifest",
					},
				},
			},
		},
	},
	Action: func(ctx context.Context, cmd *cli.Command) (Err error) {
		client, err := getClient(ctx, cmd.StringArgs("repo-name")...)
		if err != nil {
			return fmt.Errorf("get tuf-client: %w", err)
		}
		defer funchelpers.VerifyClose(&Err, client)
		// TODO: Do a client.Refresh here?

		var manifest *uapi16.Manifest
		if cmd.Bool("uapi-16") {
			manifest = uapi16.New()
		}

		for target, err := range client.IterTargetFiles(ctx) {
			if err != nil {
				return err
			}
			if manifest != nil {
				for uapi16File, err := range uapi16FromTargetFile(target.Repo, target.TargetFiles) {
					if err != nil {
						return fmt.Errorf("error while uapi16 formatting target file %s from repo %s: %w", target.Path, target.Repo.Name, err)
					}
					manifest.Files = append(manifest.Files, uapi16File)
				}
			} else if cmd.Bool("verbose") {
				pprintTargetFile(os.Stdout, "", target.Repo, target.TargetFiles)
			} else if fmtStr := cmd.String("format"); cmd.IsSet("format") {
				if err := expandTargetFile(os.Stdout, fmtStr, target.Repo, target.TargetFiles); err != nil {
					return fmt.Errorf("error while %%-formatting target file %s from repo %s: %w", target.Path, target.Repo.Name, err)
				}
			} else {
				mustFprintln(os.Stdout, target.Path)
			}
		}
		if manifest != nil {
			if err := json.NewEncoder(os.Stdout).Encode(manifest); err != nil {
				return fmt.Errorf("write uapi16 manifest: %w", err)
			}
		}
		return nil
	},
}
