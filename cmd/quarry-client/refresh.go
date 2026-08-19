// Copyright (C) 2026 Amutable GmbH

package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/urfave/cli/v3"

	"go.amutable.dev/quarry/internal/third_party/funchelpers"
)

var refreshCommand = &cli.Command{
	Name:  "refresh",
	Usage: "check for updates for the given repos",
	Arguments: []cli.Argument{
		&cli.StringArgs{
			Name:      "repo-name",
			UsageText: "[repo-name]...",
			Min:       0,
			Max:       -1,
		},
	},
	Action: func(ctx context.Context, cmd *cli.Command) (Err error) {
		repoNames := cmd.StringArgs("repo-name")

		client, err := getClient(ctx, repoNames...)
		if err != nil {
			return fmt.Errorf("get tuf-client: %w", err)
		}
		defer funchelpers.VerifyClose(&Err, client)

		wtr := os.Stdout
		var errs []error
		for repoName, updater := range client.IterRepos(ctx) {
			mustFprintf(wtr, "Refreshing %s ...", repoName)
			_ = wtr.Sync()

			if err := updater.Refresh(); err != nil {
				mustFprintf(wtr, " FAILED: %v\n", err)
				errs = append(errs, err)
			} else {
				mustFprintf(wtr, " OK!\n")
			}
		}
		return errors.Join(errs...)
	},
}
