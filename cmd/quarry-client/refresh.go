// Copyright (C) 2026 Amutable GmbH

package main

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"

	"github.com/urfave/cli/v3"
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
	Action: func(ctx context.Context, cmd *cli.Command) error {
		repoNames := cmd.StringArgs("repo-name")

		updaters, err := getUpdaters(ctx, cmd, repoNames...)
		if err != nil {
			return fmt.Errorf("failed to get tuf-client updaters: %w", err)
		}
		if len(repoNames) == 0 {
			// Make sure we iterate over the repos in order.
			repoNames = slices.Sorted(maps.Keys(updaters))
		}

		var errs []error
		for _, repoName := range repoNames {
			updater := updaters[repoName]

			fmt.Printf("Refreshing %s ...", repoName)
			_ = os.Stdout.Sync()

			if err := updater.Refresh(); err != nil {
				fmt.Printf(" FAILED: %v\n", err)
				errs = append(errs, err)
			} else {
				fmt.Printf(" OK!\n")
			}
		}
		if err := errors.Join(errs...); err != nil {
			return err
		}
		return nil
	},
}
