// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package cliext

import (
	"context"
	"time"

	"github.com/urfave/cli/v3"

	"go.amutable.dev/quarry/internal/ctxext"
)

// WithRefTimeFlag adds the --ref-time flag to [cli.Command].
func WithRefTimeFlag(cmd *cli.Command) *cli.Command {
	cmd.Flags = append(cmd.Flags,
		&cli.TimestampFlag{
			Name:  "ref-time",
			Usage: "used instead of the wallclock time for expiry checks",
			Config: cli.TimestampConfig{
				Layouts: []string{
					time.RFC3339,
					time.RFC3339Nano,
					time.DateOnly,
					// TODO: It would be nice to be able to pass a Unix epoch.
				},
			},
		})

	cmd.Before = WrapBeforeFuncs(cmd.Before, func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
		refTime := cmd.Timestamp("ref-time").UTC()
		if !refTime.IsZero() {
			ctx = context.WithValue(ctx, ctxext.RefTimeCtxKey, refTime)
		}
		return ctx, nil
	})

	return cmd
}
