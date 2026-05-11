// Copyright (C) 2026 Amutable GmbH

package main

import (
	"context"
	"time"

	"github.com/urfave/cli/v3"

	"go.amutable.dev/quarry/cmd/internal/cliext"
	"go.amutable.dev/quarry/internal/ctxext"
)

type ctxKey string

const refTimeCtxKey ctxKey = "--ref-time"

func withRefTimeFlag(cmd *cli.Command) *cli.Command {
	cmd.Flags = append(cmd.Flags,
		&cli.TimestampFlag{
			Name:  "ref-time",
			Usage: "reference time to use rather than wall clock (WARNING: UNSAFE)",
		})

	cmd.Before = cliext.WrapBeforeFuncs(cmd.Before, func(ctx context.Context, cmd *cli.Command) (_ context.Context, Err error) {
		refTime := cmd.Timestamp("ref-time")
		ctx = context.WithValue(ctx, refTimeCtxKey, refTime)
		return ctx, nil
	})

	return cmd
}

func ctxRefTime(ctx context.Context) time.Time {
	return ctxext.Value[time.Time](ctx, refTimeCtxKey)
}
