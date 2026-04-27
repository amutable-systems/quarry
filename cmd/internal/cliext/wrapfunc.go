// Copyright (C) 2026 Amutable GmbH

package cliext

import (
	"context"

	"github.com/urfave/cli/v3"
)

// WrapBeforeFuncs takes a set of [cli.BeforeFunc]s and chains them together.
// nil functions are ignored, so you can use this with unset
// [cli.Command.Before] fields.
func WrapBeforeFuncs(beforeFns ...cli.BeforeFunc) cli.BeforeFunc {
	return func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
		for _, fn := range beforeFns {
			if fn != nil {
				newCtx, err := fn(ctx, cmd)
				if err != nil {
					return newCtx, err
				}
				ctx = newCtx
			}
		}
		return ctx, nil
	}
}

// WrapAfterFuncs takes a set of [cli.AfterFunc]s and chains them together. nil
// functions are ignored, so you can use this with unset [cli.Command.After]
// fields.
func WrapAfterFuncs(afterFns ...cli.AfterFunc) cli.AfterFunc {
	return func(ctx context.Context, cmd *cli.Command) error {
		for _, fn := range afterFns {
			if fn != nil {
				if err := fn(ctx, cmd); err != nil {
					return err
				}
			}
		}
		return nil
	}
}
