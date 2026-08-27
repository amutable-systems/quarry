// Copyright (C) 2026 Amutable GmbH

package cliext

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"

	"go.amutable.dev/quarry/internal/ctxext"
	"go.amutable.dev/quarry/internal/tufclient/config"
	"go.amutable.dev/quarry/internal/uapi6conf"
)

type ctxKey string

const configCtxKey ctxKey = "--config"

// WithConfigFlag adds the --config flag to [cli.Command].
func WithConfigFlag(cmd *cli.Command) *cli.Command {
	cmd.Flags = append(cmd.Flags,
		&cli.StringFlag{
			Name: "config",
			Usage: fmt.Sprintf(
				// Split this very long help message over a few lines...
				"path to the quarry-client configuration file\n(default: config.toml in the standard search paths:\n\t%v\nwith \".d\"-style drop-ins)",
				uapi6conf.Standard("", "quarry-client"), // TODO: Should we pass this to config.LoadPath()?
			),
			TakesFile: true,
			Sources:   cli.EnvVars("QUARRY_CLIENT_CONFIG"),
		},
		&cli.StringFlag{
			Name:      "cache-dir",
			Usage:     "local cache directory for TUF metadata",
			TakesFile: true,
			Value:     "/var/lib/quarry-client/latest-metadata",
			Sources:   cli.EnvVars("QUARRY_CLIENT_CACHEDIR"),
		})

	cmd.Before = WrapBeforeFuncs(cmd.Before, func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
		var (
			cfg *config.Config
			err error
		)
		if cfgPath := cmd.String("config"); cfgPath != "" {
			cfg, err = config.LoadPath(cfgPath)
		} else {
			cfg, err = config.Load()
		}
		if err != nil {
			return nil, err
		}
		// Replace the in-memory config option with --cache-dir if it was unset
		// in the config or the user explicitly requested it.
		if cfg.CacheDir == "" || cmd.IsSet("cache-dir") {
			cfg.CacheDir = cmd.String("cache-dir")
		}
		ctx = context.WithValue(ctx, configCtxKey, cfg)

		return ctx, nil
	})

	return cmd
}

// CtxConfig returns the parsed --config flag value for [cli.Command]s
// configured using [WithConfigFlag].
func CtxConfig(ctx context.Context) *config.Config {
	return ctxext.Value[*config.Config](ctx, configCtxKey)
}
