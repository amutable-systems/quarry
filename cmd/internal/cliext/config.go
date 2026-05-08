// Copyright (C) 2026 Amutable GmbH

package cliext

import (
	"context"
	"fmt"
	"os"

	"github.com/urfave/cli/v3"

	"go.amutable.dev/quarry/internal/third_party/funchelpers"
	"go.amutable.dev/quarry/internal/tufclient/config"
)

type ctxKey string

const configCtxKey ctxKey = "--config"

// WithConfigFlag adds the --config flag to [cli.Command].
func WithConfigFlag(cmd *cli.Command) *cli.Command {
	cmd.Flags = append(cmd.Flags,
		&cli.StringFlag{
			Name:      "config",
			Usage:     "path to the quarry-client configuration file",
			TakesFile: true,
			Value:     config.DefaultConfigPath(),
			Sources:   cli.EnvVars("QUARRY_CLIENT_CONFIG"),
		},
		&cli.StringFlag{
			Name:      "cache-dir",
			Usage:     "local cache directory for TUF metadata",
			TakesFile: true,
			Value:     "/var/lib/quarry-client/latest-metadata",
			Sources:   cli.EnvVars("QUARRY_CLIENT_CACHEDIR"),
		})

	cmd.Before = WrapBeforeFuncs(cmd.Before, func(ctx context.Context, cmd *cli.Command) (_ context.Context, Err error) {
		cfgPath := cmd.String("config")

		cfgFile, err := os.Open(cfgPath) //nolint:forbidigo // user-controlled host path
		if err != nil {
			return nil, fmt.Errorf("open config: %w", err)
		}
		defer funchelpers.VerifyClose(&Err, cfgFile)

		cfg, err := config.Parse(cfgFile)
		if err != nil {
			return nil, fmt.Errorf("invalid config %s: %w", cfgPath, err)
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
	return CtxValue[*config.Config](ctx, configCtxKey)
}
