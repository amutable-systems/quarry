// Copyright (C) 2026 Amutable GmbH

package sysupdate

import (
	"context"
	"fmt"
	"os"

	"cyphar.com/go-pathrs"
	"github.com/urfave/cli/v3"

	"go.amutable.dev/quarry/cmd/internal/cliext"
	"go.amutable.dev/quarry/internal/ctxext"
	"go.amutable.dev/quarry/internal/xsysupdate"
)

const (
	// TODO: It might be nice to be able to calculate this by looking at the
	// system configuration (or the output from systemd-sysupdate) to not have
	// to duplicate the configuration here.
	quarryProxyURL = "http://localhost:555/" // quarry-client-http.service
)

type ctxKey string

const quarryProxyURLCtxKey ctxKey = "--quarry-proxy"

func withQuarryProxyFlag(cmd *cli.Command) *cli.Command {
	cmd.Flags = append(cmd.Flags,
		&cli.StringFlag{
			Name:  "quarry-proxy",
			Usage: "local 'quarry-client http' service URL (used for transfer file patching)",
			Value: quarryProxyURL,
		})

	cmd.Before = cliext.WrapBeforeFuncs(cmd.Before, func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
		ctx = context.WithValue(ctx, quarryProxyURLCtxKey, cmd.String("quarry-proxy"))
		return ctx, nil
	})

	return cmd
}

func ctxQuarryProxyURL(ctx context.Context) *string {
	url := ctxext.Value[string](ctx, quarryProxyURLCtxKey)
	if url == "" {
		url = quarryProxyURL
	}
	return &url
}

const quarryUserCtxKey ctxKey = "--quarry-user"

func withQuarryUserFlag(cmd *cli.Command) *cli.Command {
	cmd.Flags = append(cmd.Flags,
		&cli.StringFlag{
			Name:    "quarry-user",
			Aliases: []string{"u", "user"},
			Usage:   "user to switch to when acting as quarry-client (i.e., owner of /var/lib/quarry-client)",
			Value:   "quarry",
		})

	cmd.Before = cliext.WrapBeforeFuncs(cmd.Before, func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
		ctx = context.WithValue(ctx, quarryUserCtxKey, cmd.String("quarry-user"))
		return ctx, nil
	})

	return cmd
}

func ctxQuarryUser(ctx context.Context) string {
	return ctxext.Value[string](ctx, quarryUserCtxKey)
}

func withExtensionDirFlag(cmd *cli.Command) *cli.Command {
	cmd.Flags = append(cmd.Flags,
		&cli.StringFlag{
			Name:  "extension-dir",
			Usage: "directory where sysupdate extension files are stored",
			Value: xsysupdate.DefaultRootDir,
		})

	cmd.Before = cliext.WrapBeforeFuncs(cmd.Before, func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
		if cmd.IsSet("extension-dir") {
			rootPath := cmd.String("extension-dir")
			if err := os.MkdirAll(rootPath, 0o755); err != nil { //nolint:forbidigo // user-controlled host path
				return nil, fmt.Errorf("create --extension-dir=%s: %w", rootPath, err)
			}
			rootDir, err := pathrs.OpenRoot(rootPath)
			if err != nil {
				return nil, fmt.Errorf("open --extension-dir=%s: %w", rootPath, err)
			}
			ctx = context.WithValue(ctx, xsysupdate.RootDirCtxKey, rootDir)
		}
		return ctx, nil
	})

	cmd.After = cliext.WrapAfterFuncs(cmd.After, func(ctx context.Context, _ *cli.Command) error {
		if rootDir := xsysupdate.CtxRootDir(ctx); rootDir != nil {
			if err := rootDir.Close(); err != nil {
				return err
			}
		}
		return nil
	})

	return cmd
}
