// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

// Package client implements quarry-client, a TUF client that is primarily
// designed to act as a bridge between quarry repositories and systemd's
// sysupdate. It is an applet of the quarry multi-call binary (cmd/quarry).
package client

import (
	"context"

	"github.com/urfave/cli/v3"

	"go.amutable.dev/quarry/cmd/internal/cliext"
)

var app = cliext.WithRefTimeFlag(cliext.WithConfigFlag(&cli.Command{
	Name:  "quarry-client",
	Usage: "TUF client acting as a sysupdate bridge",
	// TODO: We might want to have a flag to specify a custom context with
	// a deadline? And possibly some SIGINT-based cancellation?
	Commands: []*cli.Command{
		listCommand,
		fetchCommand,
		refreshCommand,
		// TODO: infoCommand?
	},
}))

// Main is the entrypoint for the quarry-client applet.
func Main(args []string) error {
	return app.Run(context.Background(), args)
}
