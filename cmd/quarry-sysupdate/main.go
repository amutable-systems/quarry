// Copyright (C) 2026 Amutable GmbH

// Package sysupdate implements quarry-sysupdate, a wrapper around
// systemd-sysupdate that implements some Quarry-specific extensions we plan
// to upstream at some point. It is an applet of the quarry multi-call binary
// (cmd/quarry).
package sysupdate

import (
	"context"

	"github.com/urfave/cli/v3"

	"go.amutable.dev/quarry/cmd/internal/cliext"
)

var app = cliext.WithRefTimeFlag(cliext.WithConfigFlag(&cli.Command{
	Name:  "quarry-sysupdate",
	Usage: "sysupdate runner with quarry-client extensions",
	// TODO: We might want to have a flag to specify a custom context with
	// a deadline? And possibly some SIGINT-based cancellation?
	Commands: []*cli.Command{
		updateCommand,
		// TODO: rebootCommand
		// TODO: How much of sysupdate should we replicate here?
	},
}))

// Main is the entrypoint for the quarry-sysupdate applet.
func Main(args []string) error {
	return app.Run(context.Background(), args)
}
