// Copyright (C) 2026 Amutable GmbH

// quarry-sysupdate is a wrapper around systemd-sysupdate that implements some
// Quarry-specific extensions we plan to upstream at some point.
package main

import (
	"context"
	"fmt"
	"os"

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

func Main(args []string) error {
	return app.Run(context.Background(), args)
}

func main() {
	if err := Main(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
