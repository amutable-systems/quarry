// Copyright (C) 2026 Amutable GmbH

// quarry-client is a TUF client that is primarily designed to act as a bridge
// between quarry repositories and systemd's sysupdate.
package main

import (
	"context"
	"fmt"
	"os"

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

func Main(args []string) error {
	return app.Run(context.Background(), args)
}

func main() {
	if err := Main(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
