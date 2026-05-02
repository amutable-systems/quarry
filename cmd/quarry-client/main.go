// Copyright (C) 2026 Amutable GmbH

// quarry-client is a TUF client that is primarily designed to act as a bridge
// between quarry repositories and systemd's sysupdate.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/urfave/cli/v3"
)

var app = withCacheDirFlag(withConfigFlag(&cli.Command{
	Name:  "quarry-client",
	Usage: "TUF client acting as a sysupdate bridge",
	Flags: []cli.Flag{
		// TODO: Move --ref-time to utils?
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
		},
	},
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
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}
}
