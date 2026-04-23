// Copyright (C) 2026 Amutable GmbH

// hardhat is a proof-of-concept helper for managing local quarry repos.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/urfave/cli/v3"
)

var app = &cli.Command{
	Name:  "hardhat",
	Usage: "very preliminary quarry operator",
	// TODO: We might want to have a flag to specify a custom context with
	// a deadline? And possibly some SIGINT-based cancellation?
	Commands: []*cli.Command{
		targetsCommand,
		keyctlCommand,
		repoctlCommand,
	},
}

func Main(args []string) error {
	return app.Run(context.Background(), args)
}

func main() {
	if err := Main(os.Args); err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}
}
