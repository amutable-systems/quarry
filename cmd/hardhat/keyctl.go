// Copyright (C) 2026 Amutable GmbH

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/urfave/cli/v3"

	"go.amutable.dev/quarry/internal/keystore"
)

var keyctlCommand = &cli.Command{
	Name:  "keyctl",
	Usage: "manage keys in a quarry keystore",
	Commands: []*cli.Command{
		keyctlDriversCommand,
		withKeystoreFlag(keyctlGenerateCommand),
		withKeystoreFlag(keyctlDeleteCommand),
		withKeystoreFlag(keyctlListCommand),
		withKeystoreFlag(keyctlInfoCommand),
		// TODO: export
		// TODO: import
	},
}

var keyctlDriversCommand = &cli.Command{
	Name:  "drivers",
	Usage: "get a list of supported drivers",
	Action: func(_ context.Context, _ *cli.Command) error {
		fmt.Println("Enabled drivers:")
		for driver := range keystore.IterDrivers() {
			var suffix string
			if driver == keystore.DefaultDriver {
				suffix = " (default)"
			}
			fmt.Printf(" - %s%s\n", driver, suffix)
		}
		return nil
	},
}

var keyctlGenerateCommand = &cli.Command{
	Name:    "generate",
	Aliases: []string{"create"},
	Usage:   "generate a new key and store in the keystore",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "driver",
			Usage: "driver to use when generating the key",
			Value: keystore.DefaultDriver,
		},
		// TODO: Add flags for generating different kinds of keys.
	},
	Action: func(ctx context.Context, cmd *cli.Command) error {
		store := ctxKeystore(ctx)
		driver := cmd.String("driver")

		keyID, _, err := store.GenerateKey(ctx, driver)
		if err != nil {
			return fmt.Errorf("failed to generate key: %w", err)
		}
		fmt.Println(keyID)
		return nil
	},
}

var keyctlDeleteCommand = &cli.Command{
	Name:  "delete",
	Usage: "remove a key from the keystore",
	Arguments: []cli.Argument{
		&cli.StringArg{
			Name: "keyid",
		},
	},
	Action: func(ctx context.Context, cmd *cli.Command) error {
		store := ctxKeystore(ctx)
		keyID := keystore.KeyID(cmd.StringArg("keyid"))

		err := store.UnlinkKey(ctx, keyID)
		if err != nil {
			return fmt.Errorf("failed to delete key: %w", err)
		}
		return nil
	},
}

var keyctlListCommand = &cli.Command{
	Name:  "list",
	Usage: "list all of the key ids in the keystore",
	MutuallyExclusiveFlags: []cli.MutuallyExclusiveFlags{
		{
			Flags: [][]cli.Flag{
				{
					&cli.BoolFlag{
						Name:    "verbose",
						Usage:   "output more textual information about each key",
						Aliases: []string{"v"},
					},
				},
				{
					&cli.BoolFlag{
						Name:  "json",
						Usage: "output information about each key as a JSON map",
					},
				},
			},
		},
	},
	Action: func(ctx context.Context, cmd *cli.Command) error {
		store := ctxKeystore(ctx)
		verbose := cmd.Bool("verbose")

		var allKeys map[keystore.KeyID]*keystore.GenericKey
		if cmd.Bool("json") {
			allKeys = make(map[keystore.KeyID]*keystore.GenericKey)
		}
		for keyID, err := range store.ListKeyIDs(ctx) {
			if err != nil {
				return fmt.Errorf("failed to list keys: %w", err)
			}
			if allKeys == nil && !verbose {
				fmt.Println(keyID)
				continue
			}

			key, err := store.GetKey(ctx, keyID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "could not get key %s: %v", keyID, err)
				continue
			}
			switch {
			case verbose:
				if err := pprintGenericKey("", key); err != nil {
					fmt.Fprintf(os.Stderr, "could not output key %s: %v", keyID, err)
					continue
				}
			case allKeys != nil:
				allKeys[keyID] = key
			}
		}
		if allKeys != nil {
			if err := json.NewEncoder(os.Stdout).Encode(allKeys); err != nil {
				return err
			}
		}
		return nil
	},
}

var keyctlInfoCommand = &cli.Command{
	Name:  "info",
	Usage: "output information about the given key",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:  "json",
			Usage: "output information about the key in a JSON format",
			Value: false,
		},
	},
	Arguments: []cli.Argument{
		&cli.StringArg{
			Name: "keyid",
		},
	},
	Action: func(ctx context.Context, cmd *cli.Command) error {
		store := ctxKeystore(ctx)
		keyID := keystore.KeyID(cmd.StringArg("keyid"))

		key, err := store.GetKey(ctx, keyID)
		if err != nil {
			return fmt.Errorf("failed to get key %s: %w", keyID, err)
		}
		if cmd.Bool("json") {
			return json.NewEncoder(os.Stdout).Encode(key)
		}
		return pprintGenericKey("", key)
	},
}
