// Copyright (C) 2026 Amutable GmbH

package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/urfave/cli/v3"

	"go.amutable.dev/quarry/internal/keystore"
)

var keyctlCommand = withKeystoreFlag(&cli.Command{
	Name:  "keyctl",
	Usage: "manage keys in a quarry keystore",
	Commands: []*cli.Command{
		keyctlGenerateCommand,
		keyctlDeleteCommand,
		keyctlListCommand,
		keyctlInfoCommand,
		// TODO: export
		// TODO: import
	},
})

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

		keyID, _, err := store.GenerateKey(ctx, keystore.WithDriver(driver))
		if err != nil {
			return fmt.Errorf("failed to generate key: %w", err)
		}
		mustFprintln(os.Stdout, keyID)
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
				mustFprintln(os.Stdout, keyID)
				continue
			}

			key, err := store.GetKey(ctx, keyID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "could not get key %s: %v", keyID, err)
				continue
			}
			switch {
			case verbose:
				if err := pprintGenericKey(os.Stdout, "", key); err != nil {
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
	Flags: []cli.Flag{},
	Arguments: []cli.Argument{
		&cli.StringArg{
			Name: "keyid",
		},
	},
	MutuallyExclusiveFlags: []cli.MutuallyExclusiveFlags{
		{
			Flags: [][]cli.Flag{
				{
					&cli.StringFlag{
						Name:  "pkix",
						Usage: "output the public key in a PKIX ASN.1 DER form (--pkix=pem and --pkix=base64 are valid values)",
						Validator: func(s string) error {
							switch s {
							case "pem", "base64":
								return nil
							}
							return fmt.Errorf("%s is not a supported pkix encoding", s)
						},
					},
					&cli.BoolFlag{
						Name:  "json",
						Usage: "output information about the key in a JSON format",
					},
				},
			},
		},
	},
	Action: func(ctx context.Context, cmd *cli.Command) error {
		store := ctxKeystore(ctx)
		keyID := keystore.KeyID(cmd.StringArg("keyid"))

		key, err := store.GetKey(ctx, keyID)
		if err != nil {
			return fmt.Errorf("failed to get key %s: %w", keyID, err)
		}
		switch {
		case cmd.Bool("json"):
			return json.NewEncoder(os.Stdout).Encode(key)

		case cmd.IsSet("pkix"):
			pubKey, err := key.Public.ToPublicKey()
			if err != nil {
				return fmt.Errorf("parse public portion of key %s: %w", keyID, err)
			}

			der, err := x509.MarshalPKIXPublicKey(pubKey)
			if err != nil {
				return fmt.Errorf("marshal public key %s to pkix: %w", keyID, err)
			}
			switch cmd.String("pkix") {
			case "pem":
				if err := pem.Encode(os.Stdout, &pem.Block{
					Type:  "PUBLIC KEY",
					Bytes: der,
				}); err != nil {
					return err
				}
			case "base64":
				b64 := base64.NewEncoder(base64.StdEncoding, os.Stdout)
				if _, err := b64.Write(der); err != nil {
					return err
				}
				if err := b64.Close(); err != nil {
					return err
				}
				mustFprintln(os.Stdout)
			}

		default:
			return pprintGenericKey(os.Stdout, "", key)
		}
		return nil
	},
}
