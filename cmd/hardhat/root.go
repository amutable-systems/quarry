// Copyright (C) 2026 Amutable GmbH

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/urfave/cli/v3"

	"go.amutable.dev/quarry/internal/keystore"
	"go.amutable.dev/quarry/internal/tufext"
	"go.amutable.dev/quarry/internal/tufrepo"
)

var generateRootFlags = []cli.Flag{
	&cli.StringFlag{
		Name:  "driver",
		Usage: "driver to use when generating keys",
		Value: keystore.DefaultDriver,
	},
	// TODO: Add flags for generating different kinds of keys.
	&cli.StringMapFlag{
		Name:  "keys",
		Usage: "specify the public keys used for each role (<role>=<type>:<key>,<type>:<key> -- valid types are 'keyid' and 'ed25519')",
	},
	// TODO: Ideally we would have an IntMapFlag...
	&cli.StringMapFlag{
		Name:  "threshold",
		Usage: "specify the threshold of keys for each keys used for each format",
	},
	// TODO: Move --ref-time and --expire-after to utils?
	&cli.TimestampFlag{
		Name:  "ref-time",
		Usage: "configure the reference time (defaults to now)",
		Value: time.Now().UTC(),
		Config: cli.TimestampConfig{
			Layouts: []string{
				time.RFC3339,
				time.RFC3339Nano,
				time.DateOnly,
				// TODO: It would be nice to be able to pass a Unix epoch.
			},
		},
	},
	&cli.DurationFlag{
		Name:  "expire-after",
		Value: tufrepo.DefaultRootExpiry,
		Usage: "configure the expiry of root.json (duration relative to --ref-time)",
	},
}

func checkGenerateRootFlags(ctx context.Context, cmd *cli.Command) (context.Context, error) {
	for roleName := range cmd.StringMap("keys") {
		if !tufext.IsCoreRole(roleName) {
			return nil, fmt.Errorf("role %s specified in --keys is not a core role", roleName)
		}
	}
	for roleName := range cmd.StringMap("threshold") {
		if !tufext.IsCoreRole(roleName) {
			return nil, fmt.Errorf("role %s specified in --threshold is not a core role", roleName)
		}
	}
	return ctx, nil
}

func generateRoot(ctx context.Context, cmd *cli.Command) (_ *tufext.SignedRoot, _ map[string][]keystore.KeyID, Err error) {
	store := ctxKeystore(ctx)

	// Collect the threshold configuration first.
	roleThresholds := make(map[string]int, len(tufmetadata.TOP_LEVEL_ROLE_NAMES))
	for _, roleName := range tufmetadata.TOP_LEVEL_ROLE_NAMES {
		roleThresholds[roleName] = 1
	}
	for roleName, thresholdSpec := range cmd.StringMap("threshold") {
		threshold, err := strconv.ParseUint(thresholdSpec, 10, 32)
		if threshold <= 0 && err == nil {
			err = errors.New("threshold must be >= 1")
		}
		if err != nil {
			return nil, nil, fmt.Errorf("specified rold %s threshold %q is invalid: %w", roleName, thresholdSpec, err)
		}
		roleThresholds[roleName] = int(threshold)
	}
	// Make sure we always generate at least the threshold number of keys.
	toGenerateKeys := make(map[string]int, len(tufmetadata.TOP_LEVEL_ROLE_NAMES))
	for roleName, threshold := range roleThresholds {
		toGenerateKeys[roleName] = threshold
	}
	// Collect specified keys.
	rolePubKeys := make(map[string][]string, len(tufmetadata.TOP_LEVEL_ROLE_NAMES))
	for roleName, pubKeysSpec := range cmd.StringMap("keys") {
		rolePubKeys[roleName] = strings.Split(pubKeysSpec, ",")
		toGenerateKeys[roleName] -= len(rolePubKeys[roleName]) // already have those keys
	}
	// Generate remaining keys.
	newRoleKeyIDs := make(map[string][]keystore.KeyID, len(tufmetadata.TOP_LEVEL_ROLE_NAMES))
	defer func() { //nolint:contextcheck // ctx is not passed intentionally
		// Make sure to clean up any generated keys in case of an error.
		if Err != nil {
			// TODO: We want to force the removal even if the context was
			// cancelled, but we might also want to have some kind of
			// deadline here just in case? Or maybe we should use
			// context.WithoutCancel?
			ctx := context.TODO()
			for _, keyIDs := range newRoleKeyIDs {
				for _, keyID := range keyIDs {
					_ = store.UnlinkKey(ctx, keyID)
				}
			}
			newRoleKeyIDs = nil
		}
	}()
	for roleName, toGenerate := range toGenerateKeys {
		driver := cmd.String("driver")
		for n := range toGenerate {
			keyID, _, err := store.GenerateKey(ctx, driver)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to generate key %d (of %d) for role %s: %w", n+1, toGenerate, roleName, err)
			}
			newRoleKeyIDs[roleName] = append(newRoleKeyIDs[roleName], keyID)
			rolePubKeys[roleName] = append(rolePubKeys[roleName], "keyid:"+string(keyID))
		}
	}

	// Generate and sign the initial root.
	builder := tufext.NewRootBuilder()
	builder.GenerateKeyDriver = cmd.String("driver")
	if cmd.IsSet("ref-time") {
		builder.RefTime = cmd.Timestamp("ref-time")
	}
	if cmd.IsSet("expire-after") {
		builder.ExpireAfter = cmd.Duration("expire-after")
	}
	for roleName, pubKeySpecs := range rolePubKeys {
		pubKeys := make([]keystore.PublicKey, 0, len(pubKeySpecs))
		for _, pubKeySpec := range pubKeySpecs {
			pubKey, err := parsePublicKey(ctx, store, pubKeySpec)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid public key %s for role %s: %w", pubKeySpec, roleName, err)
			}
			pubKeys = append(pubKeys, *pubKey)
		}
		if _, err := builder.AddRole(roleName, roleThresholds[roleName], pubKeys...); err != nil {
			return nil, nil, fmt.Errorf("could not configure role %s keys: %w", roleName, err)
		}
	}
	// TODO: We have the chance above to collect the root keys, we should
	// probably do that to avoid fetching them again in Sign...
	signedRoot, builderNewKeys, err := builder.Sign(ctx, store)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign root.json: %w", err)
	}
	if len(builderNewKeys) > 0 {
		// Programmer error.
		return nil, nil, fmt.Errorf("RootBuilder generated extraneous keys: %v", builderNewKeys)
	}
	return signedRoot, newRoleKeyIDs, nil
}

var rootCommand = withKeystoreFlag(&cli.Command{
	Name:  "root",
	Usage: "generate a TUF root.json file",
	Flags: append([]cli.Flag{
		&cli.StringFlag{
			Name:      "output",
			Aliases:   []string{"o"},
			Usage:     "output file for the TUF targets data",
			TakesFile: true,
			Value:     "-",
		},
	}, generateRootFlags...),
	Before: checkGenerateRootFlags,
	Action: func(ctx context.Context, cmd *cli.Command) error {
		var output io.Writer
		if outPath := cmd.String("output"); outPath != "-" {
			outFile, err := os.Create(outPath) //nolint:forbidigo // user-controlled host path
			if err != nil {
				return fmt.Errorf("invalid --output argument: %w", err)
			}
			defer outFile.Close() //nolint:errcheck // poc cli code
			output = outFile
		} else {
			output = os.Stdout
		}

		signedRoot, newRoleKeyIDs, err := generateRoot(ctx, cmd)
		if err != nil {
			return err
		}

		payload, err := cjson.EncodeCanonical(signedRoot)
		if err != nil {
			return fmt.Errorf("failed to encode targets data: %w", err)
		}
		n, err := io.Copy(output, bytes.NewReader(payload))
		if err != nil {
			return fmt.Errorf("failed to write targets data: %w", err)
		}
		if output != os.Stdout {
			fmt.Printf("wrote %d bytes to %s\n", n, cmd.String("output"))
			// Only output new key information if it won't cause issues with
			// pipelines / redirects.
			if len(newRoleKeyIDs) > 0 {
				fmt.Println("Generated keys:")
				for roleName, keyIDs := range newRoleKeyIDs {
					fmt.Printf("\t%s:\n", roleName)
					for _, keyID := range keyIDs {
						fmt.Printf("\t - %s\n", keyID)
					}
				}
			}
		} else {
			fmt.Printf("\n")
		}
		return nil
	},
})
