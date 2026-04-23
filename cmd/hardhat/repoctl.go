// Copyright (C) 2026 Amutable GmbH

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/urfave/cli/v3"

	"go.amutable.dev/quarry/internal/keystore"
	"go.amutable.dev/quarry/internal/tufext"
	"go.amutable.dev/quarry/internal/tufrepo"
)

var repoctlCommand = withRepoFlag(withKeystoreFlag(&cli.Command{
	Name:  "repoctl",
	Usage: "manage quarry repository",
	Commands: []*cli.Command{
		repoctlInitCommand,
		repoctlRefreshCommand,
		repoctlSnapshotCommand,
		// TODO: repoctlRotateKeysCommand,
		// TODO: repoctlInfoCommand, // ??
	},
}))

var repoctlInitCommand = &cli.Command{
	Name:  "init",
	Usage: "create a new quarry repository",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "driver",
			Usage: "driver to use when generating keys",
			Value: keystore.DefaultDriver,
		},
		// TODO: Add flags for generating different kinds of keys.
		&cli.StringMapFlag{
			Name:  "keys",
			Usage: "specify the keys used for each format (comma-separated set of keysformat is <role>=<keyid1>,<keyid2>,...)",
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
	},
	Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
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
	},
	Action: func(ctx context.Context, cmd *cli.Command) (Err error) {
		repo := ctxRepo(ctx)
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
				return fmt.Errorf("specified rold %s threshold %q is invalid: %w", roleName, thresholdSpec, err)
			}
			roleThresholds[roleName] = int(threshold)
		}
		// Make sure we always generate at least the threshold number of keys.
		toGenerateKeys := make(map[string]int, len(tufmetadata.TOP_LEVEL_ROLE_NAMES))
		for roleName, threshold := range roleThresholds {
			toGenerateKeys[roleName] = threshold
		}
		// Collect specified keys.
		roleKeyIDs := make(map[string][]keystore.KeyID, len(tufmetadata.TOP_LEVEL_ROLE_NAMES))
		for roleName, keyIDsSpec := range cmd.StringMap("keys") {
			var keyIDs []keystore.KeyID
			for keyID := range strings.SplitSeq(keyIDsSpec, ",") {
				// TODO: Maybe we should allow users to specify "generate"/"_"
				// or some other special value to indicate that a key should be
				// generated.
				keyID := keystore.KeyID(keyID)
				if !keyID.IsValid() {
					return fmt.Errorf("specified key %q for role %s is an invalid key id", keyID, roleName)
				}
				keyIDs = append(keyIDs, keyID)
			}
			roleKeyIDs[roleName] = keyIDs
			toGenerateKeys[roleName] -= len(keyIDs) // already have those keys
		}
		// Generate remaining keys.
		newKeyIDs := make(map[string][]keystore.KeyID, len(tufmetadata.TOP_LEVEL_ROLE_NAMES))
		defer func() {
			// Make sure to clean up any generated keys in case of an error.
			if Err != nil {
				// TODO: We want to force the removal even if the context was
				// cancelled, but we might also want to have some kind of
				// deadline here just in case? Or maybe we should use
				// context.WithoutCancel?
				ctx := context.TODO()
				for _, keyIDs := range newKeyIDs {
					for _, keyID := range keyIDs {
						_ = store.UnlinkKey(ctx, keyID)
					}
				}
				newKeyIDs = nil
			}
		}()
		for roleName, toGenerate := range toGenerateKeys {
			driver := cmd.String("driver")
			for n := range toGenerate {
				keyID, _, err := store.GenerateKey(ctx, driver)
				if err != nil {
					return fmt.Errorf("failed to generate key %d (of %d) for role %s: %w", n+1, toGenerate, roleName, err)
				}
				newKeyIDs[roleName] = append(newKeyIDs[roleName], keyID)
				roleKeyIDs[roleName] = append(roleKeyIDs[roleName], keyID)
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
		for roleName, keyIDs := range roleKeyIDs {
			publicKeys := make([]keystore.PublicKey, 0, len(keyIDs))
			for _, keyID := range keyIDs {
				// TODO: We need a mechanism to only fetch public keys.
				key, err := store.GetKey(ctx, keyID)
				if err != nil {
					return fmt.Errorf("could not get key %s for role %s: %w", keyID, roleName, err)
				}
				publicKeys = append(publicKeys, key.Public)
			}
			if _, err := builder.AddRole(roleName, roleThresholds[roleName], publicKeys...); err != nil {
				return fmt.Errorf("could not configure role %s keys: %w", roleName, err)
			}
		}
		// TODO: We have the chance above to collect the root keys, we should
		// probably do that to avoid fetching them again in Sign...
		signedRoot, builderNewKeys, err := builder.Sign(ctx, store)
		if err != nil {
			return fmt.Errorf("failed to sign root.json: %w", err)
		}
		if len(builderNewKeys) > 0 {
			// Programmer error.
			return fmt.Errorf("RootBuilder generated extraneous keys: %v", builderNewKeys)
		}

		// Create an initial transaction to use.
		initTxn := tufrepo.InitTxn(signedRoot)
		// TODO: Make the initial transaction configurable...

		// TODO: Do we actually want to Sign this...?

		commitNewKeys, err := initTxn.Sign(ctx, store)
		if err != nil {
			return fmt.Errorf("failed to sign initial transaction: %w", err)
		}
		if len(commitNewKeys) > 0 {
			// Programmer error.
			return fmt.Errorf("Transaction.Sign generated extraneous keys: %v", commitNewKeys)
		}

		// TODO: Make committing this to the repo optional.
		timestamp, err := repo.TxnCommit(ctx, initTxn)
		if err != nil {
			return fmt.Errorf("failed to commit the initial transaction to the repo: %w", err)
		}

		if len(newKeyIDs) > 0 {
			fmt.Println("Generated keys:")
			for roleName, keyIDs := range newKeyIDs {
				fmt.Printf("\t%s:\n", roleName)
				for _, keyID := range keyIDs {
					fmt.Printf("\t - %s\n", keyID)
				}
			}
		}
		fmt.Println("root.json:")
		pprintToJSON("\t", signedRoot)
		fmt.Println("timestamp.json:")
		pprintToJSON("\t", timestamp)
		return nil
	},
}

var repoctlRefreshCommand = &cli.Command{
	Name:  "refresh",
	Usage: "refresh the repo's timestamp.json",
	Flags: []cli.Flag{
		&cli.StringSliceFlag{
			Name:    "role",
			Aliases: []string{"r"},
			Usage:   "set of roles to refresh",
			Value:   []string{"timestamp"},
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
		// TODO: expire-after should probably be a map because we can specify
		// multiple roles.
		&cli.DurationFlag{
			Name:  "expire-after",
			Value: tufrepo.DefaultTimestampExpiry,
			Usage: "configure the expiry of the roles specified in --role (duration relative to --ref-time)",
		},
	},
	MutuallyExclusiveFlags: []cli.MutuallyExclusiveFlags{
		{
			Flags: [][]cli.Flag{
				{
					&cli.DurationFlag{
						Name:  "refresh-if-expires-in",
						Value: 6 * time.Hour,
						Usage: "how far away from expiry should the timestamp.json be for it to be refreshed?",
					},
				},
				{
					&cli.BoolFlag{
						Name:    "force-refresh",
						Aliases: []string{"f", "force"},
						Usage:   "always refresh timestamp.json",
					},
				},
			},
		},
	},
	Action: func(ctx context.Context, cmd *cli.Command) error {
		repo := ctxRepo(ctx)
		store := ctxKeystore(ctx)

		tx, err := repo.TxnStart(ctx)
		if err != nil {
			return fmt.Errorf("start transaction: %w", err)
		}
		tx.RefTime = cmd.Timestamp("ref-time")

		var refreshWindow *time.Duration
		if !cmd.Bool("force-refresh") {
			v := cmd.Duration("refresh-if-expires-in")
			refreshWindow = &v
		}

		for _, roleName := range cmd.StringSlice("role") {
			if err := tx.BumpExpiry(ctx, roleName, func(oldExpiry time.Time, _ any) (*time.Time, error) {
				deadline := tx.RefTime.Add(-time.Second)
				if refreshWindow != nil {
					deadline = oldExpiry.Add(-*refreshWindow)
				}
				if tx.RefTime.Before(deadline) {
					fmt.Printf("Repository %s.json is not due for a refresh until %s (expiry is %s).\n",
						roleName, deadline.Format(time.RFC3339), oldExpiry.Format(time.RFC3339))
					return nil, nil //nolint:nilnil // nil indicates no change needed
				}
				expireAfter := cmd.Duration("expire-after")
				newExpiry := tx.RefTime.Add(expireAfter)
				fmt.Printf("Repository %s.json updated to expire at %s (duration is %s).\n",
					roleName, newExpiry.Format(time.RFC3339), expireAfter)
				return &newExpiry, nil
			}); err != nil {
				return fmt.Errorf("error while bumping role %s expiry: %w", roleName, err)
			}
		}

		newTimestampKeyIDs, err := tx.Sign(ctx, store)
		if err != nil {
			return fmt.Errorf("could not sign transaction: %w", err)
		}

		// TODO: Make committing this to the repo optional.
		timestamp, err := repo.TxnCommit(ctx, tx)
		if err != nil {
			return fmt.Errorf("failed to commit the transaction to the repo: %w", err)
		}

		if len(newTimestampKeyIDs) > 0 {
			fmt.Println("Rotated timestamp keys:")
			for _, keyID := range newTimestampKeyIDs {
				fmt.Printf(" - %s\n", keyID)
			}
		}

		fmt.Println("timestamp.json:")
		pprintToJSON("\t", timestamp)
		return nil
	},
}

var repoctlSnapshotCommand = &cli.Command{
	Name:  "snapshot",
	Usage: "update the repo's snapshot.json",
	Flags: []cli.Flag{
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
			Value: tufrepo.DefaultTimestampExpiry,
			Usage: "configure the expiry of snapshot.json (duration relative to --ref-time)",
		},
	},
	Arguments: []cli.Argument{
		&cli.StringArgs{
			Name:      "targets",
			UsageText: "<role1>=<path1> [<role2>=<path2>]...",
			Min:       1,
			Max:       -1,
		},
	},
	Action: func(ctx context.Context, cmd *cli.Command) error {
		repo := ctxRepo(ctx)
		store := ctxKeystore(ctx)

		tx, err := repo.TxnStart(ctx)
		if err != nil {
			return fmt.Errorf("start transaction: %w", err)
		}
		tx.RefTime = cmd.Timestamp("ref-time")

		for _, targets := range cmd.StringArgs("targets") {
			parts := strings.SplitN(targets, "=", 2)
			if len(parts) != 2 {
				return fmt.Errorf("%q is an invalid spec: must in the form 'role=path'", targets)
			}
			roleName, path := parts[0], parts[1]
			data, err := os.ReadFile(path) //nolint:forbidigo // user-controlled host path
			if err != nil {
				return fmt.Errorf("cannot read role %s data from path %s: %w", roleName, path, err)
			}
			if err := tx.UpdateRoleData(roleName, data); err != nil {
				return fmt.Errorf("failed to update role %s data in transaction: %w", roleName, err)
			}
		}

		newTimestampKeyIDs, err := tx.Sign(ctx, store)
		if err != nil {
			return fmt.Errorf("could not sign transaction: %w", err)
		}

		// TODO: Make committing this to the repo optional.
		timestamp, err := repo.TxnCommit(ctx, tx)
		if err != nil {
			return fmt.Errorf("failed to commit the transaction to the repo: %w", err)
		}

		if len(newTimestampKeyIDs) > 0 {
			fmt.Println("Rotated timestamp keys:")
			for _, keyID := range newTimestampKeyIDs {
				fmt.Printf(" - %s\n", keyID)
			}
		}

		fmt.Println("timestamp.json:")
		pprintToJSON("\t", timestamp)
		return nil
	},
}
