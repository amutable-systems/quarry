// Copyright (C) 2026 Amutable GmbH

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"cyphar.com/go-pathrs"
	"github.com/opencontainers/go-digest"
	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/urfave/cli/v3"
	"golang.org/x/sys/unix"

	"go.amutable.dev/quarry/internal/keystore"
	"go.amutable.dev/quarry/internal/linux"
	"go.amutable.dev/quarry/internal/pathrsext"
	"go.amutable.dev/quarry/internal/tufext"
)

func stripComponents(path string, toStrip int) string {
	path = filepath.Clean(path) //nolint:forbidigo // lexical paths
	components := strings.SplitN(path, "/", toStrip+1)
	if len(components) <= toStrip {
		return "."
	}
	return components[toStrip]
}

// TODO: Support specifying a set of hashes or at least a different hash algo.
var hashAlgorithm = digest.SHA256

func hashToTargets(ctx context.Context, builder *tufext.TargetsBuilder, logicalPath string, file *os.File) error { //nolint:unparam // ctx might be used in the future
	st, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to fstat %s: %w", file.Name(), err)
	}

	if st.IsDir() {
		children, err := file.Readdirnames(-1)
		if err != nil {
			return fmt.Errorf("failed to iterate over directory %s: %w", file.Name(), err)
		}
		for _, child := range children {
			logicalSubpath := filepath.Join(logicalPath, child) //nolint:forbidigo // lexical paths
			subfile, err := linux.Openat(file, child, unix.O_RDONLY|unix.O_NOFOLLOW)
			if err != nil {
				return fmt.Errorf("could not open child %s: %w", logicalSubpath, err)
			}
			err = hashToTargets(ctx, builder, logicalSubpath, subfile)
			_ = subfile.Close()
			if err != nil {
				return err
			}
		}
		return nil
	}

	// Make sure we don't end up with a nonsense name.
	if filepath.Join("/", logicalPath) == "/" { //nolint:forbidigo // lexical paths
		return fmt.Errorf("--skip-components value too large -- no components left for file %s", file.Name())
	}

	digester := hashAlgorithm.Digester()
	// TODO: Make this cancellable.
	size, err := io.Copy(digester.Hash(), file)
	if err != nil {
		return fmt.Errorf("compute file %s hash: %w", file.Name(), err)
	}
	digest := digester.Digest()

	if _, err := builder.AddTargetFile(logicalPath, size, digest); err != nil {
		return fmt.Errorf("add file %s to targets data: %w", logicalPath, err)
	}
	return nil
}

// sumFileRe matches the "standard" line format for "hashsum" files.
var sumFileRe = regexp.MustCompile(`^([0-9a-fA-F]+)\s+(.+)$`)

func addPrehashedToTargets(_ context.Context, builder *tufext.TargetsBuilder, logicalPath string, sumFile *os.File) error {
	if filepath.Join("/", logicalPath) == "/" { //nolint:forbidigo // lexical paths
		return fmt.Errorf("--skip-components value too large -- no components left for sumfile %s", sumFile.Name())
	}
	// logicalPath references the sumfile, we care about the parent directory
	// for computing the logical subpath of paths referenced in the sumfile.
	logicalPath = filepath.Dir(logicalPath)

	// We need to open the parent directory of the *actual* sumfile.
	root, err := pathrs.OpenRoot(filepath.Dir(sumFile.Name()))
	if err != nil {
		return fmt.Errorf("failed to open parent directory of sumfile %s: %w", sumFile.Name(), err)
	}

	var skippedLines uint
	scanner := bufio.NewScanner(sumFile)
	for scanner.Scan() {
		parts := sumFileRe.FindStringSubmatch(scanner.Text())
		if len(parts) != 3 {
			// This line does not contain a hashsum line (it might be empty or
			// a inline-signed sumfile that contains non-hash lines).
			// TODO: Add logging?
			skippedLines++
			continue
		}
		hash, subpath := strings.ToLower(parts[1]), parts[2]

		// Compute the logical subpath of the referenced file.
		logicalSubpath := filepath.Join(logicalPath, subpath) //nolint:forbidigo // lexical paths

		// Make sure the digest is valid.
		if err := hashAlgorithm.Validate(hash); err != nil {
			// TODO: Add proper logging.
			fmt.Fprintf(os.Stderr, "skipping invalid hash %q: %v\n", hash, err)
			skippedLines++
			continue
		}
		digest := digest.NewDigestFromEncoded(hashAlgorithm, hash)

		// Get the size.
		st, err := pathrsext.Stat(root, subpath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot stat hashed file %q: %v\n", subpath, err)
			skippedLines++
			continue
		}

		if _, err := builder.AddTargetFile(logicalSubpath, st.Size(), digest); err != nil {
			return fmt.Errorf("add file %s to targets data: %w", logicalSubpath, err)
		}
	}
	if skippedLines > 0 {
		// TODO: Add proper logging.
		fmt.Fprintf(os.Stderr, "== SKIPPED %d invalid lines in %s ==\n", skippedLines, sumFile.Name())
	}
	return nil
}

var targetsCommand = withKeystoreFlag(&cli.Command{
	Name:  "targets",
	Usage: "generate a TUF targets.json (or delegated target) file",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:      "output",
			Aliases:   []string{"o"},
			Usage:     "output file for the TUF targets data",
			TakesFile: true,
			Value:     "-",
		},
		&cli.UintFlag{
			Name:  "strip-components",
			Usage: "strip N parent components from paths when adding them to target.json",
		},
		&cli.BoolFlag{
			Name:    "pre-hashed",
			Aliases: []string{"H"},
			Usage:   "indicates that the given paths are all hashsum files (the listed files must still exist to get their size)",
		},
		// TODO: Move --ref-time and --expire-after to utils?
		&cli.TimestampFlag{
			Name:  "ref-time",
			Usage: "configure the reference time used for the targets file",
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
			Usage: "configure the expiry of the targets file (duration relative to --ref-time)",
		},
	},
	Arguments: []cli.Argument{
		// TODO: This doesn't work if you have pre-hashed values.
		// TODO: This won't work if you have enough files to hit the
		// PAGE_SIZE(?) argv limit.
		&cli.StringArgs{
			Name:      "files",
			UsageText: "<file-or-dir> [<file-or-dir>]...",
			Min:       1,
			Max:       -1,
		},
	},
	MutuallyExclusiveFlags: []cli.MutuallyExclusiveFlags{
		{
			Flags: [][]cli.Flag{
				{
					&cli.StringFlag{
						Name:      "from-root",
						Usage:     "source the signing keys from a root.json",
						TakesFile: true,
					},
				},
				{
					&cli.StringSliceFlag{
						Name:    "keyid",
						Aliases: []string{"k"},
						Usage:   "use the given keys to sign the targets file",
					},
				},
			},
			Required: true,
		},
	},
	Action: func(ctx context.Context, cmd *cli.Command) error {
		store := ctxKeystore(ctx)

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

		var keyIDs []string
		switch {
		case cmd.IsSet("from-root"):
			rootPath := cmd.String("from-root")

			rootData, err := os.ReadFile(rootPath) //nolint:forbidigo // user-controlled host path
			if err != nil {
				return fmt.Errorf("could not read root.json: %w", err)
			}
			var root tufext.SignedRoot
			if err := json.Unmarshal(rootData, &root); err != nil {
				return fmt.Errorf("invalid root.json: %w", err)
			}
			// Assume the root is validly signed.
			keyIDs = root.Signed.Roles[tufmetadata.TARGETS].KeyIDs
		case cmd.IsSet("keyid"):
			keyIDs = cmd.StringSlice("keyid")
		default:
			return fmt.Errorf("one of --from-root or --keyid must be set")
		}

		keys := make([]*keystore.GenericKey, 0, len(keyIDs))
		for _, keyID := range keyIDs {
			key, err := store.GetKey(ctx, keystore.KeyID(keyID))
			if err != nil {
				return fmt.Errorf("cannot load signing key %s: %w", keyID, err)
			}
			keys = append(keys, key)
		}

		builder := tufext.NewTargetsBuilder()

		if cmd.IsSet("ref-time") {
			builder.RefTime = cmd.Timestamp("ref-time")
		}
		if cmd.IsSet("expire-after") {
			builder.ExpireAfter = cmd.Duration("expire-after")
		}

		// TODO: Support adding delegations.

		for _, filename := range cmd.StringArgs("files") {
			file, err := os.Open(filename) //nolint:forbidigo // user-controlled host path
			if err != nil {
				return err
			}
			logicalFilename := stripComponents(filename, int(cmd.Uint("strip-components")))
			if cmd.Bool("pre-hashed") {
				if err := addPrehashedToTargets(ctx, builder, logicalFilename, file); err != nil {
					return fmt.Errorf("failed to add sumfile %s contents (as %s) to targets: %w", filename, logicalFilename, err)
				}
			} else {
				if err := hashToTargets(ctx, builder, logicalFilename, file); err != nil {
					return fmt.Errorf("failed to add %s (as %s) to targets: %w", filename, logicalFilename, err)
				}
			}
		}

		signed, err := builder.SignWith(ctx, store, keys...)
		if err != nil {
			return fmt.Errorf("failed to sign targets data: %w", err)
		}
		payload, err := cjson.EncodeCanonical(signed)
		if err != nil {
			return fmt.Errorf("failed to encode targets data: %w", err)
		}
		n, err := io.Copy(output, bytes.NewReader(payload))
		if err != nil {
			return fmt.Errorf("failed to write targets data: %w", err)
		}
		if output != os.Stdout {
			fmt.Printf("wrote %d bytes to %s", n, cmd.String("output"))
		} else {
			fmt.Printf("\n")
		}
		return nil
	},
})
