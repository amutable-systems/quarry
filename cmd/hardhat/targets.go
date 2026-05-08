// Copyright (C) 2026 Amutable GmbH

package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cyphar.com/go-pathrs"
	"github.com/opencontainers/go-digest"
	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/urfave/cli/v3"
	"golang.org/x/sys/unix"

	"go.amutable.dev/quarry/cmd/internal/cliext"
	"go.amutable.dev/quarry/internal/jsonutils"
	"go.amutable.dev/quarry/internal/keystore"
	"go.amutable.dev/quarry/internal/linux"
	"go.amutable.dev/quarry/internal/pathrsext"
	"go.amutable.dev/quarry/internal/tufext"
)

// stripComponents removes the given number of leading path components, and is
// equivalent to GNU tar's --strip-components flag. Absolute paths have the
// leading slash stripped "for free" if the first component is also to be
// stripped, and multiple "/"s are treated as a single separator.
//
// Unfortunately, GNU tar and bsdtar (libarchive) have different semantics, but
// more users are probably familiar with GNU tar.
func stripComponents(path string, n int) string {
	for ; n > 0; n-- {
		path = strings.TrimLeft(path, "/")
		sepIdx := strings.IndexByte(path, '/')
		if sepIdx < 0 {
			return "." // ran out of components
		}
		path = strings.TrimLeft(path[sepIdx+1:], "/")
	}
	return path
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

const dataRootURLCtxKey ctxKey = "--data-root-url"

func ctxDataRoolURL(ctx context.Context) *url.URL {
	return cliext.CtxValue[*url.URL](ctx, dataRootURLCtxKey)
}

const extOverrideURLCtxKey ctxKey = "--ext-override-url"

func ctxExtOverrideURL(ctx context.Context) bool {
	return cliext.CtxValue[bool](ctx, extOverrideURLCtxKey)
}

// sumFileRe matches the "standard" line format for "hashsum" files.
var sumFileRe = regexp.MustCompile(`^([0-9a-fA-F]+)\s+(.+)$`)

func getContentLength(ctx context.Context, url *url.URL) (int64, error) {
	// TODO: Should we try to use HEAD? Though, RFC 9110 says that
	// Content-Length is not guaranteed to be set with HEAD. R2 does support it
	// but my testing indicated there wasn't really any speed improvement.
	req, err := http.NewRequestWithContext(ctx, "GET", url.String(), nil)
	if err != nil {
		return -1, fmt.Errorf("cannot create http request GET %q: %w", url, err)
	}
	client := http.DefaultClient
	res, err := client.Do(req)
	if err != nil {
		return -1, fmt.Errorf("fetch %s: %w", url, err)
	}
	_ = res.Body.Close()
	return res.ContentLength, nil
}

func addPrehashedToTargets(ctx context.Context, builder *tufext.TargetsBuilder, logicalPath string, sumFile *os.File) error {
	dataRootURL := ctxDataRoolURL(ctx)
	extOverrideURL := ctxExtOverrideURL(ctx)

	if filepath.Join("/", logicalPath) == "/" { //nolint:forbidigo // lexical paths
		return fmt.Errorf("--skip-components value too large -- no components left for sumfile %s", sumFile.Name())
	}
	// logicalPath references the sumfile, we care about the parent directory
	// for computing the logical subpath of paths referenced in the sumfile.
	logicalPath = filepath.Dir(logicalPath) //nolint:forbidigo // lexical paths

	// We need to open the parent directory of the *actual* sumfile.
	root, err := pathrs.OpenRoot(filepath.Dir(sumFile.Name())) //nolint:forbidigo // lexical paths
	if err != nil {
		return fmt.Errorf("failed to open parent directory of sumfile %s: %w", sumFile.Name(), err)
	}

	var (
		scanner      = bufio.NewScanner(sumFile)
		skippedLines atomic.Uint64
		wg           sync.WaitGroup
		queueCh      = make(chan struct{}, 32)
		errCh        = make(chan error, 32)
	)
	for scanner.Scan() {
		text := scanner.Text()
		wg.Go(func() {
			parts := sumFileRe.FindStringSubmatch(text)
			if len(parts) != 3 {
				// This line does not contain a hashsum line (it might be empty or
				// a inline-signed sumfile that contains non-hash lines).
				// TODO: Add logging?
				skippedLines.Add(1)
				return
			}
			hash, subpath := strings.ToLower(parts[1]), parts[2]

			// Wait for a slot.
			select {
			case <-ctx.Done():
				return // early exit
			case queueCh <- struct{}{}:
				defer func() { <-queueCh }()
			}

			// Compute the logical subpath of the referenced file.
			logicalSubpath := filepath.Join(logicalPath, subpath) //nolint:forbidigo // lexical paths

			// Make sure the digest is valid.
			if err := hashAlgorithm.Validate(hash); err != nil {
				// TODO: Add proper logging.
				fmt.Fprintf(os.Stderr, "skipping invalid hash %q: %v\n", hash, err)
				skippedLines.Add(1)
				return
			}
			digest := digest.NewDigestFromEncoded(hashAlgorithm, hash)

			var dataURL *url.URL
			if dataRootURL != nil {
				dataURL = dataRootURL.JoinPath(logicalSubpath)
			}

			// Get the size.
			size := int64(-1)
			if dataURL != nil {
				var err error
				size, err = getContentLength(ctx, dataURL)
				if err != nil {
					fmt.Fprintf(os.Stderr, "failed to fetch %q from --data-root-url (%v) -- falling back to local file stat\n", logicalSubpath, err)
				}
			}
			if size < 0 {
				st, err := pathrsext.Stat(root, subpath)
				if err != nil {
					fmt.Fprintf(os.Stderr, "cannot stat hashed file %q: %v\n", subpath, err)
					skippedLines.Add(1)
					return
				}
				size = st.Size()
			}
			target, err := builder.AddTargetFile(logicalSubpath, size, digest)
			if err != nil {
				errCh <- fmt.Errorf("add file %s to targets data: %w", logicalSubpath, err)
				return
			}
			if extOverrideURL {
				tufext.TargetFilesExt(target).WithOverrideURL(dataURL)
			}
		})
	}
	waitCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitCh)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-waitCh:
	case err := <-errCh:
		// This will cause ctx to get cancelled by urfave/cli.
		return fmt.Errorf("error during targets generation: %w", err)
	}
	if skipped := skippedLines.Load(); skipped > 0 {
		// TODO: Add proper logging.
		fmt.Fprintf(os.Stderr, "== SKIPPED %d invalid lines in %s ==\n", skipped, sumFile.Name())
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
		&cli.StringSliceFlag{
			Name:  "include-from",
			Usage: "include targets defined in the given targets.json files (later files take precedence, with <files> arguments taking highest precedence)",
		},
		&cli.BoolFlag{
			Name:  "ext-override-url",
			Usage: "when using --data-root-url --pre-hashed, add an override URL to each target file to make clients fetch from --data-root-url",
		},
		&cli.StringFlag{
			Name:  "data-root-url",
			Usage: "base url for target files (with --pre-hashed this allows you to generate a target.json entirely from a SHA256SUMS file)",
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
			Min:       0,
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
	Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
		if urlStr := cmd.String("data-root-url"); urlStr != "" {
			if !cmd.Bool("pre-hashed") {
				return nil, fmt.Errorf("--data-root-url doesn't make sense without --pre-hashed")
			}
			rootURL, err := url.Parse(urlStr)
			if err != nil {
				return nil, fmt.Errorf("invalid --data-root-url=%q: %w", urlStr, err)
			}
			ctx = context.WithValue(ctx, dataRootURLCtxKey, rootURL)
		}
		if cmd.Bool("ext-override-url") {
			if !cmd.IsSet("data-root-url") {
				return nil, fmt.Errorf("--ext-override-url doesn't make sense without --data-root-url (and --pre-hashed)")
			}
			ctx = context.WithValue(ctx, extOverrideURLCtxKey, true)
		}
		return ctx, nil
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
			root, err := jsonutils.Parse[tufext.SignedRoot](rootData)
			if err != nil {
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

		for _, includePath := range cmd.StringSlice("include-from") {
			data, err := os.ReadFile(includePath) //nolint:forbidigo // user-controlled host path
			if err != nil {
				return fmt.Errorf("--include-from=%q file is invalid: %w", includePath, err)
			}
			// TODO: Support unsigned targets.json files?
			targets, err := jsonutils.Parse[tufext.SignedTargets](data)
			if err != nil {
				return fmt.Errorf("--include-from=%q file is invalid json: %w", includePath, err)
			}
			// Make sure it is a targets.json (though we don't care about
			// signatures).
			if err := tufext.CheckMetadataType(tufmetadata.TARGETS, &targets); err != nil {
				return fmt.Errorf("--include-from=%q file is invalid targets.json: %w", includePath, err)
			}
			// TODO: Support delegations...
			if targets.Signed.Delegations != nil {
				return fmt.Errorf("--include-from=%s file is unsupported: hardhat does not yet support delegations", includePath)
			}
			// Copy all of the target file specifications into the builder,
			// including any possible extension fields!
			maps.Copy(builder.TargetsType().Targets, targets.Signed.Targets)
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
			fmt.Printf("wrote %d bytes to %s\n", n, cmd.String("output"))
		} else {
			fmt.Printf("\n")
		}
		return nil
	},
})
