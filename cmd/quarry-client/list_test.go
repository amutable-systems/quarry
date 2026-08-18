// Copyright (C) 2026 Amutable GmbH

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/urfave/cli/v3"

	"go.amutable.dev/quarry/internal/tufclient"
	"go.amutable.dev/quarry/internal/tufclient/config"
	"go.amutable.dev/quarry/internal/uapi16"
)

const (
	fooHash = "315f3097821c3c2f001c50ab5996543598c819a566d18072f41834169ab827b2"
	barHash = "4e7267fd5c54130fe83e69920d63e38117957e56f9172965b8db27c75a3c1a96"
)

// testRepo returns a [config.Repository] for a dummy repository. The config
// has to be parsed because the URL fields are not exported types.
func testRepo(t *testing.T) *config.Repository {
	t.Helper()
	cfg, err := config.Parse(strings.NewReader(`
config_version = 1
cache_dir = "/nonexistent/quarry-client-test"

[repo."test-repo"]
root_trust = "insecure-tofu"
meta_root_url = "https://example.com/meta"
data_root_url = "https://example.com/data"
`))
	require.NoError(t, err)
	repo, ok := cfg.Repos["test-repo"]
	require.True(t, ok, "test-repo should be in the parsed config")
	return repo
}

// testTarget returns a target file in the [testRepo] repository.
func testTarget(t *testing.T, path string, length int64, sha256 string) *tufclient.TargetInfo {
	t.Helper()
	hashBytes, err := hex.DecodeString(sha256)
	require.NoError(t, err)
	return &tufclient.TargetInfo{
		TargetFiles: &tufmetadata.TargetFiles{
			Path:   path,
			Length: length,
			Hashes: tufmetadata.Hashes{"sha256": hashBytes},
		},
		Repo: testRepo(t),
	}
}

// outputAll runs the whole formatter lifecycle over the given targets and
// returns everything that was written.
func outputAll(t *testing.T, newFormatter func(io.Writer) listFormatter, targets ...*tufclient.TargetInfo) string {
	t.Helper()
	var buf bytes.Buffer
	formatter := newFormatter(&buf)

	// No client is needed by any formatter at this point.
	require.NoError(t, formatter.Begin(t.Context(), nil))
	for _, target := range targets {
		require.NoError(t, formatter.Output(t.Context(), target))
	}
	require.NoError(t, formatter.Finish(t.Context()))
	return buf.String()
}

func TestPlainListFormatter(t *testing.T) {
	got := outputAll(t,
		func(wtr io.Writer) listFormatter { return newPlainListFormatter(wtr) },
		testTarget(t, "FooOS.raw", 14, fooHash),
		testTarget(t, "sub/dir/BarOS.raw", 15, barHash))
	assert.Equal(t, "FooOS.raw\nsub/dir/BarOS.raw\n", got)
}

func TestVerboseListFormatter(t *testing.T) {
	got := outputAll(t,
		func(wtr io.Writer) listFormatter { return newVerboseListFormatter(wtr) },
		testTarget(t, "FooOS.raw", 14, fooHash))
	assert.Equal(t, "FooOS.raw:\n"+
		"\tURL(s):\n"+
		"\t - https://example.com/data/FooOS.raw\n"+
		"\tSize: 14\n"+
		"\tHashes:\n"+
		"\t - sha256:"+fooHash+"\n", got)
}

// The "custom" target file metadata is pretty-printed inline, which is the one
// part of the verbose output that does not come from [pprintTargetFile].
func TestVerboseListFormatterCustom(t *testing.T) {
	target := testTarget(t, "FooOS.raw", 14, fooHash)
	custom := json.RawMessage(`{"vendor":"amutable"}`)
	target.Custom = &custom

	got := outputAll(t,
		func(wtr io.Writer) listFormatter { return newVerboseListFormatter(wtr) },
		target)
	assert.Contains(t, got, "\tCustom:\n")
	assert.Contains(t, got, `"vendor": "amutable"`)
}

func TestFormatListFormatter(t *testing.T) {
	for _, test := range []struct {
		format, expected string
	}{
		{"%n", "FooOS.raw\n"},
		{"%R", "test-repo\n"},
		{"%s", "14\n"},
		{"%h", fooHash + "\n"},
		{"%u", "https://example.com/data/FooOS.raw\n"},
		{"%R %n %s", "test-repo FooOS.raw 14\n"},
		{"no expansions here", "no expansions here\n"},
	} {
		t.Run(test.format, func(t *testing.T) {
			got := outputAll(t,
				func(wtr io.Writer) listFormatter { return newFormatListFormatter(wtr, test.format) },
				testTarget(t, "FooOS.raw", 14, fooHash))
			assert.Equal(t, test.expected, got)
		})
	}
}

func TestFormatListFormatterInvalid(t *testing.T) {
	var buf bytes.Buffer
	formatter := newFormatListFormatter(&buf, "%Z")
	require.Error(t, formatter.Output(t.Context(), testTarget(t, "FooOS.raw", 14, fooHash)))
	assert.Empty(t, buf.String())
}

func TestUAPI16ListFormatter(t *testing.T) {
	var buf bytes.Buffer
	formatter := newUAPI16ListFormatter(&buf)

	require.NoError(t, formatter.Begin(t.Context(), nil))
	require.NoError(t, formatter.Output(t.Context(), testTarget(t, "FooOS.raw", 14, fooHash)))
	require.NoError(t, formatter.Output(t.Context(), testTarget(t, "sub/dir/BarOS.raw", 15, barHash)))
	// The manifest can only be written once the whole listing is known.
	assert.Empty(t, buf.String(), "no manifest should be written before Finish")

	require.NoError(t, formatter.Finish(t.Context()))

	var manifest uapi16.Manifest
	require.NoError(t, json.Unmarshal(buf.Bytes(), &manifest))
	assert.Equal(t, uapi16.MediaType, manifest.MediaType)
	assert.Equal(t, []*uapi16.File{
		{
			Name:     "FooOS.raw",
			DataURL:  "https://example.com/data/FooOS.raw",
			DataSize: 14,
			SHA256:   fooHash,
		},
		{
			Name:     "sub/dir/BarOS.raw",
			DataURL:  "https://example.com/data/sub/dir/BarOS.raw",
			DataSize: 15,
			SHA256:   barHash,
		},
	}, manifest.Files)
}

// getListFormatterFor runs a dummy command with the given arguments and
// returns the [listFormatter] that "list" would have picked.
func getListFormatterFor(t *testing.T, wtr io.Writer, args ...string) listFormatter {
	t.Helper()
	var got listFormatter
	cmd := &cli.Command{
		Name: "list",
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "verbose"},
			&cli.StringFlag{Name: "format"},
			&cli.BoolFlag{Name: "uapi-16"},
		},
		Action: func(_ context.Context, cmd *cli.Command) error {
			got = getListFormatter(wtr, cmd)
			return nil
		},
	}
	require.NoError(t, cmd.Run(t.Context(), append([]string{"list"}, args...)))
	return got
}

func TestGetListFormatter(t *testing.T) {
	var buf bytes.Buffer
	assert.IsType(t, &plainListFormatter{}, getListFormatterFor(t, &buf))
	assert.IsType(t, &verboseListFormatter{}, getListFormatterFor(t, &buf, "--verbose"))
	assert.IsType(t, &formatListFormatter{}, getListFormatterFor(t, &buf, "--format=%n"))
	assert.IsType(t, &uapi16ListFormatter{}, getListFormatterFor(t, &buf, "--uapi-16"))
	// An empty --format is still an explicit --format.
	assert.IsType(t, &formatListFormatter{}, getListFormatterFor(t, &buf, "--format="))
}
