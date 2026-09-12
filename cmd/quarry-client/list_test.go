// Copyright (C) 2026 Amutable GmbH

package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/urfave/cli/v3"

	"go.amutable.dev/quarry/internal/generics"
	"go.amutable.dev/quarry/internal/tufclient"
	"go.amutable.dev/quarry/internal/tufclient/config"
	"go.amutable.dev/quarry/internal/tufext"
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

// testClient returns a client with no repositories configured. That is enough
// for the formatters -- none of them need repository state to format a target
// file, and an empty client gives the UAPI.16 manifest no expiry.
func testClient(t *testing.T) *tufclient.Client {
	t.Helper()
	// cache_dir is %-expanded by config.Parse, and t.TempDir() embeds the test
	// name -- which for our subtests contains things like "%n".
	cacheDir := strings.ReplaceAll(t.TempDir(), "%", "%%")
	cfg, err := config.Parse(strings.NewReader(
		"config_version = 1\ncache_dir = \"" + cacheDir + "\"\n",
	))
	require.NoError(t, err)
	client, err := tufclient.NewClient(t.Context(), cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	return client
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

// testInlineTarget returns a target file in the [testRepo] repository whose
// contents are embedded in the target metadata as inline data.
func testInlineTarget(t *testing.T, path string, data []byte) *tufclient.TargetInfo {
	t.Helper()
	sum := sha256.Sum256(data)
	target := testTarget(t, path, int64(len(data)), hex.EncodeToString(sum[:]))
	tufext.TargetFilesExt(target.TargetFiles).WithInlineData(data)
	// SetExtensionJSON round-trips the struct through JSON, which drops
	// non-JSON fields like Path -- so it has to be set again afterwards.
	target.Path = path
	return target
}

// outputAll runs the whole formatter lifecycle over the given targets and
// returns everything that was written.
func outputAll(t *testing.T, newFormatter func(io.Writer) listFormatter, targets ...*tufclient.TargetInfo) string {
	t.Helper()
	var buf bytes.Buffer
	formatter := newFormatter(&buf)

	require.NoError(t, formatter.Begin(t.Context(), testClient(t)))
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

// Inline data is mentioned ahead of the URLs, which it takes priority over.
func TestVerboseListFormatterInlineData(t *testing.T) {
	data := []byte("inline FooOS data")
	sum := sha256.Sum256(data)

	got := outputAll(t,
		func(wtr io.Writer) listFormatter { return newVerboseListFormatter(wtr) },
		testInlineTarget(t, "FooOS.raw", data))
	assert.Equal(t, "FooOS.raw:\n"+
		"\tInline data: 17 bytes\n"+
		"\tURL(s):\n"+
		"\t - https://example.com/data/FooOS.raw\n"+
		"\tSize: 17\n"+
		"\tHashes:\n"+
		"\t - sha256:"+hex.EncodeToString(sum[:])+"\n", got)
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

// %u expands to a data: URL for inline targets, as there is (probably) no
// download URL with the target's blob behind it.
func TestFormatListFormatterInlineData(t *testing.T) {
	data := []byte("inline FooOS data")
	got := outputAll(t,
		func(wtr io.Writer) listFormatter { return newFormatListFormatter(wtr, "%u") },
		testInlineTarget(t, "FooOS.raw", data))
	assert.Equal(t, "data:;base64,"+base64.StdEncoding.EncodeToString(data)+"\n", got)
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

	// The manifest is streamed, so the root file object appears up-front and
	// each target is written as it is seen.
	require.NoError(t, formatter.Begin(t.Context(), testClient(t)))
	assert.Equal(t, "\x1e{\"mediaType\":\""+uapi16.MediaType+"\"}\n", buf.String())

	require.NoError(t, formatter.Output(t.Context(), testTarget(t, "FooOS.raw", 14, fooHash)))
	require.NoError(t, formatter.Output(t.Context(), testTarget(t, "sub/dir/BarOS.raw", 15, barHash)))
	require.NoError(t, formatter.Finish(t.Context()))

	assert.Equal(t, []*uapi16.File{
		{MediaType: uapi16.MediaType},
		{
			Name:     "FooOS.raw",
			Size:     generics.Ptr[uint64](14),
			SHA256:   fooHash,
			Contents: []*uapi16.Contents{{URL: "https://example.com/data/FooOS.raw"}},
		},
		{
			Name:     "sub/dir/BarOS.raw",
			Size:     generics.Ptr[uint64](15),
			SHA256:   barHash,
			Contents: []*uapi16.Contents{{URL: "https://example.com/data/sub/dir/BarOS.raw"}},
		},
	}, parseManifest(t, buf.Bytes()))
}

// An inlined empty file gets an explicitly empty literal source ahead of the
// URL. The literal must actually be on the wire -- a source-less {} entry
// would mean "a file next to the manifest" to consumers.
func TestUAPI16ListFormatterEmptyInlineData(t *testing.T) {
	var buf bytes.Buffer
	formatter := newUAPI16ListFormatter(&buf)

	require.NoError(t, formatter.Begin(t.Context(), testClient(t)))
	require.NoError(t, formatter.Output(t.Context(), testInlineTarget(t, "an-empty-file.txt", []byte{})))
	require.NoError(t, formatter.Finish(t.Context()))

	assert.Contains(t, buf.String(), `"contents":[{"literal":""},`)
	files := parseManifest(t, buf.Bytes())
	require.Len(t, files, 2)
	assert.Equal(t, []*uapi16.Contents{
		{Literal: generics.Ptr("")},
		{URL: "https://example.com/data/an-empty-file.txt"},
	}, files[1].Contents)
}

// parseManifest splits a JSON-SEQ manifest into its file objects, verifying
// the record framing as it goes.
func parseManifest(t *testing.T, data []byte) []*uapi16.File {
	t.Helper()
	require.NotEmpty(t, data)
	require.Equal(t, byte(0x1e), data[0], "manifest must start with an RS byte")

	records := strings.Split(string(data[1:]), "\x1e")
	files := make([]*uapi16.File, 0, len(records))
	for _, record := range records {
		require.True(t, strings.HasSuffix(record, "\n"), "record %q must end with a newline", record)
		var file uapi16.File
		require.NoError(t, json.Unmarshal([]byte(record), &file))
		files = append(files, &file)
	}
	return files
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
