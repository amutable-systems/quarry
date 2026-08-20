// Copyright (C) 2026 Amutable GmbH

package uapi16ext_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/generics"
	"go.amutable.dev/quarry/internal/uapi16"
	"go.amutable.dev/quarry/internal/uapi16ext"
)

const fooHash = "922a9bae0e02b4ffac3e5ed5054230d0689b9c2e25b0178ba82b925f2a0c3e48"

// testTarget returns a minimal target file, parsed from JSON so that go-tuf
// fills in UnrecognizedFields exactly as it would for a real targets.json.
func testTarget(t *testing.T, extra string) *tufmetadata.TargetFiles {
	t.Helper()
	hashBytes, err := hex.DecodeString(fooHash)
	require.NoError(t, err)

	encoded := `{"length":14,"hashes":{"sha256":"` + fooHash + `"}`
	if extra != "" {
		encoded += "," + extra
	}
	encoded += "}"

	var target tufmetadata.TargetFiles
	require.NoError(t, json.Unmarshal([]byte(encoded), &target))
	target.Path = "FooOS.raw"
	require.Equal(t, tufmetadata.Hashes{"sha256": hashBytes}, target.Hashes)
	return &target
}

func testBaseURL(t *testing.T) *url.URL {
	t.Helper()
	baseURL, err := url.Parse("https://example.com/data")
	require.NoError(t, err)
	return baseURL
}

// fromTargetFile converts a target file and returns the extension fields of
// the resulting file object, after checking the parts that never vary.
func fromTargetFile(t *testing.T, target *tufmetadata.TargetFiles, wantURLs ...string) map[string]json.RawMessage {
	t.Helper()
	file, err := uapi16ext.FromTargetFile(target, testBaseURL(t))
	require.NoError(t, err)

	if len(wantURLs) == 0 {
		wantURLs = []string{"https://example.com/data/FooOS.raw"}
	}
	contents := make([]*uapi16.Contents, 0, len(wantURLs))
	for _, wantURL := range wantURLs {
		contents = append(contents, &uapi16.Contents{URL: wantURL})
	}

	extensions := file.UnrecognizedFields
	file.UnrecognizedFields = nil
	assert.Equal(t, &uapi16.File{
		Name:     "FooOS.raw",
		Size:     generics.Ptr[uint64](14),
		SHA256:   fooHash,
		Contents: contents,
	}, file)
	return extensions
}

// A target with no TUF metadata beyond what UAPI.16 can express gets no
// extension fields at all. This also includes "x-quarry-override-url", which
// is mapped to a UAPI.16-native representation.
func TestFromTargetFileNoExtensions(t *testing.T) {
	assert.Nil(t, fromTargetFile(t, testTarget(t, "")))
	assert.Nil(t, fromTargetFile(t,
		testTarget(t, `"x-quarry-override-url": "https://mirror.example.com/data/FooOS.raw"`),
		"https://mirror.example.com/data/FooOS.raw",
		"https://example.com/data/FooOS.raw"))
}

// The worked example: "custom.quarry" is hoisted into xAmutableQuarry, while
// the unrecognised target fields and the rest of "custom" land in
// xAmutableTufExt (aside from "x-quarry-*" fields that are mapped to
// UAPI.16-native concepts).
func TestFromTargetFileExtensions(t *testing.T) {
	target := testTarget(t, `
		"custom": {
			"quarry": {"component": "rootfs", "channel": "stable"},
			"sysupdate": {"version": "42"},
			"someVendorThing": 3
		},
		"x-quarry-override-url": "https://mirror.example.com/data/FooOS.raw?a=1&b=2",
		"x-someone-else": {"url": "https://mirror.example.org/?a=1&b=2"}`)

	extensions := fromTargetFile(t, target,
		// The override URL is preferred over the repository's own URL.
		"https://mirror.example.com/data/FooOS.raw?a=1&b=2",
		"https://example.com/data/FooOS.raw")

	require.Len(t, extensions, 2)
	assert.JSONEq(t, `{"component":"rootfs","channel":"stable"}`, string(extensions["xAmutableQuarry"]))

	// Only the known x-quarry-* fields are dropped from xAmutableTufExt --
	// other vendors' extension fields are kept verbatim.
	var tufExt map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(extensions["xAmutableTufExt"], &tufExt))
	assert.NotContains(t, tufExt, "x-quarry-override-url")
	assert.Contains(t, tufExt, "x-someone-else")

	assert.JSONEq(t, `{
		"x-someone-else": {"url": "https://mirror.example.org/?a=1&b=2"},
		"custom": {"sysupdate": {"version": "42"}, "someVendorThing": 3}
	}`, string(extensions["xAmutableTufExt"]))

	// Extension values are stored unescaped, so that they survive being
	// embedded in the manifest by [uapi16.Writer].
	assert.Contains(t, string(extensions["xAmutableTufExt"]), "?a=1&b=2")
}

// A "custom" object holding nothing but "quarry" leaves xAmutableTufExt with
// no "custom" sub-object -- and in this case, no reason to exist at all.
func TestFromTargetFileOnlyQuarryCustom(t *testing.T) {
	extensions := fromTargetFile(t, testTarget(t, `"custom": {"quarry": {"channel": "stable"}}`))
	require.Len(t, extensions, 1)
	assert.JSONEq(t, `{"channel":"stable"}`, string(extensions["xAmutableQuarry"]))
}

// Conversely, a "custom" object with no "quarry" in it produces no
// xAmutableQuarry field.
func TestFromTargetFileNoQuarryCustom(t *testing.T) {
	extensions := fromTargetFile(t, testTarget(t, `"custom": {"sysupdate": {"version": "42"}}`))
	require.Len(t, extensions, 1)
	assert.JSONEq(t, `{"custom":{"sysupdate":{"version":"42"}}}`, string(extensions["xAmutableTufExt"]))
}

// The "quarry" entry is matched the way [encoding/json] matches a struct
// field, which is case-insensitively -- the same way go-tuf itself matches
// "custom" on the target object one level up.
func TestFromTargetFileQuarryCustomCase(t *testing.T) {
	extensions := fromTargetFile(t, testTarget(t, `"custom": {"Quarry": {"channel": "stable"}}`))
	require.Len(t, extensions, 1)
	assert.JSONEq(t, `{"channel":"stable"}`, string(extensions["xAmutableQuarry"]))
}

// An empty "custom" object carries no information, so it is dropped entirely.
// A "custom" of null is treated the same as an absent one.
func TestFromTargetFileEmptyCustom(t *testing.T) {
	assert.Nil(t, fromTargetFile(t, testTarget(t, `"custom": {}`)))
	assert.Nil(t, fromTargetFile(t, testTarget(t, `"custom": null`)))
}

// The "quarry" entry is copied verbatim, so an explicitly empty one is kept
// rather than being second-guessed.
func TestFromTargetFileEmptyQuarryCustom(t *testing.T) {
	extensions := fromTargetFile(t, testTarget(t, `"custom": {"quarry": {}}`))
	require.Len(t, extensions, 1)
	assert.JSONEq(t, `{}`, string(extensions["xAmutableQuarry"]))
}

// TUF permits "custom" to hold any JSON value. A non-object has no "quarry"
// entry to hoist out of it, so it is stored as-is instead.
func TestFromTargetFileNonObjectCustom(t *testing.T) {
	extensions := fromTargetFile(t, testTarget(t, `"custom": ["a", "b"]`))
	require.Len(t, extensions, 1)
	assert.JSONEq(t, `{"custom":["a","b"]}`, string(extensions["xAmutableTufExt"]))
}

// A non-object "quarry" entry is likewise stored verbatim, and the rest of
// "custom" is unaffected by it.
func TestFromTargetFileNonObjectQuarryCustom(t *testing.T) {
	extensions := fromTargetFile(t, testTarget(t, `"custom": {"quarry": "stable", "sysupdate": {"version": "42"}}`))
	require.Len(t, extensions, 2)
	assert.Equal(t, `"stable"`, string(extensions["xAmutableQuarry"]))
	assert.JSONEq(t, `{"custom":{"sysupdate":{"version":"42"}}}`, string(extensions["xAmutableTufExt"]))
}

// Inline data is emitted as a literal contents entry ahead of the download
// URLs, and (being a known x-quarry-* field) is not duplicated into
// xAmutableTufExt.
func TestFromTargetFileInlineData(t *testing.T) {
	data := []byte("FooOS raw data")
	sum := sha256.Sum256(data)
	literal := base64.StdEncoding.EncodeToString(data)

	target := testTarget(t, `"x-quarry-inline-data": "`+literal+`"`)
	target.Length = int64(len(data))
	target.Hashes = tufmetadata.Hashes{"sha256": sum[:]}

	file, err := uapi16ext.FromTargetFile(target, testBaseURL(t))
	require.NoError(t, err)
	assert.Equal(t, []*uapi16.Contents{
		{Literal: literal},
		{URL: "https://example.com/data/FooOS.raw"},
	}, file.Contents)
	assert.Nil(t, file.UnrecognizedFields, "inline data must not be duplicated into xAmutableTufExt")
}

// The generated file object round-trips through a manifest unchanged.
func TestFromTargetFileRoundTrip(t *testing.T) {
	target := testTarget(t, `
		"custom": {"quarry": {"channel": "stable"}, "sysupdate": {"version": "42"}},
		"x-quarry-override-url": "https://mirror.example.com/data/FooOS.raw"`)

	file, err := uapi16ext.FromTargetFile(target, testBaseURL(t))
	require.NoError(t, err)
	encoded, err := json.Marshal(file)
	require.NoError(t, err)

	var decoded uapi16.File
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	assert.Equal(t, file, &decoded)
}

func TestFromTargetFileErrors(t *testing.T) {
	// Invalid JSON can only ever come from a hand-built TargetFiles, as go-tuf
	// validates "custom" while unmarshalling real TUF metadata.
	t.Run("invalid-custom", func(t *testing.T) {
		target := testTarget(t, "")
		target.Custom = generics.Ptr(json.RawMessage(`{"quarry":`))
		_, err := uapi16ext.FromTargetFile(target, testBaseURL(t))
		require.Error(t, err)
	})

	t.Run("no-sha256", func(t *testing.T) {
		target := testTarget(t, "")
		target.Hashes = tufmetadata.Hashes{"sha512": []byte("whatever")}
		_, err := uapi16ext.FromTargetFile(target, testBaseURL(t))
		require.ErrorContains(t, err, "no sha256 hash")
	})

	t.Run("negative-length", func(t *testing.T) {
		target := testTarget(t, "")
		target.Length = -1
		_, err := uapi16ext.FromTargetFile(target, testBaseURL(t))
		require.ErrorContains(t, err, "negative length")
	})

	t.Run("no-base-urls", func(t *testing.T) {
		_, err := uapi16ext.FromTargetFile(testTarget(t, ""))
		require.ErrorContains(t, err, "no baseURLs")
	})

	// A literal that does not match the target hashes must never be emitted.
	t.Run("inline-data-mismatch", func(t *testing.T) {
		literal := base64.StdEncoding.EncodeToString([]byte("this is not it"))
		target := testTarget(t, `"x-quarry-inline-data": "`+literal+`"`)
		_, err := uapi16ext.FromTargetFile(target, testBaseURL(t))
		require.ErrorContains(t, err, "inline data")
	})
}
