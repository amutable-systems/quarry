// Copyright (C) 2026 Amutable GmbH

package uapi16_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.amutable.dev/quarry/internal/generics"
	"go.amutable.dev/quarry/internal/uapi16"
)

// Every field of an encoded object, known or extension, is emitted in a single
// canonical (sorted) order.
func TestFileExtensionFields(t *testing.T) {
	encoded, err := json.Marshal(&uapi16.File{
		Name:   "FooOS.raw",
		Size:   generics.Ptr[uint64](14),
		SHA256: "922a9bae0e02b4ffac3e5ed5054230d0689b9c2e25b0178ba82b925f2a0c3e48",
		UnrecognizedFields: map[string]json.RawMessage{
			"xAmutableTufExt": json.RawMessage(`{"custom":{"vendor":"amutable"}}`),
			"xAmutableQuarry": json.RawMessage(`{"channel":"stable"}`),
		},
	})
	require.NoError(t, err)
	//nolint:testifylint // the field order is the point of this test
	assert.Equal(t, `{"name":"FooOS.raw",`+
		`"sha256":"922a9bae0e02b4ffac3e5ed5054230d0689b9c2e25b0178ba82b925f2a0c3e48",`+
		`"size":14,`+
		`"xAmutableQuarry":{"channel":"stable"},`+
		`"xAmutableTufExt":{"custom":{"vendor":"amutable"}}}`, string(encoded))
}

func TestContentsExtensionFields(t *testing.T) {
	encoded, err := json.Marshal(&uapi16.Contents{
		URL:      "https://example.com/data/FooOS.raw",
		Encoding: "zstd",
		UnrecognizedFields: map[string]json.RawMessage{
			"xAmutableQuarry": json.RawMessage(`{"mirror":true}`),
		},
	})
	require.NoError(t, err)
	//nolint:testifylint // the field order is the point of this test
	assert.Equal(t, `{"encoding":"zstd","url":"https://example.com/data/FooOS.raw",`+
		`"xAmutableQuarry":{"mirror":true}}`, string(encoded))
}

// A known field wins even when it is unset and thus not emitted at all --
// otherwise an extension field could masquerade as a field the caller left
// empty, and slip past the checks [uapi16.Writer] makes on the typed fields.
func TestExtensionFieldsUnsetCollision(t *testing.T) {
	var buf bytes.Buffer
	writer := uapi16.NewWriter(&buf)

	// A non-root file object may not have a mediaType.
	require.NoError(t, writer.WriteFile(&uapi16.File{
		Name:               "FooOS.raw",
		UnrecognizedFields: map[string]json.RawMessage{"mediaType": json.RawMessage(`"` + uapi16.MediaType + `"`)},
	}))
	// ... and a root file object may not have a name.
	require.Error(t, writer.WriteRoot(&uapi16.File{
		UnrecognizedFields: map[string]json.RawMessage{"name": json.RawMessage(`"../../etc/shadow"`)},
	}))

	records := parseJSONSeq(t, buf.Bytes())
	require.Len(t, records, 2)
	assert.Equal(t, map[string]any{"mediaType": uapi16.MediaType}, records[0])
	assert.Equal(t, map[string]any{"name": "FooOS.raw"}, records[1])
}

// An invalid extension on a nested Contents fails the whole file object,
// rather than being silently dropped from it.
func TestExtensionFieldsInvalidNested(t *testing.T) {
	_, err := json.Marshal(&uapi16.File{
		Name: "FooOS.raw",
		Contents: []*uapi16.Contents{{
			URL:                "https://example.com/",
			UnrecognizedFields: map[string]json.RawMessage{"xAmutableQuarry": json.RawMessage(`}`)},
		}},
	})
	require.ErrorContains(t, err, "xAmutableQuarry")
}

// Extension fields must not be HTML-escaped by the [uapi16.Writer], for the
// same reason the known URL fields are not.
func TestExtensionFieldsNoEscape(t *testing.T) {
	var buf bytes.Buffer
	writer := uapi16.NewWriter(&buf)
	require.NoError(t, writer.WriteFile(&uapi16.File{
		Name: "FooOS.raw",
		Contents: []*uapi16.Contents{{
			URL:                "https://example.com/data/FooOS.raw?foo=1&bar=2",
			UnrecognizedFields: map[string]json.RawMessage{"xAmutableQuarry": json.RawMessage(`{"mirror":"?a=1&b=2"}`)},
		}},
		UnrecognizedFields: map[string]json.RawMessage{
			"xAmutableTufExt": json.RawMessage(`{"x-quarry-override-url":"https://mirror.example.com/?a=1&b=2"}`),
		},
	}))
	assert.NotContains(t, buf.String(), `\u0026`)
	assert.Contains(t, buf.String(), `"x-quarry-override-url":"https://mirror.example.com/?a=1&b=2"`)
	assert.Contains(t, buf.String(), `"mirror":"?a=1&b=2"`)
}

// Unknown fields are collected on decode, and known fields never leak into
// UnrecognizedFields.
func TestExtensionFieldsUnmarshal(t *testing.T) {
	var file uapi16.File
	require.NoError(t, json.Unmarshal([]byte(`{
		"name": "FooOS.raw",
		"size": 14,
		"contents": [{"url": "https://example.com/data/FooOS.raw", "xAmutableQuarry": {"mirror": true}}],
		"xAmutableQuarry": {"channel": "stable"},
		"xSomeoneElseThing": [1, 2, 3]
	}`), &file))

	assert.Equal(t, "FooOS.raw", file.Name)
	assert.Equal(t, generics.Ptr[uint64](14), file.Size)
	assert.Equal(t, map[string]json.RawMessage{
		"xAmutableQuarry":   json.RawMessage(`{"channel": "stable"}`),
		"xSomeoneElseThing": json.RawMessage(`[1, 2, 3]`),
	}, file.UnrecognizedFields)

	require.Len(t, file.Contents, 1)
	assert.Equal(t, map[string]json.RawMessage{
		"xAmutableQuarry": json.RawMessage(`{"mirror": true}`),
	}, file.Contents[0].UnrecognizedFields)
}

// An object with no extension fields decodes to a nil map rather than an empty
// one, so that it compares equal to a hand-built object.
func TestExtensionFieldsUnmarshalNone(t *testing.T) {
	var file uapi16.File
	require.NoError(t, json.Unmarshal([]byte(`{"name":"FooOS.raw","contents":[{"url":"https://example.com/"}]}`), &file))
	assert.Equal(t, &uapi16.File{
		Name:     "FooOS.raw",
		Contents: []*uapi16.Contents{{URL: "https://example.com/"}},
	}, &file)
}

// Storing extension fields as raw JSON (rather than as "any", like go-tuf
// does) means values survive a round-trip byte-for-byte -- in particular
// integers too large to be represented exactly as a float64.
func TestExtensionFieldsRoundTrip(t *testing.T) {
	const input = `{"name":"FooOS.raw",` +
		`"xAmutableQuarry":{"bigly":12345678901234567890,"precise":1.7976931348623157e+308},` +
		`"xSomeoneElseThing":"é😀"}`

	var file uapi16.File
	require.NoError(t, json.Unmarshal([]byte(input), &file))
	encoded, err := json.Marshal(&file)
	require.NoError(t, err)
	//nolint:testifylint // byte-for-byte equality is the point of this test
	assert.Equal(t, input, string(encoded))
}
