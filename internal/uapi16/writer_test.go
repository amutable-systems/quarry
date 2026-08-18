// Copyright (C) 2026 Amutable GmbH

package uapi16_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.amutable.dev/quarry/internal/generics"
	"go.amutable.dev/quarry/internal/uapi16"
)

// parseJSONSeq splits an RFC7464 JSON-SEQ stream into its records, verifying
// the framing as it goes.
func parseJSONSeq(t *testing.T, data []byte) []map[string]any {
	t.Helper()
	require.NotEmpty(t, data, "json-seq stream must not be empty")
	require.Equal(t, byte(0x1e), data[0], "json-seq stream must start with an RS byte")

	chunks := strings.Split(string(data[1:]), "\x1e")
	records := make([]map[string]any, 0, len(chunks))
	for _, chunk := range chunks {
		require.True(t, strings.HasSuffix(chunk, "\n"), "json-seq record %q must end with a newline", chunk)
		var record map[string]any
		require.NoError(t, json.Unmarshal([]byte(chunk), &record))
		records = append(records, record)
	}
	return records
}

func TestWriter(t *testing.T) {
	var buf bytes.Buffer
	writer := uapi16.NewWriter(&buf)

	require.NoError(t, writer.WriteRoot(&uapi16.File{ValidBeforeUSec: generics.Ptr[uint64](1776856773123234)}))
	require.NoError(t, writer.WriteFile(&uapi16.File{
		Name:   "FooOS.raw",
		Size:   generics.Ptr[uint64](7523532800),
		SHA256: "922a9bae0e02b4ffac3e5ed5054230d0689b9c2e25b0178ba82b925f2a0c3e48",
		Contents: []*uapi16.Contents{
			{URL: "https://example.com/data/FooOS.raw?foo=1&bar=2"},
			{URL: "https://mirror.example.com/data/FooOS.raw"},
		},
	}))
	// An explicit zero size must survive as "size":0 -- to consumers that is a
	// zero-length file, while an omitted size means "the remainder of the source
	// data".
	require.NoError(t, writer.WriteFile(&uapi16.File{Name: "empty", Size: generics.Ptr[uint64](0)}))
	require.NoError(t, writer.WriteFile(&uapi16.File{Name: "sizeless"}))

	// URLs must not be HTML-escaped.
	assert.Contains(t, buf.String(), "?foo=1&bar=2")

	records := parseJSONSeq(t, buf.Bytes())
	require.Len(t, records, 4)

	// The root file object identifies the stream and has no name.
	assert.Equal(t, map[string]any{
		"mediaType":       uapi16.MediaType,
		"validBeforeUSec": float64(1776856773123234),
	}, records[0])

	assert.Equal(t, map[string]any{
		"name":   "FooOS.raw",
		"size":   float64(7523532800),
		"sha256": "922a9bae0e02b4ffac3e5ed5054230d0689b9c2e25b0178ba82b925f2a0c3e48",
		"contents": []any{
			map[string]any{"url": "https://example.com/data/FooOS.raw?foo=1&bar=2"},
			map[string]any{"url": "https://mirror.example.com/data/FooOS.raw"},
		},
	}, records[1])

	assert.Equal(t, map[string]any{"name": "empty", "size": float64(0)}, records[2])

	// Unset fields are omitted entirely, rather than being emitted as nulls or
	// zero values.
	assert.Equal(t, map[string]any{"name": "sizeless"}, records[3])
}

// The root file object does not have to be written explicitly.
func TestWriterImpliedRoot(t *testing.T) {
	var buf bytes.Buffer
	writer := uapi16.NewWriter(&buf)

	require.NoError(t, writer.WriteFile(&uapi16.File{Name: "FooOS.raw"}))
	require.NoError(t, writer.WriteFile(&uapi16.File{Name: "BarOS.raw"}))
	// Writing the root explicitly afterwards is too late.
	require.Error(t, writer.WriteRoot(&uapi16.File{}))

	records := parseJSONSeq(t, buf.Bytes())
	require.Len(t, records, 3)
	assert.Equal(t, map[string]any{"mediaType": uapi16.MediaType}, records[0])
	assert.Equal(t, map[string]any{"name": "FooOS.raw"}, records[1])
	assert.Equal(t, map[string]any{"name": "BarOS.raw"}, records[2])
}

// An explicitly empty contents array means "no sources at all", which is not
// the same as an unset one (which implies a file named [uapi16.File.Name]).
func TestWriterEmptyContents(t *testing.T) {
	var buf bytes.Buffer
	writer := uapi16.NewWriter(&buf)

	require.NoError(t, writer.WriteFile(&uapi16.File{
		Name:     "FooOS.raw",
		Contents: []*uapi16.Contents{},
	}))

	records := parseJSONSeq(t, buf.Bytes())
	require.Len(t, records, 2)
	assert.Equal(t, map[string]any{"name": "FooOS.raw", "contents": []any{}}, records[1])
}

func TestWriterRootMediaType(t *testing.T) {
	var buf bytes.Buffer
	writer := uapi16.NewWriter(&buf)

	// The media type is filled in for us, and the caller's File is untouched.
	root := &uapi16.File{}
	require.NoError(t, writer.WriteRoot(root))
	assert.Empty(t, root.MediaType)

	records := parseJSONSeq(t, buf.Bytes())
	require.Len(t, records, 1)
	assert.Equal(t, uapi16.MediaType, records[0]["mediaType"])
}

func TestWriterErrors(t *testing.T) {
	t.Run("named-root", func(t *testing.T) {
		var buf bytes.Buffer
		writer := uapi16.NewWriter(&buf)
		require.Error(t, writer.WriteRoot(&uapi16.File{Name: "FooOS.raw"}))
		assert.Empty(t, buf.Bytes())
		// The failed root file object doesn't count as having been written.
		require.NoError(t, writer.WriteFile(&uapi16.File{Name: "FooOS.raw"}))
		assert.Len(t, parseJSONSeq(t, buf.Bytes()), 2)
	})

	t.Run("double-root", func(t *testing.T) {
		var buf bytes.Buffer
		writer := uapi16.NewWriter(&buf)
		require.NoError(t, writer.WriteRoot(&uapi16.File{}))
		require.Error(t, writer.WriteRoot(&uapi16.File{}))
		assert.Len(t, parseJSONSeq(t, buf.Bytes()), 1)
	})

	// A rejected file object must not leave a lone (implied) root file object
	// behind, so nothing at all is written in these cases.
	t.Run("invalid-name", func(t *testing.T) {
		var buf bytes.Buffer
		writer := uapi16.NewWriter(&buf)
		require.ErrorIs(t, writer.WriteFile(&uapi16.File{Name: "../FooOS.raw"}), uapi16.ErrInvalidName)
		assert.Empty(t, buf.Bytes())
	})

	t.Run("file-media-type", func(t *testing.T) {
		var buf bytes.Buffer
		writer := uapi16.NewWriter(&buf)
		require.Error(t, writer.WriteFile(&uapi16.File{
			MediaType: uapi16.MediaType,
			Name:      "FooOS.raw",
		}))
		assert.Empty(t, buf.Bytes())
	})
}

// errWriter is an [io.Writer] that always fails.
type errWriter struct{}

var errWrite = errors.New("write failed")

func (errWriter) Write([]byte) (int, error) { return 0, errWrite }

func TestWriterWriteError(t *testing.T) {
	writer := uapi16.NewWriter(errWriter{})
	require.ErrorIs(t, writer.WriteRoot(&uapi16.File{}), errWrite)
	// The root was never successfully written, so writing a file object retries
	// it (and fails again).
	require.ErrorIs(t, writer.WriteFile(&uapi16.File{Name: "FooOS.raw"}), errWrite)
}
