// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package tufext_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/opencontainers/umoci/pkg/hardening"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/tufext"
)

// inlineTestTarget returns a target file whose length and hashes match the
// given data.
func inlineTestTarget(data []byte) *tufmetadata.TargetFiles {
	sum := sha256.Sum256(data)
	return &tufmetadata.TargetFiles{
		Length: int64(len(data)),
		Hashes: tufmetadata.Hashes{"sha256": sum[:]},
	}
}

// Inline data is stored as a standard-base64 JSON string and comes back out
// verified.
func TestInlineDataRoundTrip(t *testing.T) {
	data := []byte("small inline target data")
	target := inlineTestTarget(data)
	tufext.TargetFilesExt(target).WithInlineData(data)

	encoded, err := json.Marshal(target)
	require.NoError(t, err)
	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(encoded, &fields))
	assert.Equal(t,
		`"`+base64.StdEncoding.EncodeToString(data)+`"`,
		string(fields[tufext.InlineDataField]))

	var decoded tufmetadata.TargetFiles
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	got, err := tufext.TargetFilesExt(&decoded).InlineData()
	require.NoError(t, err)
	assert.Equal(t, data, got)
}

// A non-empty target with no inline data returns nil without error.
func TestInlineDataAbsent(t *testing.T) {
	target := inlineTestTarget([]byte("no inline data here"))
	got, err := tufext.TargetFilesExt(target).InlineData()
	require.NoError(t, err)
	assert.Nil(t, got)
}

// An explicit JSON null carries no data, so (for a non-empty target) it is
// treated the same as an absent field.
func TestInlineDataNull(t *testing.T) {
	target := inlineTestTarget([]byte("no inline data here"))
	target.UnrecognizedFields = map[string]any{tufext.InlineDataField: nil}
	got, err := tufext.TargetFilesExt(target).InlineData()
	require.NoError(t, err)
	assert.Nil(t, got)
}

// Inline data that does not match the target hashes is rejected.
func TestInlineDataCorrupt(t *testing.T) {
	target := inlineTestTarget([]byte("the genuine data"))
	tufext.TargetFilesExt(target).WithInlineData([]byte("the corrupt data")) // same length
	_, err := tufext.TargetFilesExt(target).InlineData()
	require.ErrorIs(t, err, hardening.ErrDigestMismatch)
}

// Inline data with a matching hash but a mismatched length is also rejected.
func TestInlineDataWrongLength(t *testing.T) {
	data := []byte("some inline data")
	target := inlineTestTarget(data)
	target.Length += 10
	tufext.TargetFilesExt(target).WithInlineData(data)
	_, err := tufext.TargetFilesExt(target).InlineData()
	require.ErrorIs(t, err, hardening.ErrSizeMismatch)
}

// A target without any usable hashes cannot vouch for its inline data.
func TestInlineDataNoUsableHashes(t *testing.T) {
	data := []byte("some inline data")
	target := inlineTestTarget(data)
	tufext.TargetFilesExt(target).WithInlineData(data)
	target.Hashes = nil
	_, err := tufext.TargetFilesExt(target).InlineData()
	require.ErrorIs(t, err, tufext.ErrNoSupportedHashTypes)
}

// A value that is not a base64 string is rejected rather than ignored (for a
// non-empty target -- see TestInlineDataZeroLengthIgnoresField).
func TestInlineDataInvalidValue(t *testing.T) {
	target := inlineTestTarget([]byte("some inline data"))
	for _, bad := range []any{42, true, []string{"a"}, "!!! not base64 !!!"} {
		target.UnrecognizedFields = map[string]any{tufext.InlineDataField: bad}
		_, err := tufext.TargetFilesExt(target).InlineData()
		assert.Error(t, err, "inline data %v should be rejected", bad)
	}
}

// A zero-length target needs no inline data at all -- its contents are known
// from the (signed) length alone, so an empty but non-nil slice is returned
// whether the inline data field is absent, null, or an inlined "".
func TestInlineDataZeroLength(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(*tufmetadata.TargetFiles)
	}{
		{"Absent", func(*tufmetadata.TargetFiles) {}},
		{"Null", func(target *tufmetadata.TargetFiles) {
			target.UnrecognizedFields = map[string]any{tufext.InlineDataField: nil}
		}},
		{"Inlined", func(target *tufmetadata.TargetFiles) {
			tufext.TargetFilesExt(target).WithInlineData([]byte{})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			target := inlineTestTarget([]byte{})
			test.setup(target)

			got, err := tufext.TargetFilesExt(target).InlineData()
			require.NoError(t, err)
			assert.NotNil(t, got)
			assert.Empty(t, got)
		})
	}
}

// The zero-length short-cut still has to honour the signed hashes -- a target
// that claims to be empty but whose hashes are of something else must be
// rejected rather than silently satisfied with an empty file.
func TestInlineDataZeroLengthCorrupt(t *testing.T) {
	target := inlineTestTarget([]byte("not actually empty"))
	target.Length = 0
	_, err := tufext.TargetFilesExt(target).InlineData()
	require.ErrorIs(t, err, hardening.ErrDigestMismatch)
}

// Likewise, a zero-length target without any usable hashes is trusted no more
// than a non-empty one would be.
func TestInlineDataZeroLengthNoUsableHashes(t *testing.T) {
	target := inlineTestTarget([]byte{})
	target.Hashes = nil
	_, err := tufext.TargetFilesExt(target).InlineData()
	require.ErrorIs(t, err, tufext.ErrNoSupportedHashTypes)
}

// For zero-length targets the signed length and hashes are authoritative and
// the inline data field is never consulted, so whatever it holds -- garbage,
// or data that would otherwise fail the length check -- cannot cause an error.
// This pins that behaviour so that any change to it is deliberate.
func TestInlineDataZeroLengthIgnoresField(t *testing.T) {
	for _, value := range []any{
		42,
		true,
		[]string{"a"},
		"!!! not base64 !!!",
		base64.StdEncoding.EncodeToString([]byte("data that is not empty")),
	} {
		target := inlineTestTarget([]byte{})
		target.UnrecognizedFields = map[string]any{tufext.InlineDataField: value}

		got, err := tufext.TargetFilesExt(target).InlineData()
		require.NoErrorf(t, err, "inline data %v", value)
		assert.NotNilf(t, got, "inline data %v", value)
		assert.Emptyf(t, got, "inline data %v", value)
	}
}
