// Copyright (C) 2026 Amutable GmbH

package keystore_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/keystore"
)

func TestWithRSABits_FillsRSAState(t *testing.T) {
	r, err := keystore.NewGenerateResolver([]keystore.GenerateOption{
		keystore.WithRSABits(4096),
	})
	require.NoError(t, err)

	var rs keystore.RSAState
	require.NoError(t, keystore.ApplyOptions(r, &rs))
	assert.Equal(t, 4096, rs.Bits)
	assert.NoError(t, r.CheckUnconsumed())
}

func TestWithRSABits_ImpliesKeyType(t *testing.T) {
	r, err := keystore.NewGenerateResolver([]keystore.GenerateOption{
		keystore.WithRSABits(3072),
	})
	require.NoError(t, err)
	assert.Equal(t, tufmetadata.KeyTypeRSASSA_PSS_SHA256, r.KeyTypeName())
}

func TestWithRSABits_CompatibleWithExplicitKeyType(t *testing.T) {
	// Explicit WithKeyType + WithRSABits should agree, not conflict.
	r, err := keystore.NewGenerateResolver([]keystore.GenerateOption{
		keystore.WithKeyType(tufmetadata.KeyTypeRSASSA_PSS_SHA256),
		keystore.WithRSABits(4096),
	})
	require.NoError(t, err)
	assert.Equal(t, tufmetadata.KeyTypeRSASSA_PSS_SHA256, r.KeyTypeName())

	var rs keystore.RSAState
	require.NoError(t, keystore.ApplyOptions(r, &rs))
	assert.Equal(t, 4096, rs.Bits)
}

func TestWithRSABits_IncompatibleKeyType_OrderIndependent(t *testing.T) {
	// The conflict must be detected regardless of option order. (The old
	// resolver silently dropped WithRSABits in the bits-first order and
	// generated an ECDSA key.)
	for name, opts := range map[string][]keystore.GenerateOption{
		"KeyTypeFirst": {
			keystore.WithKeyType(tufmetadata.KeyTypeECDSA_SHA2_P256),
			keystore.WithRSABits(4096),
		},
		"BitsFirst": {
			keystore.WithRSABits(4096),
			keystore.WithKeyType(tufmetadata.KeyTypeECDSA_SHA2_P256),
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := keystore.NewGenerateResolver(opts)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "conflicting keytypes")
		})
	}
}

func TestWithRSABits_BelowMinimum(t *testing.T) {
	// This must error at resolver construction, before any driver is
	// selected.
	_, err := keystore.NewGenerateResolver([]keystore.GenerateOption{
		keystore.WithRSABits(1024),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "minimum")
	assert.Contains(t, err.Error(), "2048")
}

func TestWithRSABits_AtMinimum(t *testing.T) {
	r, err := keystore.NewGenerateResolver([]keystore.GenerateOption{
		keystore.WithRSABits(keystore.MinRSABits),
	})
	require.NoError(t, err)

	var rs keystore.RSAState
	require.NoError(t, keystore.ApplyOptions(r, &rs))
	assert.Equal(t, keystore.MinRSABits, rs.Bits)
}

func TestWithRSABits_LastWins(t *testing.T) {
	// Both imply the same keytype, so there is no conflict and the last
	// value wins.
	r, err := keystore.NewGenerateResolver([]keystore.GenerateOption{
		keystore.WithRSABits(2048),
		keystore.WithRSABits(4096),
	})
	require.NoError(t, err)

	var rs keystore.RSAState
	require.NoError(t, keystore.ApplyOptions(r, &rs))
	assert.Equal(t, 4096, rs.Bits)
}

func TestWithRSABits_UsableInRotate(t *testing.T) {
	r, err := keystore.NewRotateResolver([]keystore.RotateOption{
		keystore.WithRSABits(4096),
	})
	require.NoError(t, err)
	assert.Equal(t, tufmetadata.KeyTypeRSASSA_PSS_SHA256, r.KeyTypeName())

	var rs keystore.RSAState
	require.NoError(t, keystore.ApplyOptions(r, &rs))
	assert.Equal(t, 4096, rs.Bits)
}

// WithRSABits must not be usable for import or export -- keytype
// parameters are fixed by the key material there.
func TestWithRSABits_NotImportOrExportOption(t *testing.T) {
	var opt keystore.Option = keystore.WithRSABits(2048)

	_, isImport := opt.(keystore.ImportOption)
	_, isExport := opt.(keystore.ExportOption)
	assert.False(t, isImport, "WithRSABits must not implement ImportOption")
	assert.False(t, isExport, "WithRSABits must not implement ExportOption")

	// Sanity-check the markers WithRSABits *does* claim.
	_, isGen := opt.(keystore.GenerateOption)
	_, isRot := opt.(keystore.RotateOption)
	assert.True(t, isGen, "WithRSABits must implement GenerateOption")
	assert.True(t, isRot, "WithRSABits must implement RotateOption")
}

func TestWithRSABits_String(t *testing.T) {
	assert.Equal(t, "WithRSABits(4096)", fmt.Sprint(keystore.WithRSABits(4096)))
}
