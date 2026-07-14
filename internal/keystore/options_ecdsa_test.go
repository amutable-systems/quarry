// Copyright (C) 2026 Amutable GmbH

package keystore_test

import (
	"crypto/elliptic"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/keystore"
)

func TestWithCurve_P256_FillsKeyType(t *testing.T) {
	r, err := keystore.NewGenerateResolver([]keystore.GenerateOption{
		keystore.WithCurve(elliptic.P256()),
	})
	require.NoError(t, err)
	assert.Equal(t, tufmetadata.KeyTypeECDSA_SHA2_P256, r.KeyTypeName())

	var es keystore.ECDSAState
	require.NoError(t, keystore.ApplyOptions(r, &es))
	assert.Equal(t, elliptic.P256(), es.Curve)
	assert.NoError(t, r.CheckUnconsumed())
}

func TestWithCurve_NotP256(t *testing.T) {
	// This must error at resolver construction, before any state pass
	// runs.
	for _, curve := range []elliptic.Curve{
		elliptic.P224(),
		elliptic.P384(),
		elliptic.P521(),
	} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			_, err := keystore.NewGenerateResolver([]keystore.GenerateOption{
				keystore.WithCurve(curve),
			})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "only NIST P-256")
			assert.Contains(t, err.Error(), curve.Params().Name)
		})
	}
}

func TestWithCurve_Nil(t *testing.T) {
	_, err := keystore.NewGenerateResolver([]keystore.GenerateOption{
		keystore.WithCurve(nil),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestWithCurve_CompatibleWithExplicitKeyType(t *testing.T) {
	r, err := keystore.NewGenerateResolver([]keystore.GenerateOption{
		keystore.WithKeyType(tufmetadata.KeyTypeECDSA_SHA2_P256),
		keystore.WithCurve(elliptic.P256()),
	})
	require.NoError(t, err)
	assert.Equal(t, tufmetadata.KeyTypeECDSA_SHA2_P256, r.KeyTypeName())
}

func TestWithCurve_IncompatibleKeyType_OrderIndependent(t *testing.T) {
	for name, opts := range map[string][]keystore.GenerateOption{
		"KeyTypeFirst": {
			keystore.WithKeyType(tufmetadata.KeyTypeRSASSA_PSS_SHA256),
			keystore.WithCurve(elliptic.P256()),
		},
		"CurveFirst": {
			keystore.WithCurve(elliptic.P256()),
			keystore.WithKeyType(tufmetadata.KeyTypeRSASSA_PSS_SHA256),
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := keystore.NewGenerateResolver(opts)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "conflicting keytypes")
		})
	}
}

func TestWithCurve_ConflictsWithRSABits(t *testing.T) {
	// Implied keytypes conflict even without an explicit WithKeyType.
	_, err := keystore.NewGenerateResolver([]keystore.GenerateOption{
		keystore.WithCurve(elliptic.P256()),
		keystore.WithRSABits(2048),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "conflicting keytypes")
}

func TestWithCurve_UsableInRotate(t *testing.T) {
	r, err := keystore.NewRotateResolver([]keystore.RotateOption{
		keystore.WithCurve(elliptic.P256()),
	})
	require.NoError(t, err)
	assert.Equal(t, tufmetadata.KeyTypeECDSA_SHA2_P256, r.KeyTypeName())
}

// WithCurve must not be usable for import or export.
func TestWithCurve_NotImportOrExportOption(t *testing.T) {
	var opt keystore.Option = keystore.WithCurve(elliptic.P256())

	_, isImport := opt.(keystore.ImportOption)
	_, isExport := opt.(keystore.ExportOption)
	assert.False(t, isImport, "WithCurve must not implement ImportOption")
	assert.False(t, isExport, "WithCurve must not implement ExportOption")

	_, isGen := opt.(keystore.GenerateOption)
	_, isRot := opt.(keystore.RotateOption)
	assert.True(t, isGen, "WithCurve must implement GenerateOption")
	assert.True(t, isRot, "WithCurve must implement RotateOption")
}

func TestWithCurve_String(t *testing.T) {
	assert.Equal(t, "WithCurve(P-256)", fmt.Sprint(keystore.WithCurve(elliptic.P256())))
}

func TestWithCurve_StringNil(t *testing.T) {
	assert.Equal(t, "WithCurve(<nil>)", fmt.Sprint(keystore.WithCurve(nil)))
}
