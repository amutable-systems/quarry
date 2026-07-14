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

func TestWithDriver_FillsDriverName(t *testing.T) {
	r, err := keystore.NewGenerateResolver([]keystore.GenerateOption{
		keystore.WithDriver("insecure"),
	})
	require.NoError(t, err)
	assert.Equal(t, "insecure", r.DriverName())
	assert.NoError(t, r.CheckUnconsumed())
}

func TestWithDriver_LastWins(t *testing.T) {
	// Last-wins. Unlike keytypes, a duplicate driver does not re-route
	// other options, so overriding is a useful pattern for
	// programmatically-built option lists.
	r, err := keystore.NewGenerateResolver([]keystore.GenerateOption{
		keystore.WithDriver("insecure"),
		keystore.WithDriver("pkcs11"),
	})
	require.NoError(t, err)
	assert.Equal(t, "pkcs11", r.DriverName())
}

func TestWithDriver_Empty_Rejected(t *testing.T) {
	_, err := keystore.NewGenerateResolver([]keystore.GenerateOption{
		keystore.WithDriver(""),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestWithDriver_UsableAcrossOperations(t *testing.T) {
	// A single WithDriver(name) value should work as a GenerateOption,
	// RotateOption, and ImportOption.
	drv := keystore.WithDriver("insecure")

	rg, err := keystore.NewGenerateResolver([]keystore.GenerateOption{drv})
	require.NoError(t, err)
	assert.Equal(t, "insecure", rg.DriverName())

	rr, err := keystore.NewRotateResolver([]keystore.RotateOption{drv})
	require.NoError(t, err)
	assert.Equal(t, "insecure", rr.DriverName())

	ri, err := keystore.NewImportResolver([]keystore.ImportOption{drv})
	require.NoError(t, err)
	assert.Equal(t, "insecure", ri.DriverName())
}

func TestWithKeyType_FillsKeyTypeName(t *testing.T) {
	r, err := keystore.NewGenerateResolver([]keystore.GenerateOption{
		keystore.WithKeyType(tufmetadata.KeyTypeRSASSA_PSS_SHA256),
	})
	require.NoError(t, err)
	assert.Equal(t, tufmetadata.KeyTypeRSASSA_PSS_SHA256, r.KeyTypeName())
	assert.NoError(t, r.CheckUnconsumed())
}

func TestWithKeyType_Conflicting_Rejected(t *testing.T) {
	// Conflicting keytypes are a hard error rather than last-wins, since
	// a silently-dropped keytype would also re-route any keytype-specific
	// options.
	_, err := keystore.NewGenerateResolver([]keystore.GenerateOption{
		keystore.WithKeyType(tufmetadata.KeyTypeRSASSA_PSS_SHA256),
		keystore.WithKeyType(tufmetadata.KeyTypeECDSA_SHA2_P256),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "conflicting keytypes")
}

func TestWithKeyType_SameValueAllowed(t *testing.T) {
	r, err := keystore.NewGenerateResolver([]keystore.GenerateOption{
		keystore.WithKeyType(tufmetadata.KeyTypeEd25519),
		keystore.WithKeyType(tufmetadata.KeyTypeEd25519),
	})
	require.NoError(t, err)
	assert.Equal(t, tufmetadata.KeyTypeEd25519, r.KeyTypeName())
}

func TestWithKeyType_Empty_Rejected(t *testing.T) {
	_, err := keystore.NewGenerateResolver([]keystore.GenerateOption{
		keystore.WithKeyType(""),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestWithDriverAndWithKeyType_Together(t *testing.T) {
	r, err := keystore.NewGenerateResolver([]keystore.GenerateOption{
		keystore.WithDriver("insecure"),
		keystore.WithKeyType(tufmetadata.KeyTypeRSASSA_PSS_SHA256),
	})
	require.NoError(t, err)
	assert.Equal(t, "insecure", r.DriverName())
	assert.Equal(t, tufmetadata.KeyTypeRSASSA_PSS_SHA256, r.KeyTypeName())
	assert.NoError(t, r.CheckUnconsumed())
}

func TestWithDriver_String(t *testing.T) {
	// CheckUnconsumed prints options with %v.
	assert.Equal(t, `WithDriver("insecure")`, fmt.Sprint(keystore.WithDriver("insecure")))
}

func TestWithKeyType_String(t *testing.T) {
	assert.Equal(t, `WithKeyType("rsa")`, fmt.Sprint(keystore.WithKeyType("rsa")))
}
