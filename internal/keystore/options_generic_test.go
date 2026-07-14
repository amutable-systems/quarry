// Copyright (C) 2026 Amutable GmbH

package keystore_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
	// Last-wins -- overriding is a useful pattern for
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

func TestWithDriver_String(t *testing.T) {
	// CheckUnconsumed prints options with %v.
	assert.Equal(t, `WithDriver("insecure")`, fmt.Sprint(keystore.WithDriver("insecure")))
}
