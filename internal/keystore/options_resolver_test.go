// Copyright (C) 2026 Amutable GmbH

package keystore_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.amutable.dev/quarry/internal/keystore"
)

// customState is a stand-in for a driver- or keytype-specific state
// struct.
type customState struct {
	marked bool
}

// customOpt is an option defined outside the keystore package (as a
// driver package would do for its driver-specific options).
type customOpt struct {
	errReturn error
}

func (customOpt) IsOption()         {}
func (customOpt) IsGenerateOption() {}
func (customOpt) IsRotateOption()   {}
func (customOpt) IsImportOption()   {}
func (customOpt) IsExportOption()   {}

func (c customOpt) Apply(s *customState) error {
	if c.errReturn != nil {
		return c.errReturn
	}
	s.marked = true
	return nil
}

func (customOpt) String() string { return "customOpt()" }

func TestResolver_NoOpts(t *testing.T) {
	r, err := keystore.NewGenerateResolver(nil)
	require.NoError(t, err)
	assert.NoError(t, r.CheckUnconsumed())
}

func TestResolver_ApplyOptions_CustomState(t *testing.T) {
	r, err := keystore.NewGenerateResolver([]keystore.GenerateOption{customOpt{}})
	require.NoError(t, err)

	var cs customState
	require.NoError(t, keystore.ApplyOptions(r, &cs))
	assert.True(t, cs.marked)
	assert.NoError(t, r.CheckUnconsumed())
}

func TestResolver_ApplyOptions_OptionError(t *testing.T) {
	boom := errors.New("boom")
	r, err := keystore.NewGenerateResolver([]keystore.GenerateOption{customOpt{errReturn: boom}})
	require.NoError(t, err)

	var cs customState
	err = keystore.ApplyOptions(r, &cs)
	assert.ErrorIs(t, err, boom)
}

func TestResolver_CheckUnconsumed_Unmatched(t *testing.T) {
	// customOpt only matches *customState, and no such pass is ever run.
	r, err := keystore.NewGenerateResolver([]keystore.GenerateOption{customOpt{}})
	require.NoError(t, err)

	err = r.CheckUnconsumed()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported option")
	assert.Contains(t, err.Error(), "customOpt()")
}

func TestResolver_ConsumedAcrossMultiplePasses(t *testing.T) {
	// Repeated and non-matching passes must not un-consume an option.
	r, err := keystore.NewGenerateResolver([]keystore.GenerateOption{customOpt{}})
	require.NoError(t, err)

	var cs1, cs2 customState
	require.NoError(t, keystore.ApplyOptions(r, &cs1))
	require.NoError(t, keystore.ApplyOptions(r, &cs2))
	assert.True(t, cs1.marked)
	assert.True(t, cs2.marked)
	assert.NoError(t, r.CheckUnconsumed())
}

// ptrReceiverOpt declares Apply on a pointer receiver. If passed by
// value, Apply is not in the method set and the resolver cannot see it,
// so the option is reported as unsupported (fail-closed). Options should
// declare Apply on value receivers.
type ptrReceiverOpt struct{}

func (ptrReceiverOpt) IsOption()         {}
func (ptrReceiverOpt) IsGenerateOption() {}

func (*ptrReceiverOpt) Apply(s *customState) error {
	s.marked = true
	return nil
}

func TestResolver_PointerReceiverApplyTrap(t *testing.T) {
	t.Run("value", func(t *testing.T) {
		r, err := keystore.NewGenerateResolver([]keystore.GenerateOption{ptrReceiverOpt{}})
		require.NoError(t, err)

		var cs customState
		require.NoError(t, keystore.ApplyOptions(r, &cs))
		assert.False(t, cs.marked, "pointer-receiver Apply must not match a value option")
		assert.Error(t, r.CheckUnconsumed())
	})

	t.Run("pointer", func(t *testing.T) {
		r, err := keystore.NewGenerateResolver([]keystore.GenerateOption{&ptrReceiverOpt{}})
		require.NoError(t, err)

		var cs customState
		require.NoError(t, keystore.ApplyOptions(r, &cs))
		assert.True(t, cs.marked)
		assert.NoError(t, r.CheckUnconsumed())
	})
}

// Smoke tests for the other three resolver constructors.

func TestNewRotateResolver_Smoke(t *testing.T) {
	r, err := keystore.NewRotateResolver([]keystore.RotateOption{customOpt{}})
	require.NoError(t, err)

	var cs customState
	require.NoError(t, keystore.ApplyOptions(r, &cs))
	assert.True(t, cs.marked)
	assert.NoError(t, r.CheckUnconsumed())
}

func TestNewImportResolver_Smoke(t *testing.T) {
	r, err := keystore.NewImportResolver([]keystore.ImportOption{customOpt{}})
	require.NoError(t, err)

	var cs customState
	require.NoError(t, keystore.ApplyOptions(r, &cs))
	assert.True(t, cs.marked)
	assert.NoError(t, r.CheckUnconsumed())
}

func TestNewExportResolver_Smoke(t *testing.T) {
	r, err := keystore.NewExportResolver([]keystore.ExportOption{customOpt{}})
	require.NoError(t, err)

	var cs customState
	require.NoError(t, keystore.ApplyOptions(r, &cs))
	assert.True(t, cs.marked)
	assert.NoError(t, r.CheckUnconsumed())
}
