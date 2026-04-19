// Copyright (C) 2026 Amutable GmbH

package opts_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	storeopts "go.amutable.dev/quarry/internal/tufrepo/opts"
)

func TestPutBlob_WithAttribute(t *testing.T) {
	t.Run("InitialSet", func(t *testing.T) {
		var cfg storeopts.PutBlobConfig
		require.NoError(t, storeopts.WithAttribute("role", "root").ApplyPutBlob(&cfg))
		assert.Equal(t, map[string]string{"role": "root"}, cfg.Attributes)
	})
	t.Run("MultipleKeys", func(t *testing.T) {
		var cfg storeopts.PutBlobConfig
		require.NoError(t, storeopts.WithAttribute("a", "1").ApplyPutBlob(&cfg))
		require.NoError(t, storeopts.WithAttribute("b", "2").ApplyPutBlob(&cfg))
		assert.Equal(t, map[string]string{"a": "1", "b": "2"}, cfg.Attributes)
	})
	t.Run("DuplicateKeyRejected", func(t *testing.T) {
		var cfg storeopts.PutBlobConfig
		require.NoError(t, storeopts.WithAttribute("role", "root").ApplyPutBlob(&cfg))
		err := storeopts.WithAttribute("role", "root").ApplyPutBlob(&cfg)
		assert.ErrorIs(t, err, storeopts.ErrIncompatibleOptions)
	})
	t.Run("DuplicateKeyDifferentValueRejected", func(t *testing.T) {
		var cfg storeopts.PutBlobConfig
		require.NoError(t, storeopts.WithAttribute("role", "root").ApplyPutBlob(&cfg))
		err := storeopts.WithAttribute("role", "snapshot").ApplyPutBlob(&cfg)
		require.ErrorIs(t, err, storeopts.ErrIncompatibleOptions)
		assert.Equal(t, map[string]string{"role": "root"}, cfg.Attributes)
	})
}

func TestClobber_PutBlob(t *testing.T) {
	var cfg storeopts.PutBlobConfig
	require.NoError(t, storeopts.Clobber.ApplyPutBlob(&cfg))
	require.NotNil(t, cfg.ClobberIfMatches)
	assert.Equal(t, storeopts.WildcardETag, *cfg.ClobberIfMatches)
}

func TestNoClobber_PutBlob(t *testing.T) {
	var cfg storeopts.PutBlobConfig
	require.NoError(t, storeopts.NoClobber.ApplyPutBlob(&cfg))
	require.NotNil(t, cfg.ClobberIfMatches)
	assert.Equal(t, storeopts.ETag(""), *cfg.ClobberIfMatches)
}

func TestIfETagMatches_PutBlob(t *testing.T) {
	t.Run("SetsSlot", func(t *testing.T) {
		var cfg storeopts.PutBlobConfig
		require.NoError(t, storeopts.IfETagMatches("abc").ApplyPutBlob(&cfg))
		require.NotNil(t, cfg.ClobberIfMatches)
		assert.Equal(t, storeopts.ETag("abc"), *cfg.ClobberIfMatches)
	})
	t.Run("DuplicateSameValueAllowed", func(t *testing.T) {
		var cfg storeopts.PutBlobConfig
		require.NoError(t, storeopts.IfETagMatches("abc").ApplyPutBlob(&cfg))
		first := cfg.ClobberIfMatches
		require.NoError(t, storeopts.IfETagMatches("abc").ApplyPutBlob(&cfg))
		require.NotNil(t, cfg.ClobberIfMatches)
		assert.Equal(t, storeopts.ETag("abc"), *cfg.ClobberIfMatches)
		// Each apply should store a fresh local copy, not alias the receiver.
		assert.NotSame(t, first, cfg.ClobberIfMatches)
	})
	t.Run("ConflictRejected", func(t *testing.T) {
		var cfg storeopts.PutBlobConfig
		require.NoError(t, storeopts.IfETagMatches("abc").ApplyPutBlob(&cfg))
		err := storeopts.IfETagMatches("xyz").ApplyPutBlob(&cfg)
		require.ErrorIs(t, err, storeopts.ErrIncompatibleOptions)
		require.NotNil(t, cfg.ClobberIfMatches)
		assert.Equal(t, storeopts.ETag("abc"), *cfg.ClobberIfMatches)
	})
	t.Run("WildcardThenEmpty", func(t *testing.T) {
		var cfg storeopts.PutBlobConfig
		require.NoError(t, storeopts.IfETagMatches(storeopts.WildcardETag).ApplyPutBlob(&cfg))
		err := storeopts.IfETagMatches("").ApplyPutBlob(&cfg)
		require.ErrorIs(t, err, storeopts.ErrIncompatibleOptions)
	})
	t.Run("EmptyThenNonEmpty", func(t *testing.T) {
		var cfg storeopts.PutBlobConfig
		require.NoError(t, storeopts.IfETagMatches("").ApplyPutBlob(&cfg))
		require.NotNil(t, cfg.ClobberIfMatches)
		err := storeopts.IfETagMatches("abc").ApplyPutBlob(&cfg)
		require.ErrorIs(t, err, storeopts.ErrIncompatibleOptions)
	})
}
