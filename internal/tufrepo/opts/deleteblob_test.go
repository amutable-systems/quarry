// Copyright (C) 2026 Amutable GmbH

package opts_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	storeopts "go.amutable.dev/quarry/internal/tufrepo/opts"
)

func TestIfETagMatches_DeleteBlob(t *testing.T) {
	t.Run("SetsSlot", func(t *testing.T) {
		var cfg storeopts.DeleteBlobConfig
		require.NoError(t, storeopts.IfETagMatches("abc").ApplyDeleteBlob(&cfg))
		require.NotNil(t, cfg.IfMatches)
		assert.Equal(t, storeopts.ETag("abc"), *cfg.IfMatches)
	})
	t.Run("DuplicateSameValueAllowed", func(t *testing.T) {
		var cfg storeopts.DeleteBlobConfig
		require.NoError(t, storeopts.IfETagMatches("abc").ApplyDeleteBlob(&cfg))
		require.NoError(t, storeopts.IfETagMatches("abc").ApplyDeleteBlob(&cfg))
		require.NotNil(t, cfg.IfMatches)
		assert.Equal(t, storeopts.ETag("abc"), *cfg.IfMatches)
	})
	t.Run("ConflictRejected", func(t *testing.T) {
		var cfg storeopts.DeleteBlobConfig
		require.NoError(t, storeopts.IfETagMatches("abc").ApplyDeleteBlob(&cfg))
		err := storeopts.IfETagMatches("xyz").ApplyDeleteBlob(&cfg)
		require.ErrorIs(t, err, storeopts.ErrIncompatibleOptions)
		require.NotNil(t, cfg.IfMatches)
		assert.Equal(t, storeopts.ETag("abc"), *cfg.IfMatches)
	})
	t.Run("WildcardThenEmpty", func(t *testing.T) {
		var cfg storeopts.DeleteBlobConfig
		require.NoError(t, storeopts.IfETagMatches(storeopts.WildcardETag).ApplyDeleteBlob(&cfg))
		err := storeopts.IfETagMatches("").ApplyDeleteBlob(&cfg)
		require.ErrorIs(t, err, storeopts.ErrIncompatibleOptions)
	})
	t.Run("EmptyThenNonEmpty", func(t *testing.T) {
		var cfg storeopts.DeleteBlobConfig
		require.NoError(t, storeopts.IfETagMatches("").ApplyDeleteBlob(&cfg))
		require.NotNil(t, cfg.IfMatches)
		err := storeopts.IfETagMatches("abc").ApplyDeleteBlob(&cfg)
		require.ErrorIs(t, err, storeopts.ErrIncompatibleOptions)
	})
}
