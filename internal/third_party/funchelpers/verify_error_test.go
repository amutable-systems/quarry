// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (C) 2016-2025 SUSE LLC
 * Copyright (C) 2026 Aleksa Sarai <cyphar@cyphar.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// This file was copied from
// "github.com/opencontainers/umoci/internal/funchelpers".

package funchelpers

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyError(t *testing.T) {
	t.Run("NoError", func(t *testing.T) {
		testFn := func() (Err error) {
			defer VerifyError(&Err, func() error { return nil })
			return nil
		}
		assert.NoError(t, testFn(), "no error returned")
	})

	t.Run("SingleError", func(t *testing.T) {
		testErr := errors.New("TestVerifyError example error")
		testFn := func() (Err error) {
			defer VerifyError(&Err, func() error { return testErr })
			return nil
		}
		err := testFn()
		require.Error(t, err, "an error should be returned")
		assert.ErrorIs(t, err, testErr, "basic error should be returned") //nolint:testifylint // assert is fine for error path checks
		assert.EqualError(t, err,
			"deferred error verification failed: TestVerifyError example error",
			"a single deferred error should just be the wrapped error")
	})

	t.Run("Multiple", func(t *testing.T) {
		wantErr := errors.New("wanted error")
		badErr := errors.New("unwanted error")

		testFn := func(finalErr error, errs ...error) (numErrCalled int, Err error) {
			for _, err := range errs {
				defer VerifyError(&Err, func() error {
					numErrCalled++
					return err
				})
			}
			return numErrCalled, finalErr
		}

		t.Run("DeferErr_OnlyLast", func(t *testing.T) {
			numErr, err := testFn(nil, nil, nil, wantErr)
			assert.Equal(t, 3, numErr, "each deferred error function should be called")
			assert.ErrorIs(t, err, wantErr, "last error should be kept")
		})

		t.Run("DeferErr_OnlyFirst", func(t *testing.T) {
			numErr, err := testFn(nil, wantErr, nil, nil)
			assert.Equal(t, 3, numErr, "each deferred error function should be called")
			assert.ErrorIs(t, err, wantErr, "first deferred error should be returned")
		})

		t.Run("MainErr_OnlyMain", func(t *testing.T) {
			numErr, err := testFn(wantErr, nil, nil, nil)
			assert.Equal(t, 3, numErr, "each deferred error function should be called")
			assert.ErrorIs(t, err, wantErr, "main error should be kept")
		})

		t.Run("DeferErr_Multiple", func(t *testing.T) {
			numErr, err := testFn(nil, badErr, badErr, wantErr, nil)
			assert.Equal(t, 4, numErr, "each deferred error function should be called")
			assert.ErrorIs(t, err, wantErr, "first deferred error should be returned")
		})

		t.Run("MainErr_Multiple", func(t *testing.T) {
			numErr, err := testFn(wantErr, badErr, badErr, badErr)
			assert.Equal(t, 3, numErr, "each deferred error function should be called")
			assert.ErrorIs(t, err, wantErr, "main error should be kept")
		})

		t.Run("DeferErr_JoinsAll", func(t *testing.T) {
			err1 := errors.New("first deferred error")
			err2 := errors.New("second deferred error")
			err3 := errors.New("third deferred error")

			numErr, err := testFn(nil, err1, err2, err3)
			require.Error(t, err, "deferred errors should be returned")
			assert.Equal(t, 3, numErr, "each deferred error function should be called")
			for _, wantErr := range []error{err1, err2, err3} {
				assert.ErrorIs(t, err, wantErr, "every deferred error should be joined")
			}
		})

		t.Run("MainErr_DeferErr_JoinsAll", func(t *testing.T) {
			mainErr := errors.New("main error")
			err1 := errors.New("first deferred error")
			err2 := errors.New("second deferred error")

			numErr, err := testFn(mainErr, err1, nil, err2)
			require.Error(t, err, "an error should be returned")
			assert.Equal(t, 3, numErr, "each deferred error function should be called")
			for _, wantErr := range []error{mainErr, err1, err2} {
				assert.ErrorIs(t, err, wantErr, "main and deferred errors should all be joined")
			}
		})

		t.Run("JoinOrdering", func(t *testing.T) {
			mainErr := errors.New("main error")
			err1 := errors.New("first deferred error")
			err2 := errors.New("second deferred error")

			numErr, err := testFn(mainErr, err1, err2)
			require.Error(t, err, "an error should be returned")
			assert.Equal(t, 2, numErr, "each deferred error function should be called")
			assert.EqualError(t, err,
				"main error\n"+
					"deferred error verification failed: second deferred error\n"+
					"deferred error verification failed: first deferred error",
				"main error should come first, then deferred errors in LIFO order")
		})
	})
}

type mockCloser struct {
	closeErr  error
	numClosed int
}

func (c *mockCloser) Close() error {
	c.numClosed++
	return c.closeErr
}

func TestVerifyClose(t *testing.T) {
	testFn := func(mainErr error, closer io.Closer) (Err error) {
		defer VerifyClose(&Err, closer)
		return mainErr
	}

	t.Run("NoError", func(t *testing.T) {
		closer := &mockCloser{}
		err := testFn(nil, closer)
		require.NoError(t, err, "no error returned")
		assert.Equal(t, 1, closer.numClosed, "closer should be closed")
	})

	t.Run("CloseErr", func(t *testing.T) {
		closeErr := errors.New("close error")
		closer := &mockCloser{closeErr: closeErr}
		err := testFn(nil, closer)
		require.Error(t, err, "close error should be returned")
		assert.ErrorIs(t, err, closeErr, "close error should be returned") //nolint:testifylint // assert is fine for error path checks
		assert.EqualError(t, err,
			"deferred error verification failed: close error",
			"a lone close error should just be the wrapped error")
	})

	t.Run("MainErr_CloseErr", func(t *testing.T) {
		mainErr := errors.New("main error")
		closeErr := errors.New("close error")
		closer := &mockCloser{closeErr: closeErr}
		err := testFn(mainErr, closer)
		require.Error(t, err, "an error should be returned")
		assert.ErrorIs(t, err, mainErr, "main error should be kept") //nolint:testifylint // assert is fine for error path checks
		assert.ErrorIs(t, err, closeErr, "close error should be joined")
	})

	t.Run("ErrClosed", func(t *testing.T) {
		closer := &mockCloser{closeErr: fs.ErrClosed}
		err := testFn(nil, closer)
		require.NoError(t, err, "fs.ErrClosed should be masked")
		assert.Equal(t, 1, closer.numClosed, "closer should be closed")
	})

	t.Run("WrappedErrClosed", func(t *testing.T) {
		closer := &mockCloser{closeErr: fmt.Errorf("dummy wrapper: %w", fs.ErrClosed)}
		err := testFn(nil, closer)
		require.NoError(t, err, "wrapped fs.ErrClosed should be masked")
	})

	t.Run("MainErr_ErrClosed", func(t *testing.T) {
		mainErr := errors.New("main error")
		closer := &mockCloser{closeErr: fs.ErrClosed}
		err := testFn(mainErr, closer)
		require.Error(t, err, "main error should be returned")
		assert.NotErrorIs(t, err, fs.ErrClosed, "fs.ErrClosed should be masked") //nolint:testifylint // assert is fine for error path checks
		assert.EqualError(t, err, "main error",
			"main error should be unchanged if close returns fs.ErrClosed")
	})
}
