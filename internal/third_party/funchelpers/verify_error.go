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

	"go.amutable.dev/quarry/internal/third_party/assert"
)

// VerifyError is a helper designed to make verifying deferred functions that
// return errors more ergonomic (most notably Close). This helper is intended
// to be used with named return values.
//
//	func foo() (Err error) {
//		f, err := os.Create("foobar")
//		if err != nil {
//			return err
//		}
//		defer funchelpers.VerifyError(&Err, foo.Close)
//		return nil
//	}
//
// which is equivalent to
//
//	func foo() (Err error) {
//		f, err := os.Create("foobar")
//		if err != nil {
//			return err
//		}
//		defer func() {
//			if err := f.Close(); err != nil {
//				Err = errors.Join(Err, err)
//			}
//		}
//		return nil
//	}
func VerifyError(Err *error, fn func() error) {
	assert.Assert(Err != nil,
		"VerifyError must be called with non-nil Err slot") // programmer error
	if err := fn(); err != nil {
		// If *Err == nil, errors.Join(*Err, err) is still indistinguishable
		// from err itself because it's special-cased in (*joinError).Error().
		*Err = errors.Join(*Err,
			fmt.Errorf("deferred error verification failed: %w", err))
	}
}

// VerifyClose is shorthand for `VerifyError(Err, closer.Close)` but it masks
// [fs.ErrClosed] errors.
func VerifyClose(Err *error, closer io.Closer) {
	VerifyError(Err, func() error {
		err := closer.Close()
		if errors.Is(err, fs.ErrClosed) {
			err = nil
		}
		return err
	})
}
