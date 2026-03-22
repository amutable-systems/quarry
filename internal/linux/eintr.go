// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (C) Open Containers Initiative Contributors
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

// This code was copied from "github.com/opencontainers/runc/internal/linux".

package linux

import (
	"errors"

	"golang.org/x/sys/unix"
)

// retryOnEINTR takes a function that returns an error and calls it
// until the error returned is not EINTR.
func retryOnEINTR(fn func() error) error {
	_, err := retryOnEINTR2(func() (struct{}, error) {
		return struct{}{}, fn()
	})
	return err
}

// retryOnEINTR2 is like retryOnEINTR, but it returns 2 values.
func retryOnEINTR2[T any](fn func() (T, error)) (T, error) {
	for {
		val, err := fn()
		if !errors.Is(err, unix.EINTR) {
			return val, err
		}
	}
}
