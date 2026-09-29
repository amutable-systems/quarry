// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package generics

// TakeError can be used to wrap a function that returns (T, erorr) to extract
// just the error in one line.
func TakeError[T any](_ T, err error) error {
	return err
}
