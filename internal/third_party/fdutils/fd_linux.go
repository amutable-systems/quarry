//go:build linux

// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2019-2025 SUSE LLC
 * Copyright (C) 2026 Aleksa Sarai <cyphar@cyphar.com>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// This code was copied from "cyphar.com/go-pathrs/internal/fdutils".

// Package fdutils contains a few helper methods when dealing with *os.File and
// file descriptors.
package fdutils

import (
	"os"
)

// WithFileFd2 is a more ergonomic wrapper around file.SyscallConn().Control().
func WithFileFd2[T any](file *os.File, fn func(fd uintptr) (T, error)) (T, error) {
	conn, err := file.SyscallConn()
	if err != nil {
		return *new(T), err
	}
	var (
		ret      T
		innerErr error
	)
	if err := conn.Control(func(fd uintptr) {
		ret, innerErr = fn(fd)
	}); err != nil {
		return *new(T), err
	}
	return ret, innerErr
}

// WithFileFd is like [WithFileFd2] except that no other type is returned.
func WithFileFd(file *os.File, fn func(fd uintptr) error) error {
	_, err := WithFileFd2(file, func(fd uintptr) (struct{}, error) {
		return struct{}{}, fn(fd)
	})
	return err
}
