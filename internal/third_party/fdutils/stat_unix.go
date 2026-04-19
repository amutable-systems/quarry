//go:build linux

// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2026 Amutable GmbH
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package fdutils

import (
	"os"

	"golang.org/x/sys/unix"
)

// Fstat is an [os.File]-friendly version of [unix.Fstat].
func Fstat(fd *os.File) (*unix.Stat_t, error) {
	return WithFileFd2(fd, func(fd uintptr) (*unix.Stat_t, error) {
		var stat unix.Stat_t
		if err := unix.Fstat(int(fd), &stat); err != nil {
			return nil, os.NewSyscallError("fstat", err)
		}
		return &stat, nil
	})
}
