// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package pathrsext

import (
	"os"

	"cyphar.com/go-pathrs"
)

// Stat is shorthand for [pathrs.Root.Resolve] followed by [os.File.Stat].
func Stat(root *pathrs.Root, subpath string) (os.FileInfo, error) {
	handle, err := root.Resolve(subpath)
	if err != nil {
		return nil, err
	}
	return handle.IntoFile().Stat()
}
