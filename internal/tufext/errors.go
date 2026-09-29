// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package tufext

import (
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"
)

// Re-exported versions of go-tuf's errors, but in a format that can
// ergonomically be used with [errors.Is].
var (
	ErrBadVersionNumber       error = &tufmetadata.ErrBadVersionNumber{}
	ErrDownload               error = &tufmetadata.ErrDownload{}
	ErrDownloadHTTP           error = &tufmetadata.ErrDownloadHTTP{}
	ErrDownloadLengthMismatch error = &tufmetadata.ErrDownloadLengthMismatch{}
	ErrEqualVersionNumber     error = &tufmetadata.ErrEqualVersionNumber{}
	ErrExpiredMetadata        error = &tufmetadata.ErrExpiredMetadata{}
	ErrLengthOrHashMismatch   error = &tufmetadata.ErrLengthOrHashMismatch{}
	ErrRepository             error = &tufmetadata.ErrRepository{}
	ErrRuntime                error = &tufmetadata.ErrRuntime{}
	ErrType                   error = &tufmetadata.ErrType{}
	ErrUnsignedMetadata       error = &tufmetadata.ErrUnsignedMetadata{}
	ErrValue                  error = &tufmetadata.ErrValue{}
)
