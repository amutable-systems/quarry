// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package opts

import (
	"errors"
)

// ErrIncompatibleOptions is returned if an option was specified that conflicts
// with a previously set option.
var ErrIncompatibleOptions = errors.New("incompatible options")

// ErrETagMismatch is returned when [ClobberIfMatches] was used and the stored
// key does not match the provided ETag.
var ErrETagMismatch = errors.New("unexpected object when doing upload: etag mismatch")
