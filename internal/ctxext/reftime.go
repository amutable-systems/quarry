// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package ctxext

import (
	"context"
	"time"
)

// DefaultRefTime is the default value returned by [RefTime] if no value was
// explicitly configured.
var DefaultRefTime = time.Now().UTC()

type refTimeCtxKey struct{}

// RefTimeCtxKey is used to store a fixed reference time in [context.Context]
// for later operations to use. This is often set via command-line flags or
// environment variables.
var RefTimeCtxKey refTimeCtxKey

// RefTime returns the reference time stored in the given context (with the key
// [RefTimeCtxKey]. If no reference time is stored, (time.Now(), false) is
// returned. The times are always mapped to UTC.
func RefTime(ctx context.Context) (time.Time, bool) {
	refTime := Value[time.Time](ctx, RefTimeCtxKey)
	ok := !refTime.IsZero()
	if !ok {
		refTime = DefaultRefTime
	}
	return refTime.UTC(), ok
}
