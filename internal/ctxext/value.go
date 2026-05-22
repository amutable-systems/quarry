// Copyright (C) 2026 Amutable GmbH

package ctxext

import "context"

// Value is a typed version of [context.Context.Value]. This function panics if
// the type of the value does not match the generic type. If the value is
// unset, the zero value of T is returned.
func Value[T any](ctx context.Context, key any) T {
	v := ctx.Value(key)
	if v == nil {
		return *new(T)
	}
	return v.(T) //nolint:forcetypeassert // caller guarantees this is true
}
