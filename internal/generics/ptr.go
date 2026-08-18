// Copyright (C) 2026 Amutable GmbH

package generics

// PtrToAny casts a *T to any, but propagates a nil pointer to a nil interface.
// (Unlike Go's native casting.)
func PtrToAny[T any](v *T) any {
	if v == nil {
		return nil
	}
	return v
}

// Ptr returns a pointer to a copy of the given value. This is primarily useful
// for filling in optional JSON fields, where a nil pointer and a pointer to the
// zero value have to be distinguishable.
func Ptr[T any](v T) *T {
	return &v
}
