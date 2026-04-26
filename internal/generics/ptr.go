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
