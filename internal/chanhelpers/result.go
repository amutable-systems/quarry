// Copyright (C) 2026 Amutable GmbH

package chanhelpers

// Result is very akin to Rust's Result type. It is primarily useful when you
// need to spawn a failable task as a goroutine and thus need to receive both
// success and error values (Go doesn't have tuples which would make this
// easier), such as with [GoRetryCtx].
type Result[T any] struct {
	Ok  T
	Err error
}

// Unwrap unwraps a [Result] into (val, error).
func (r Result[T]) Unwrap() (T, error) {
	if r.Err != nil {
		return *new(T), r.Err
	}
	return r.Ok, nil
}
