// Copyright (C) 2026 Amutable GmbH

package generics

import (
	"iter"
)

// ErrorIter makes it easier to write ergonomic scan-like iterators where
// errors can be returned at any time, without needing to handle the error case
// explicitly.
func ErrorIter[T any](iterFn func(yield func(T) bool) error) iter.Seq2[T, error] {
	return func(yield func(T, error) bool) {
		err := iterFn(func(val T) bool {
			return yield(val, nil)
		})
		if err != nil {
			_ = yield(*new(T), err)
		}
	}
}

// ReverseIter iterates over a slice in reverse.
func ReverseIter[T any, S ~[]T](s S) iter.Seq[T] {
	return func(yield func(T) bool) {
		for i := len(s) - 1; i >= 0; i-- {
			if !yield(s[i]) {
				return
			}
		}
	}
}
