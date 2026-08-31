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

// SeqLeft takes an [iter.Seq2] and returns an [iter.Seq] containing only the
// "left" values (the first generic type).
func SeqLeft[T1, T2 any](seq iter.Seq2[T1, T2]) iter.Seq[T1] {
	return func(yield func(T1) bool) {
		seq(func(v T1, _ T2) bool {
			return yield(v)
		})
	}
}

// SeqRight takes an [iter.Seq2] and returns an [iter.Seq] containing only the
// "right" values (the second generic type).
func SeqRight[T1, T2 any](seq iter.Seq2[T1, T2]) iter.Seq[T2] {
	return func(yield func(T2) bool) {
		seq(func(_ T1, v T2) bool {
			return yield(v)
		})
	}
}

// Set is an alias for map[T]struct{} (an idiomatic Go map).
type Set[T comparable] = map[T]struct{}

// SeqSet takes an [iter.Seq] and returns a [Set] containing the sequence
// values.
func SeqSet[T comparable](seq iter.Seq[T]) Set[T] {
	m := make(Set[T], 64)
	for k := range seq {
		m[k] = struct{}{}
	}
	return m
}
