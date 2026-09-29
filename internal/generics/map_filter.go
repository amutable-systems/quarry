// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package generics

import (
	"iter"
)

// IsEmptySeq returns whether the sequence yields no values.
func IsEmptySeq[V any](seq iter.Seq[V]) bool {
	empty := true
	seq(func(_ V) bool {
		empty = false
		return false // do not yield any more values
	})
	return empty
}

// MapSeq returns a new sequence with all of the values mapped using the given
// mapping function.
func MapSeq[I, O any](seq iter.Seq[I], mapFn func(I) O) iter.Seq[O] {
	return func(yield func(O) bool) {
		seq(func(i I) bool {
			return yield(mapFn(i))
		})
	}
}

// FoldSeq folds every element in the given sequence into an accumulator, using
// the given initial value for the accumulator.
func FoldSeq[V, B any](seq iter.Seq[V], init B, fn func(B, V) B) B {
	acc := init
	for v := range seq {
		acc = fn(acc, v)
	}
	return acc
}

// FlattenSeq flattens a sequence of sequences into a single sequence made up
// of the concatenation of all inner sequences. For a sequence of slices, use
// [MapSeq] with [slices.Values] to convert:
//
//	FlattenSeq(MapSeq(outerSeq, slices.Values))
//
// For flattening a slice of slices, use [slices.Concat] instead.
func FlattenSeq[V any](seqs iter.Seq[iter.Seq[V]]) iter.Seq[V] {
	return func(yield func(V) bool) {
		for seq := range seqs {
			for v := range seq {
				if !yield(v) {
					return
				}
			}
		}
	}
}

// CollectErrorSeq returns a slice containing the contents of the given
// sequence. If an error occurs during the sequence, iteration is stopped and
// an the error is returned (along with the partially-completed slice).
func CollectErrorSeq[V any](seq iter.Seq2[V, error]) ([]V, error) {
	var vec []V
	for v, err := range seq {
		if err != nil {
			return vec, err
		}
		vec = append(vec, v)
	}
	return vec, nil
}

// SeqContains returns true iff the sequence contains the given value.
func SeqContains[V comparable](seq iter.Seq[V], needle V) bool {
	return SeqAny(seq, func(v V) bool {
		return v == needle
	})
}

// FilterSeq returns a new sequence which only yields values for which the
// predicate returns true.
func FilterSeq[V comparable](seq iter.Seq[V], predicate func(V) bool) iter.Seq[V] {
	return func(yield func(V) bool) {
		seq(func(v V) bool {
			if !predicate(v) {
				return true // skip, keep iterating
			}
			return yield(v)
		})
	}
}

// SeqAny returns true iff predicate returns true for at least one of the
// elements in the sequence.
func SeqAny[V any](seq iter.Seq[V], predicate func(V) bool) bool {
	for v := range seq {
		if predicate(v) {
			return true
		}
	}
	return false
}

// SeqAll returns true iff the predicate returns true for all of the elements
// of the sequence.
func SeqAll[V any](seq iter.Seq[V], predicate func(V) bool) bool {
	// all(seq, fn(v)) === !any(seq, !fn(v))
	return !SeqAny(seq, func(v V) bool {
		return !predicate(v)
	})
}
