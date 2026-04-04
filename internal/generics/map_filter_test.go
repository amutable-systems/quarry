// Copyright (C) 2026 Amutable GmbH

package generics_test

import (
	"errors"
	"iter"
	"slices"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.amutable.dev/quarry/internal/generics"
)

func intSeq(vals ...int) iter.Seq[int] {
	return func(yield func(int) bool) {
		for _, v := range vals {
			if !yield(v) {
				return
			}
		}
	}
}

type intOrError struct {
	v   int
	err error
}

func intErrorSeq2(pairs ...intOrError) iter.Seq2[int, error] {
	return func(yield func(int, error) bool) {
		for _, p := range pairs {
			if !yield(p.v, p.err) {
				return
			}
		}
	}
}

// countingSeq2 wraps a Seq2 and counts how many pairs were yielded.
func countingSeq2(seq iter.Seq2[int, error], yielded *int) iter.Seq2[int, error] {
	return func(yield func(int, error) bool) {
		seq(func(v int, err error) bool {
			*yielded++
			return yield(v, err)
		})
	}
}

// countingSeq wraps a sequence and counts how many elements were yielded.
func countingSeq(seq iter.Seq[int], yielded *int) iter.Seq[int] {
	return func(yield func(int) bool) {
		seq(func(v int) bool {
			*yielded++
			return yield(v)
		})
	}
}

func TestIsEmptySeq(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input iter.Seq[int]
		want  bool
	}{
		{"Empty", intSeq(), true},
		{"Single", intSeq(1), false},
		{"Multiple", intSeq(1, 2, 3), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, generics.IsEmptySeq(tc.input))
		})
	}
}

func TestIsEmptySeq_Reiterate(t *testing.T) {
	seq := intSeq(1, 2, 3)
	assert.False(t, generics.IsEmptySeq(seq))
	assert.False(t, generics.IsEmptySeq(seq))

	empty := intSeq()
	assert.True(t, generics.IsEmptySeq(empty))
	assert.True(t, generics.IsEmptySeq(empty))
}

func TestIsEmptySeq_EarlyTermination(t *testing.T) {
	var yielded int
	src := countingSeq(intSeq(1, 2, 3, 4, 5), &yielded)

	assert.False(t, generics.IsEmptySeq(src))
	assert.Equal(t, 1, yielded, "source should stop after first element")
}

func TestMapSeq(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input iter.Seq[int]
		mapFn func(int) string
		want  []string
	}{
		{
			"Basic",
			intSeq(1, 2, 3),
			strconv.Itoa,
			[]string{"1", "2", "3"},
		},
		{
			"Empty",
			intSeq(),
			strconv.Itoa,
			nil,
		},
		{
			"Single",
			intSeq(42),
			strconv.Itoa,
			[]string{"42"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mapped := generics.MapSeq(tc.input, tc.mapFn)

			// Iterate twice to verify reusability.
			assert.Equal(t, tc.want, slices.Collect(mapped))
			assert.Equal(t, tc.want, slices.Collect(mapped))
		})
	}
}

func TestFoldSeq(t *testing.T) {
	sum := func(a, b int) int { return a + b }

	for _, tc := range []struct {
		name  string
		input iter.Seq[int]
		init  int
		want  int
	}{
		{"Multiple", intSeq(1, 2, 3, 4), 0, 10},
		{"Single", intSeq(5), 0, 5},
		{"Empty", intSeq(), 0, 0},
		{"NonZeroInit", intSeq(1, 2, 3), 100, 106},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, generics.FoldSeq(tc.input, tc.init, sum))
		})
	}
}

func TestFoldSeq_Reiterate(t *testing.T) {
	sum := func(a, b int) int { return a + b }
	seq := intSeq(1, 2, 3)

	assert.Equal(t, 6, generics.FoldSeq(seq, 0, sum))
	assert.Equal(t, 6, generics.FoldSeq(seq, 0, sum))
}

func TestChained_Filter_FoldSeq(t *testing.T) {
	isEven := func(v int) bool { return v%2 == 0 }
	sum := func(a, b int) int { return a + b }

	filtered := generics.FilterSeq(intSeq(1, 2, 3, 4, 5, 6), isEven)

	assert.Equal(t, 12, generics.FoldSeq(filtered, 0, sum))
	assert.Equal(t, 12, generics.FoldSeq(filtered, 0, sum))
}

func seqOfSeqs(seqs ...iter.Seq[int]) iter.Seq[iter.Seq[int]] {
	return func(yield func(iter.Seq[int]) bool) {
		for _, s := range seqs {
			if !yield(s) {
				return
			}
		}
	}
}

func TestFlattenSeq(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input iter.Seq[iter.Seq[int]]
		want  []int
	}{
		{
			"Multiple",
			seqOfSeqs(intSeq(1, 2), intSeq(3, 4), intSeq(5)),
			[]int{1, 2, 3, 4, 5},
		},
		{
			"Single",
			seqOfSeqs(intSeq(1, 2, 3)),
			[]int{1, 2, 3},
		},
		{
			"Empty",
			seqOfSeqs(),
			nil,
		},
		{
			"EmptyInner",
			seqOfSeqs(intSeq(1, 2), intSeq(), intSeq(3)),
			[]int{1, 2, 3},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flattened := generics.FlattenSeq(tc.input)

			// Iterate twice to verify reusability.
			assert.Equal(t, tc.want, slices.Collect(flattened))
			assert.Equal(t, tc.want, slices.Collect(flattened))
		})
	}
}

func TestFlattenSeq_Reiterate(t *testing.T) {
	seqs := seqOfSeqs(intSeq(1, 2), intSeq(3, 4))
	flattened := generics.FlattenSeq(seqs)
	assert.Equal(t, []int{1, 2, 3, 4}, slices.Collect(flattened))
	assert.Equal(t, []int{1, 2, 3, 4}, slices.Collect(flattened))
}

func TestFlattenSeq_EarlyTermination(t *testing.T) {
	var outerYielded int
	src := func(yield func(iter.Seq[int]) bool) {
		for _, seq := range []iter.Seq[int]{intSeq(1, 2), intSeq(3, 4), intSeq(5, 6)} {
			outerYielded++
			if !yield(seq) {
				return
			}
		}
	}

	// Take only the first element from the flattened sequence.
	for range generics.FlattenSeq(src) {
		break
	}
	assert.Equal(t, 1, outerYielded, "outer source should stop after consumer breaks")
}

func TestChained_MapSeq_FlattenSeq(t *testing.T) {
	// Map each int to a slice, convert with slices.Values, then flatten.
	expand := func(v int) iter.Seq[int] { return intSeq(v, v*10) }
	flattened := generics.FlattenSeq(generics.MapSeq(intSeq(1, 2, 3), expand))

	assert.Equal(t, []int{1, 10, 2, 20, 3, 30}, slices.Collect(flattened))
	assert.Equal(t, []int{1, 10, 2, 20, 3, 30}, slices.Collect(flattened))
}

func TestChained_FlattenSeq_SlicesValues(t *testing.T) {
	// Demonstrate the recommended pattern for flattening a seq of slices:
	//   FlattenSeq(MapSeq(outerSeq, slices.Values))
	sliceSeq := func(yield func([]int) bool) {
		for _, s := range [][]int{{1, 2}, {3, 4}, {5}} {
			if !yield(s) {
				return
			}
		}
	}

	flattened := generics.FlattenSeq(generics.MapSeq(sliceSeq, slices.Values))

	assert.Equal(t, []int{1, 2, 3, 4, 5}, slices.Collect(flattened))
	assert.Equal(t, []int{1, 2, 3, 4, 5}, slices.Collect(flattened))
}

var errSentinel = errors.New("test error")

func TestCollectErrorSeq(t *testing.T) {
	for _, tc := range []struct {
		name    string
		input   iter.Seq2[int, error]
		want    []int
		wantErr error
	}{
		{
			"AllSuccess",
			intErrorSeq2(
				intOrError{v: 1},
				intOrError{v: 2},
				intOrError{v: 3},
			),
			[]int{1, 2, 3},
			nil,
		},
		{
			"Single",
			intErrorSeq2(intOrError{v: 42}),
			[]int{42},
			nil,
		},
		{
			"Empty",
			intErrorSeq2(),
			nil,
			nil,
		},
		{
			"ErrorFirst",
			intErrorSeq2(
				intOrError{err: errSentinel},
				intOrError{v: 2},
			),
			nil,
			errSentinel,
		},
		{
			"ErrorMiddle",
			intErrorSeq2(
				intOrError{v: 1},
				intOrError{v: 2},
				intOrError{err: errSentinel},
				intOrError{v: 4},
			),
			[]int{1, 2},
			errSentinel,
		},
		{
			"ErrorLast",
			intErrorSeq2(
				intOrError{v: 1},
				intOrError{v: 2},
				intOrError{err: errSentinel},
			),
			[]int{1, 2},
			errSentinel,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := generics.CollectErrorSeq(tc.input)
			assert.Equal(t, tc.want, got)
			assert.ErrorIs(t, err, tc.wantErr)
		})
	}
}

func TestCollectErrorSeq_Reiterate(t *testing.T) {
	seq := intErrorSeq2(
		intOrError{v: 1},
		intOrError{v: 2},
		intOrError{err: errSentinel},
		intOrError{v: 4},
	)

	got, err := generics.CollectErrorSeq(seq)
	require.ErrorIs(t, err, errSentinel)
	assert.Equal(t, []int{1, 2}, got)

	got, err = generics.CollectErrorSeq(seq)
	require.ErrorIs(t, err, errSentinel)
	assert.Equal(t, []int{1, 2}, got)
}

func TestCollectErrorSeq_EarlyTermination(t *testing.T) {
	var yielded int
	src := countingSeq2(intErrorSeq2(
		intOrError{v: 1},
		intOrError{v: 2},
		intOrError{err: errSentinel},
		intOrError{v: 4},
		intOrError{v: 5},
	), &yielded)

	got, err := generics.CollectErrorSeq(src)
	require.ErrorIs(t, err, errSentinel)
	assert.Equal(t, []int{1, 2}, got)
	assert.Equal(t, 3, yielded, "source should stop after the error element")
}

func TestChained_FilterMap_CollectErrorSeq(t *testing.T) {
	// Build a Seq2 by mapping a filtered Seq with a function that can fail.
	isEven := func(v int) bool { return v%2 == 0 }
	toSeq2 := func(seq iter.Seq[int]) iter.Seq2[int, error] {
		return func(yield func(int, error) bool) {
			for v := range seq {
				if !yield(v, nil) {
					return
				}
			}
		}
	}

	chained := toSeq2(generics.FilterSeq(intSeq(1, 2, 3, 4, 5, 6), isEven))

	got, err := generics.CollectErrorSeq(chained)
	require.NoError(t, err)
	assert.Equal(t, []int{2, 4, 6}, got)

	// Reiterate.
	got, err = generics.CollectErrorSeq(chained)
	require.NoError(t, err)
	assert.Equal(t, []int{2, 4, 6}, got)
}

func TestSeqContains_Reiterate(t *testing.T) {
	seq := intSeq(1, 2, 3)
	assert.True(t, generics.SeqContains(seq, 2))
	assert.True(t, generics.SeqContains(seq, 2))

	assert.False(t, generics.SeqContains(seq, 99))
	assert.False(t, generics.SeqContains(seq, 99))
}

func TestSeqContains(t *testing.T) {
	for _, tc := range []struct {
		name   string
		input  iter.Seq[int]
		needle int
		want   bool
	}{
		{"Present", intSeq(1, 2, 3), 2, true},
		{"Absent", intSeq(1, 2, 3), 4, false},
		{"First", intSeq(1, 2, 3), 1, true},
		{"Last", intSeq(1, 2, 3), 3, true},
		{"Empty", intSeq(), 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, generics.SeqContains(tc.input, tc.needle))
		})
	}
}

func TestFilterSeq(t *testing.T) {
	isEven := func(v int) bool { return v%2 == 0 }

	for _, tc := range []struct {
		name      string
		input     iter.Seq[int]
		predicate func(int) bool
		want      []int
	}{
		{
			"SomeMatch",
			intSeq(1, 2, 3, 4, 5, 6),
			isEven,
			[]int{2, 4, 6},
		},
		{
			"NoneMatch",
			intSeq(1, 3, 5),
			isEven,
			nil,
		},
		{
			"AllMatch",
			intSeq(2, 4, 6),
			isEven,
			[]int{2, 4, 6},
		},
		{
			"Empty",
			intSeq(),
			isEven,
			nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			filtered := generics.FilterSeq(tc.input, tc.predicate)

			// Iterate twice to verify reusability.
			assert.Equal(t, tc.want, slices.Collect(filtered))
			assert.Equal(t, tc.want, slices.Collect(filtered))
		})
	}
}

func TestMapSeq_EarlyTermination(t *testing.T) {
	var yielded int
	src := countingSeq(intSeq(1, 2, 3, 4, 5), &yielded)
	mapped := generics.MapSeq(src, strconv.Itoa)

	for range mapped {
		break
	}
	assert.Equal(t, 1, yielded, "source should stop after consumer breaks")
}

func TestFilterSeq_EarlyTermination(t *testing.T) {
	var yielded int
	src := countingSeq(intSeq(1, 2, 3, 4, 5), &yielded)
	// Filter that matches everything, so the first yield to the consumer
	// triggers the break.
	filtered := generics.FilterSeq(src, func(int) bool { return true })

	for range filtered {
		break
	}
	assert.Equal(t, 1, yielded, "source should stop after consumer breaks")
}

func TestSeqAny_Reiterate(t *testing.T) {
	isEven := func(v int) bool { return v%2 == 0 }
	seq := intSeq(1, 2, 3)
	assert.True(t, generics.SeqAny(seq, isEven))
	assert.True(t, generics.SeqAny(seq, isEven))

	odds := intSeq(1, 3, 5)
	assert.False(t, generics.SeqAny(odds, isEven))
	assert.False(t, generics.SeqAny(odds, isEven))
}

func TestSeqAll_Reiterate(t *testing.T) {
	isEven := func(v int) bool { return v%2 == 0 }
	evens := intSeq(2, 4, 6)
	assert.True(t, generics.SeqAll(evens, isEven))
	assert.True(t, generics.SeqAll(evens, isEven))

	mixed := intSeq(1, 2, 3)
	assert.False(t, generics.SeqAll(mixed, isEven))
	assert.False(t, generics.SeqAll(mixed, isEven))
}

func TestSeqAny(t *testing.T) {
	isEven := func(v int) bool { return v%2 == 0 }

	for _, tc := range []struct {
		name      string
		input     iter.Seq[int]
		predicate func(int) bool
		want      bool
	}{
		{"SomeMatch", intSeq(1, 2, 3), isEven, true},
		{"AllMatch", intSeq(2, 4, 6), isEven, true},
		{"NoneMatch", intSeq(1, 3, 5), isEven, false},
		{"Single_Match", intSeq(2), isEven, true},
		{"Single_NoMatch", intSeq(1), isEven, false},
		{"Empty", intSeq(), isEven, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, generics.SeqAny(tc.input, tc.predicate))
		})
	}
}

func TestSeqAll(t *testing.T) {
	isEven := func(v int) bool { return v%2 == 0 }

	for _, tc := range []struct {
		name      string
		input     iter.Seq[int]
		predicate func(int) bool
		want      bool
	}{
		{"AllMatch", intSeq(2, 4, 6), isEven, true},
		{"SomeMatch", intSeq(1, 2, 3), isEven, false},
		{"NoneMatch", intSeq(1, 3, 5), isEven, false},
		{"Single_Match", intSeq(2), isEven, true},
		{"Single_NoMatch", intSeq(1), isEven, false},
		{"Empty", intSeq(), isEven, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, generics.SeqAll(tc.input, tc.predicate))
		})
	}
}

func TestSeqAny_EarlyTermination(t *testing.T) {
	var yielded int
	src := countingSeq(intSeq(1, 2, 3, 4, 5), &yielded)

	assert.True(t, generics.SeqAny(src, func(v int) bool { return v == 2 }))
	assert.Equal(t, 2, yielded, "source should stop after first match")
}

func TestSeqAll_EarlyTermination(t *testing.T) {
	var yielded int
	src := countingSeq(intSeq(1, 2, 3, 4, 5), &yielded)

	assert.False(t, generics.SeqAll(src, func(v int) bool { return v%2 == 0 }))
	assert.Equal(t, 1, yielded, "source should stop after first non-match")
}

func TestSeqContains_EarlyTermination(t *testing.T) {
	var yielded int
	src := countingSeq(intSeq(1, 2, 3, 4, 5), &yielded)

	assert.True(t, generics.SeqContains(src, 2))
	assert.Equal(t, 2, yielded, "source should stop after needle is found")
}

func TestChained_FilterMap_Collect(t *testing.T) {
	isEven := func(v int) bool { return v%2 == 0 }
	double := func(v int) int { return v * 2 }

	chained := generics.MapSeq(generics.FilterSeq(intSeq(1, 2, 3, 4, 5, 6), isEven), double)

	assert.Equal(t, []int{4, 8, 12}, slices.Collect(chained))
	assert.Equal(t, []int{4, 8, 12}, slices.Collect(chained))
}

func TestChained_MapFilter_Collect(t *testing.T) {
	double := func(v int) int { return v * 2 }
	greaterThan5 := func(v int) bool { return v > 5 }

	chained := generics.FilterSeq(generics.MapSeq(intSeq(1, 2, 3, 4, 5), double), greaterThan5)

	assert.Equal(t, []int{6, 8, 10}, slices.Collect(chained))
	assert.Equal(t, []int{6, 8, 10}, slices.Collect(chained))
}

func TestChained_FilterFilter_Collect(t *testing.T) {
	isEven := func(v int) bool { return v%2 == 0 }
	greaterThan4 := func(v int) bool { return v > 4 }

	chained := generics.FilterSeq(generics.FilterSeq(intSeq(1, 2, 3, 4, 5, 6, 7, 8), isEven), greaterThan4)

	assert.Equal(t, []int{6, 8}, slices.Collect(chained))
	assert.Equal(t, []int{6, 8}, slices.Collect(chained))
}

func TestChained_Filter_IsEmpty(t *testing.T) {
	isEven := func(v int) bool { return v%2 == 0 }

	// Filtering all-odd by isEven yields nothing.
	empty := generics.FilterSeq(intSeq(1, 3, 5), isEven)
	assert.True(t, generics.IsEmptySeq(empty))
	assert.True(t, generics.IsEmptySeq(empty))

	nonEmpty := generics.FilterSeq(intSeq(1, 2, 3), isEven)
	assert.False(t, generics.IsEmptySeq(nonEmpty))
	assert.False(t, generics.IsEmptySeq(nonEmpty))
}

func TestChained_Filter_SeqContains(t *testing.T) {
	isEven := func(v int) bool { return v%2 == 0 }

	evens := generics.FilterSeq(intSeq(1, 2, 3, 4, 5, 6), isEven)
	assert.True(t, generics.SeqContains(evens, 4))
	assert.True(t, generics.SeqContains(evens, 4))
	assert.False(t, generics.SeqContains(evens, 3))
	assert.False(t, generics.SeqContains(evens, 3))
}

func TestChained_Filter_SeqAny(t *testing.T) {
	isEven := func(v int) bool { return v%2 == 0 }
	greaterThan5 := func(v int) bool { return v > 5 }

	evens := generics.FilterSeq(intSeq(1, 2, 3, 4, 5, 6), isEven)
	assert.True(t, generics.SeqAny(evens, greaterThan5))
	assert.True(t, generics.SeqAny(evens, greaterThan5))
}

func TestChained_Filter_SeqAll(t *testing.T) {
	isEven := func(v int) bool { return v%2 == 0 }
	positive := func(v int) bool { return v > 0 }

	evens := generics.FilterSeq(intSeq(2, 4, 6), isEven)
	assert.True(t, generics.SeqAll(evens, positive))
	assert.True(t, generics.SeqAll(evens, positive))
}

func TestChained_FilterMap_EarlyTermination(t *testing.T) {
	var yielded int
	src := countingSeq(intSeq(1, 2, 3, 4, 5, 6, 7, 8, 9, 10), &yielded)
	isEven := func(v int) bool { return v%2 == 0 }
	double := func(v int) int { return v * 2 }

	chained := generics.MapSeq(generics.FilterSeq(src, isEven), double)

	// Take only the first element. The source yields 1 (odd, skipped by
	// filter), then 2 (even, passed through filter+map, yielded to us),
	// at which point we break.
	for range chained {
		break
	}
	assert.Equal(t, 2, yielded, "source should stop once consumer gets first result through the chain")
}

func TestChained_FilterMap_SeqContains_EarlyTermination(t *testing.T) {
	var yielded int
	src := countingSeq(intSeq(1, 2, 3, 4, 5, 6, 7, 8, 9, 10), &yielded)
	isEven := func(v int) bool { return v%2 == 0 }
	double := func(v int) int { return v * 2 }

	// Evens are [2,4,6,8,10], doubled to [4,8,12,16,20]. Looking for 8.
	// Source yields: 1(skip), 2(doubled=4, no), 3(skip), 4(doubled=8, found).
	chained := generics.MapSeq(generics.FilterSeq(src, isEven), double)
	assert.True(t, generics.SeqContains(chained, 8))
	assert.Equal(t, 4, yielded, "source should stop once needle is found through the chain")
}
