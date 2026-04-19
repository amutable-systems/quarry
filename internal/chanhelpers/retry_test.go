// Copyright (C) 2026 Amutable GmbH

package chanhelpers_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.amutable.dev/quarry/internal/chanhelpers"
)

// receiveWithin receives from ch or fails the test after timeout.
func receiveWithin[T any](t *testing.T, ch <-chan T, timeout time.Duration) (T, bool) {
	t.Helper()
	select {
	case v, ok := <-ch:
		return v, ok
	case <-time.After(timeout):
		t.Fatalf("did not receive from channel within %s", timeout)
		panic("unreachable")
	}
}

func TestGoRetryCtx_ImmediateSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var calls atomic.Int32
	ch := chanhelpers.GoRetryCtx(ctx, func() *int {
		calls.Add(1)
		v := 42
		return &v
	})

	v, ok := receiveWithin(t, ch, time.Second)
	require.True(t, ok, "channel should deliver a value before being closed")
	assert.Equal(t, 42, v)

	_, ok = receiveWithin(t, ch, time.Second)
	assert.False(t, ok, "channel should be closed after delivering the value")

	assert.Equal(t, int32(1), calls.Load(), "fn should be called exactly once on immediate success")
}

func TestGoRetryCtx_RetryUntilSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const successOn = 3
	var calls atomic.Int32
	ch := chanhelpers.GoRetryCtx(ctx, func() *int {
		n := calls.Add(1)
		if n < successOn {
			return nil
		}
		v := 100
		return &v
	})

	v, ok := receiveWithin(t, ch, 5*time.Second)
	require.True(t, ok)
	assert.Equal(t, 100, v)

	_, ok = receiveWithin(t, ch, time.Second)
	assert.False(t, ok, "channel should be closed")

	assert.Equal(t, int32(successOn), calls.Load())
}

func TestGoRetryCtx_CancellationStopsRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// Non-blocking send so fn never stalls on a full buffer.
	calls := make(chan struct{}, 64)
	ch := chanhelpers.GoRetryCtx(ctx, func() *int {
		select {
		case calls <- struct{}{}:
		default:
		}
		return nil
	})

	select {
	case <-calls:
	case <-time.After(time.Second):
		t.Fatal("fn was never called")
	}
	cancel()

	// Drain the at-most-one call that may race with cancel().
	time.Sleep(200 * time.Millisecond)
	for {
		select {
		case <-calls:
			continue
		default:
		}
		break
	}

	select {
	case <-calls:
		t.Fatal("fn was called after ctx cancellation was observed")
	case <-time.After(300 * time.Millisecond):
	}

	// Channel is neither sent to nor closed on cancellation.
	select {
	case v, ok := <-ch:
		t.Fatalf("unexpected channel activity after cancellation: value=%v, ok=%v", v, ok)
	default:
	}
}

func TestGoRetryCtx_AlreadyCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// First call runs before ctx is checked; select then picks Done over the
	// pending time.After, so fn is invoked exactly once.
	var calls atomic.Int32
	ch := chanhelpers.GoRetryCtx(ctx, func() *int {
		calls.Add(1)
		return nil
	})

	select {
	case v, ok := <-ch:
		t.Fatalf("unexpected channel activity under already-cancelled ctx: value=%v, ok=%v", v, ok)
	case <-time.After(200 * time.Millisecond):
	}
	assert.Equal(t, int32(1), calls.Load(), "fn should be called exactly once before cancellation is observed")
}

func TestGoRetryCtx_SuccessBeatsCancel(t *testing.T) {
	// ctx is checked only after fn returns nil; an immediate success bypasses
	// it.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ch := chanhelpers.GoRetryCtx(ctx, func() *int {
		v := 7
		return &v
	})

	v, ok := receiveWithin(t, ch, time.Second)
	require.True(t, ok)
	assert.Equal(t, 7, v)

	_, ok = receiveWithin(t, ch, time.Second)
	assert.False(t, ok, "channel should be closed after delivering value")
}

func TestGoRetryCtx_WithResult(t *testing.T) {
	// Canonical pairing: fn returns *Result so failures reach the caller.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var calls atomic.Int32
	ch := chanhelpers.GoRetryCtx(ctx, func() *chanhelpers.Result[int] {
		n := calls.Add(1)
		if n < 2 {
			return nil
		}
		return &chanhelpers.Result[int]{Err: errSentinel}
	})

	r, ok := receiveWithin(t, ch, 5*time.Second)
	require.True(t, ok)

	got, err := r.Unwrap()
	require.ErrorIs(t, err, errSentinel)
	assert.Zero(t, got)

	assert.Equal(t, int32(2), calls.Load())
}
