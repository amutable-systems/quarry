// Copyright (C) 2026 Amutable GmbH

package chanhelpers

import (
	"context"
	"time"
)

// GoRetryCtx retries the given *non-blocking* function in a loop until it
// succeeds (by returning a non-nil value).
func GoRetryCtx[T any](ctx context.Context, fn func() *T) <-chan T {
	ch := make(chan T, 1)
	go func() {
		timeout := 50 * time.Millisecond
		for {
			v := fn()
			if v != nil {
				ch <- *v
				close(ch)
				return
			}
			select {
			case <-ctx.Done():
				// The error is handled by the caller.
				return
			case <-time.After(timeout):
				// Retry with exponential back-off.
				if timeout < time.Minute {
					timeout *= 2
				}
			}
		}
	}()
	return ch
}
