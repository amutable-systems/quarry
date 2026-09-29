// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

// Package goext provides some helpers for spawning goroutines.
package goext

// GoRet runs "go func()" and returns a channel you can wait on to receive the
// value.
func GoRet[T any](goFn func() T) <-chan T {
	retCh := make(chan T, 1)
	go func() {
		ret := goFn()
		retCh <- ret
		close(retCh)
	}()
	return retCh
}

// GoErr is shorthand for [GoRet] with error values.
var GoErr = GoRet[error]
