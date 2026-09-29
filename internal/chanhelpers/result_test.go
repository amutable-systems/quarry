// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package chanhelpers_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.amutable.dev/quarry/internal/chanhelpers"
)

var errSentinel = errors.New("test sentinel error")

func TestResult_Unwrap(t *testing.T) {
	for _, tc := range []struct {
		name    string
		result  chanhelpers.Result[int]
		want    int
		wantErr error
	}{
		{"Ok", chanhelpers.Result[int]{Ok: 42}, 42, nil},
		{"OkZero", chanhelpers.Result[int]{Ok: 0}, 0, nil},
		{"Err", chanhelpers.Result[int]{Err: errSentinel}, 0, errSentinel},
		{"ErrWithOk", chanhelpers.Result[int]{Ok: 42, Err: errSentinel}, 0, errSentinel},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.result.Unwrap()
			if tc.wantErr == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, tc.wantErr)
			}
			assert.Equal(t, tc.want, got)
		})
	}
}
