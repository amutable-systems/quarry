// Copyright (C) 2026 Amutable GmbH

package generics

import (
	"fmt"

	"github.com/tiendc/go-deepcopy"
)

// DeepCopy returns a deep copy of the object of type T.
func DeepCopy[T any](value T) (T, error) {
	var clone T
	err := deepcopy.Copy(&clone, value)
	if err != nil {
		err = fmt.Errorf("failed to clone %T: %w", value, err)
	}
	return clone, err
}
