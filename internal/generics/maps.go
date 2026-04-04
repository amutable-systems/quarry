// Copyright (C) 2026 Amutable GmbH

package generics

// MapContains is just shorhand for checking that a map contains a key.
//
//	ok := generics.MapContains(m, k)
//
// is equivalent to
//
//	_, ok := m[k]
//
// except that a nil map will not panic.
func MapContains[M ~map[K]V, K comparable, V any](m M, k K) bool {
	var ok bool
	if m != nil {
		_, ok = m[k]
	}
	return ok
}
