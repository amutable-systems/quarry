// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

// Package keyopts provides options for usage with keystore drivers as well as
// some generic options that work with all keystore drivers (because they are
// properties of the keys themselves).
package keyopts

// GenerateOption is an option to be used with GenerateKey.
type GenerateOption interface {
	ApplyKeyGenerate(any) (bool, error)
}

/*
type generateOptionFunc func(any) (bool, error)

func (fn generateOptionFunc) ApplyKeyGenerate(state any) (bool, error) {
	return fn(state)
}
*/

// RotateOption is an option to be used with RotateKey.
type RotateOption interface {
	ApplyKeyRotate(any) (bool, error)
}

/*
type rotateOptionFunc func(any) (bool, error)

func (fn rotateOptionFunc) ApplyKeyRotate(state any) (bool, error) {
	return fn(state)
}
*/

// ImportOption an option to be used with ImportKey.
type ImportOption interface {
	ApplyKeyImport(any) (bool, error)
}

/*
type importOptionFunc func(any) (bool, error)

func (fn importOptionFunc) ApplyKeyImport(state any) (bool, error) {
	return fn(state)
}
*/

// ExportOption an option to be used with ExportKey.
type ExportOption interface {
	ApplyKeyExport(any) (bool, error)
}

/*
type exportOptionFunc func(any) (bool, error)

func (fn exportOptionFunc) ApplyKeyExport(state any) (bool, error) {
	return fn(state)
}
*/
