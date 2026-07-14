// Copyright (C) 2026 Amutable GmbH

package keystore

// Option is the base interface for all key-management options. Concrete
// options implement a typed apply method (such as Apply(*RSAState) error)
// plus one or more marker methods (such as
// [GenerateOption.IsGenerateOption]) to declare which [Store] operations
// they are valid for.
//
// Note that the apply method must be part of the method set of the value
// stored in the option list -- an Apply with a pointer receiver on an
// option passed by value will never match any state and will be reported
// as unsupported.
type Option interface {
	// IsOption is a no-op marker method identifying key-management options.
	IsOption()
}

// GenerateOption is the interface for options accepted by
// [Store.GenerateKey].
type GenerateOption interface {
	Option
	IsGenerateOption()
}

// RotateOption is the interface for options accepted by [Store.RotateKey].
type RotateOption interface {
	Option
	IsRotateOption()
}

// ImportOption is the interface for options accepted by [Driver.ImportKey].
type ImportOption interface {
	Option
	IsImportOption()
}

// ExportOption is the interface for options accepted by [Driver.ExportKey].
type ExportOption interface {
	Option
	IsExportOption()
}
