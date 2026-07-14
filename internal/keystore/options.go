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

// GenericOption is satisfied by options that apply to all of the
// key-provisioning operations ([Store.GenerateKey], [Store.RotateKey], and
// [Driver.ImportKey]). Export operations consume an existing key rather
// than producing one, so they have no use for these options.
type GenericOption interface {
	GenerateOption
	RotateOption
	ImportOption
}

// GenerateRotateOption is satisfied by options that only apply to
// operations producing new key material ([Store.GenerateKey] and
// [Store.RotateKey]). Keytype-specific options like [WithRSABits] are
// typed as this, since key parameters are fixed by the key material for
// [Driver.ImportKey].
type GenerateRotateOption interface {
	GenerateOption
	RotateOption
}

// keyTypeParamer is implemented by options that constrain the TUF keytype
// of the operation ([WithKeyType] explicitly, keytype-specific options
// like [WithRSABits] by implication). The resolver collects the keytype
// from every option up-front and treats any mismatch as a hard conflict
// (rather than last-wins, which would silently disable the losing
// option's sibling options). Options are also expected to validate their
// own values here, since keyTypeParam is called for every option even if
// no state pass ever matches it.
//
// Note that keyTypeParam does not mark an option as consumed, only a
// matching state pass does.
type keyTypeParamer interface {
	keyTypeParam() (string, error)
}
