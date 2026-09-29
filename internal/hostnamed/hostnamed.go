// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

// Package hostnamed implements a minimal varlink client for the
// io.systemd.Hostname interface for quarry's needs.
//
// Note that machine tag support (SetTags and the TAGS= machine-info field)
// requires systemd v262 or later.
package hostnamed

import (
	"context"
	"errors"
	"strings"

	"go.amutable.dev/quarry/internal/varlink"
)

// vlInterface is the varlink interface name implemented by hostnamed.
const vlInterface = "io.systemd.Hostname"

// DefaultSocketURI is the varlink URI for systemd-hostnamed's socket-activated
// io.systemd.Hostname service.
const DefaultSocketURI = "unix:/run/systemd/" + vlInterface

// Description is the subset of the io.systemd.Hostname.Describe reply that
// quarry makes use of. Unknown reply fields are ignored when unmarshalling.
type Description struct {
	// Hostname is the hostname of the system.
	Hostname string `json:"Hostname"`
	// MachineID is the 128-bit machine ID formatted as a hexadecimal string.
	MachineID string `json:"MachineID"`
	// MachineTags is the set of parsed machine tags.
	// NOTE: This was added in <https://github.com/systemd/systemd/pull/43488>.
	MachineTags []string `json:"MachineTags"`
	// MachineInformationData is the full contents of machine-info(5), as an
	// array of "KEY=VALUE" strings (with the values unescaped).
	MachineInformationData []string `json:"MachineInformationData"`
}

// Describe calls io.systemd.Hostname.Describe and returns the running
// machine's [Description]. If uri is empty then [DefaultSocketURI] is used as
// the varlink service URI.
func Describe(ctx context.Context, uri string) (*Description, error) {
	if uri == "" {
		uri = DefaultSocketURI
	}
	return varlink.Call[Description](ctx, uri, vlInterface+".Describe", struct{}{})
}

// CurrentTags returns the current set of machine tags (from the TAGS= field
// of machine-info(5), fetched via [Describe]), sorted and deduplicated. The
// tags are not validated (see [ParseTags]), so hand-edited machine-info files
// can yield tags that hostnamed itself would reject.
func CurrentTags(ctx context.Context, uri string) ([]string, error) {
	desc, err := Describe(ctx, uri)
	if err != nil {
		return nil, err
	}
	if desc == nil {
		return nil, errors.New("io.systemd.Hostname.Describe returned null data")
	}
	// MachineTags provides pre-parsed tags, so prefer that if it is available.
	if desc.MachineTags != nil {
		return desc.MachineTags, nil
	}
	// Fallback to parsing the raw TAGS= line from MachineInformationData if
	// MachineTags is missing.
	// TODO: This probably can be dropped because v262 is needed for all of
	// this and <https://github.com/systemd/systemd/pull/43488> was merged in
	// time for v262 too?
	for _, kv := range desc.MachineInformationData {
		if value, ok := strings.CutPrefix(kv, "TAGS="); ok {
			return ParseTags(value), nil
		}
	}
	return nil, nil
}

// SetTagsParams is the input to [SetTags] (io.systemd.Hostname.SetTags) and
// provides the set of requested tags to add or remove from the existing set.
// Each field is treated idempotently (i.e., adding pre-existing tags or
// removing non-existent tags silently succeeds) and Remove takes precedence
// over Add if a tag is listed in both sets.
//
// NOTE: The "set" field provided by io.systemd.Hostname.SetTags is
// intentionally missing -- if present (even if null!) it resets the machine
// tag list wholesale, likely clobbering other random tags.
type SetTagsParams struct {
	Add    []string `json:"add,omitempty"`
	Remove []string `json:"remove,omitempty"`
}

// String represents a set of tags changes in the form of
// "'tagA':'tagB':-'tagC'" with removed tags including a "-" prefix.
func (p *SetTagsParams) String() string {
	if p == nil {
		return ""
	}
	var buf strings.Builder
	for i, tag := range p.Add {
		if i > 0 {
			buf.WriteRune(':')
		}
		buf.WriteRune('\'')
		buf.WriteString(tag)
		buf.WriteRune('\'')
	}
	for _, tag := range p.Remove {
		if buf.Len() > 0 {
			buf.WriteRune(':')
		}
		buf.WriteString(`-'`)
		buf.WriteString(tag)
		buf.WriteRune('\'')
	}
	return buf.String()
}

// Invert swaps the Add and Remove sets from [SetTagsParams], which is very
// useful for reverting the application of tags.
//
// NOTE: If you use this to revert a [SetTags] operation you must be sure that
// Add does not contain pre-existing tags and Remove does not contain
// non-existent tags as otherwise the state after the revert will not match the
// state before it.
func (p *SetTagsParams) Invert() { p.Add, p.Remove = p.Remove, p.Add }

// Inverted is like [SetTagsParams.Invert] but returns a cloned copy that is
// inverted.
func (p *SetTagsParams) Inverted() *SetTagsParams {
	pnew := new(SetTagsParams)
	*pnew = *p
	pnew.Invert()
	return pnew
}

// IsEmpty indicates whether the requested set of changes is actually a no-op.
func (p *SetTagsParams) IsEmpty() bool { return p == nil || len(p.Add) == 0 && len(p.Remove) == 0 }

// RawSetTags calls io.systemd.Hostname.SetTags with the given [SetTagsParams],
// but without any of the fallback logic in [SetTags]. Most users should
// probably use [SetTags].
//
// systemd-hostnamed has restrictions on tag names and if any tags in either
// set are invalid, the entire operation will fail with an error of type
// org.varlink.service.InvalidParameter (which can be detected using
// [varlink.IsInvalidParameter]).
//
// This method requires systemd v262 or later.
func RawSetTags(ctx context.Context, uri string, params *SetTagsParams) error {
	if params.IsEmpty() {
		return nil
	}
	if uri == "" {
		uri = DefaultSocketURI
	}
	_, err := varlink.Call[struct{}](ctx, uri, vlInterface+".SetTags", params)
	return err
}

// SetTags calls io.systemd.Hostname.SetTags with the given [SetTagsParams].
// Tags not referenced in either the Add nor Remove sets remain unchanged and
// if both sets are empty then this operation is a no-op. If uri is empty then
// [DefaultSocketURI] is used as the varlink service URI.
//
// If any tags are flagged as invalid by hostnamed, the operation is retried
// with each tag one-by-one. The set of applied and rejected flags is returned
// in the form of [SetTagsParams] for the caller's convenience. This is a more
// user-friendly approach than [RawSetTags], which will do nothing if any tags
// are invalid.
//
// NOTE: The fallback path described in the previous paragraph works well to
// remove completely invalid tags, but in certain cases this may result in
// somewhat unexpected behaviour. In particular, if you try to add the same
// key-value tag with two different values, the [RawSetTags] call will fail
// (hostnamed rejects contradictory tags) but the fallback path will set them
// separately which would be permitted and then one will take arbitrary
// precdence. Callers should be sure to avoid those kinds of pitfalls.
func SetTags(ctx context.Context, uri string, params *SetTagsParams) (applied, rejected *SetTagsParams, _ error) {
	// Fast path: If all the tags are valid, this will work in one shot.
	if err := RawSetTags(ctx, uri, params); err == nil {
		return params, nil, nil
	} else if !varlink.IsInvalidParameter(err) {
		// If the error is not InvalidParameter, something else went wrong.
		return nil, nil, err
	}

	// Slow path: Do each requested tag addition and removal individually to
	// detect which tags are invalid by using hostnamed as an oracle.
	// TODO: There must be a way to deduplicate this.
	applied = &SetTagsParams{
		Add:    make([]string, 0, len(params.Add)),
		Remove: make([]string, 0, len(params.Remove)),
	}
	rejected = &SetTagsParams{
		Add:    make([]string, 0, len(params.Add)),
		Remove: make([]string, 0, len(params.Remove)),
	}
	for _, tag := range params.Add {
		switch err := RawSetTags(ctx, uri, &SetTagsParams{Add: []string{tag}}); {
		case err == nil:
			applied.Add = append(applied.Add, tag)
		case varlink.IsInvalidParameter(err):
			rejected.Add = append(rejected.Add, tag)
		default:
			return applied, rejected, err
		}
	}
	for _, tag := range params.Remove {
		switch err := RawSetTags(ctx, uri, &SetTagsParams{Remove: []string{tag}}); {
		case err == nil:
			applied.Remove = append(applied.Remove, tag)
		case varlink.IsInvalidParameter(err):
			rejected.Remove = append(rejected.Remove, tag)
		default:
			return applied, rejected, err
		}
	}
	return applied, rejected, nil
}
