// Copyright (C) 2026 Amutable GmbH

// Package varlink provides very minimal wrappers around
// [snai.pe/go-varlink.Client].
package varlink

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"snai.pe/go-varlink"

	"go.amutable.dev/quarry/internal/third_party/funchelpers"
)

// IsInvalidParameter reports whether the given error is an
// org.varlink.service.InvalidParameter error reply.
func IsInvalidParameter(err error) bool {
	vlErr, ok := errors.AsType[varlink.Error](err)
	return ok && vlErr.ErrorCode() == "org.varlink.service.InvalidParameter"
}

// Call performs a "vanilla" (single-reply) varlink method call against the
// service at uri using [varlink.DefaultClient]. If there was a reply, it will
// be deserialised into an instance of type ReplyT -- otherwise Call will
// return nil, nil.
//
// TODO: If passed an empty uri, should we derive it from the method name and
// use a socket in /run/systemd/?
func Call[ReplyT any](ctx context.Context, uri, method string, params any) (_ *ReplyT, Err error) {
	// A lot of varlink services are socket-activated and have very short idle
	// windows before the service shuts down, meaning that using a connection
	// pool (like varlink.DefaultClient does) can lead to spurious EPIPEs. So
	// create a new client for every call, the overhead should be fairly
	// minimal anyway.
	vtrans := new(varlink.Transport)
	defer vtrans.CloseIdleConnections()
	vcli := varlink.Client{Transport: vtrans}

	rs, err := vcli.Call(ctx, method, params, varlink.CallURI(uri))
	if err != nil {
		return nil, fmt.Errorf("varlink call %s: %w", method, err)
	}
	defer funchelpers.VerifyClose(&Err, rs)

	if !rs.Next() {
		// This was not a oneway call so there must be a reply from the server.
		return nil, fmt.Errorf("varlink call %s: no reply received: %w", method, rs.Error())
	}

	// [varlink.ReplyStream.Unmarshal] sets DisallowUnknownFields which means
	// that we would need to include all unknown fields in our structure or
	// have a custom UnmarshalJSON method for every type, so "unmarshal" to
	// [json.RawMessage] first then do the real unmarshal.
	var raw json.RawMessage
	if err := rs.Unmarshal(&raw); err != nil {
		return nil, fmt.Errorf("varlink call %s: %w", method, err)
	}
	if len(raw) > 0 {
		var reply ReplyT
		if err := json.Unmarshal(raw, &reply); err != nil {
			return nil, fmt.Errorf("varlink call %s: decode reply parameters: %w", method, err)
		}
		return &reply, nil
	}
	return nil, nil //nolint:nilnil // this API makes more sense
}
