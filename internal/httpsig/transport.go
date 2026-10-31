// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package httpsig

import (
	"crypto"
	"fmt"
	"net/http"
	"slices"
)

// Transport is an [http.RoundTripper] that signs requests with Base before
// passing them to Next. The caller's request is never modified: each request
// is cloned and the clone is signed.
//
// Only the first request of a redirect chain is signed. Redirect hops (any
// request with a non-nil Response, which [http.Client] sets when following
// redirects) are sent without a signature: Signature and Signature-Input are
// removed, and Prepare is not called. A server that wants a redirected
// request authenticated must not redirect it.
//
// Some caveats:
//
//   - The same nonce can be sent twice. If a reused connection fails before
//     any response, net/http may resend the same signed request, which a
//     server with a replay cache would reject.
//   - Fields that [http.Transport] adds while sending (such as
//     Accept-Encoding or the default User-Agent) are never seen. Covering one
//     fails with [ErrMissingComponent] (or, if added with
//     [WithOptionalComponents], leaves it out).
//   - The body is never read. Covering it needs a Content-Digest, set by the
//     caller or in Prepare.
//
// Transport does not filter by host; callers that must only sign requests to
// some hosts should wrap it.
type Transport struct {
	// Base describes the signature added to each request.
	Base *Base
	// Signer signs each request.
	Signer crypto.Signer
	// Options are passed to [Base.SignRequest] for each request.
	Options []SignOption
	// Prepare, if set, is called on the clone of each first request before
	// signing. It can set header fields that Base covers and return
	// additional options for this request. An error fails the request, so it
	// is never sent unsigned.
	Prepare func(req *http.Request) ([]SignOption, error)
	// Next sends the request; nil means [http.DefaultTransport].
	Next http.RoundTripper
}

func (t *Transport) next() http.RoundTripper {
	if t.Next != nil {
		return t.Next
	}
	return http.DefaultTransport
}

// RoundTrip implements [http.RoundTripper].
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	if req.Response != nil {
		// Redirect hop: never sign, never forward a signature.
		req.Header.Del(headerSignature)
		req.Header.Del(headerSignatureInput)
		return t.next().RoundTrip(req)
	}
	opts := t.Options
	if t.Prepare != nil {
		extra, err := t.Prepare(req)
		if err != nil {
			closeBody(req)
			return nil, err
		}
		opts = append(slices.Clip(opts), extra...)
	}
	if _, err := t.Base.SignRequest(t.Signer, req, opts...); err != nil {
		closeBody(req)
		return nil, fmt.Errorf("sign request to %s: %w", req.URL.Host, err)
	}
	return t.next().RoundTrip(req)
}

// closeBody closes the body of a request that will not be sent, as
// [http.RoundTripper] requires.
func closeBody(req *http.Request) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
}
