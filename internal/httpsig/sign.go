// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package httpsig

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"maps"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/shogo82148/go-sfv"
)

const (
	headerSignatureInput = "Signature-Input"
	headerSignature      = "Signature"
)

type signConfig struct {
	created    time.Time
	keyID      string
	hasKeyID   bool
	label      string
	hasLabel   bool
	signerOpts crypto.SignerOpts
	nonce      string
	extra      map[string]any
}

// SignOption supplies per-signature values to [Base.SignRequest].
type SignOption func(*signConfig)

// WithCreated sets the reference time used for "created" (and "expires").
// The default is [time.Now].
func WithCreated(t time.Time) SignOption {
	return func(c *signConfig) { c.created = t }
}

// WithKeyID adds a "keyid" parameter.
func WithKeyID(keyID string) SignOption {
	return func(c *signConfig) { c.keyID, c.hasKeyID = keyID, true }
}

// WithSigLabel sets the signature label (the dictionary key in
// Signature-Input and Signature). The default is "s<N>", where N is one more
// than the number of signatures already on the request, increased until the
// label is free. The label must be a valid sf-key and must not already be
// present on the request.
func WithSigLabel(label string) SignOption {
	return func(c *signConfig) { c.label, c.hasLabel = label, true }
}

// WithSignerOpts sets the [crypto.SignerOpts] passed to [crypto.SignMessage],
// which select the algorithm for RSA keys. The default is the first
// algorithm listed for the key type in the package documentation.
func WithSignerOpts(opts crypto.SignerOpts) SignOption {
	return func(c *signConfig) { c.signerOpts = opts }
}

// WithNonceValue uses nonce instead of a random one. It is an error to use
// this with a Base that was created with [WithoutNonce].
func WithNonceValue(nonce string) SignOption {
	return func(c *signConfig) { c.nonce = nonce }
}

// WithExtraParamValue supplies the value of a parameter declared with
// [WithExtraParam]. value must be a string, int64, bool or []byte (serialised
// as an sf-string, sf-integer, sf-boolean or sf-binary respectively). It is
// an error to supply a value for a name the Base did not declare.
func WithExtraParamValue(name string, value any) SignOption {
	return func(c *signConfig) {
		if c.extra == nil {
			c.extra = make(map[string]any)
		}
		c.extra[name] = value
	}
}

// SignRequest signs req as described by b, appends the signature to req's
// Signature-Input and Signature header fields, and returns the label it was
// added under (the [WithSigLabel] value, or the allocated "s<N>"). req is
// modified in place; callers that must not modify the request (such as a
// RoundTripper) should Clone it first. On error, req is unchanged.
func (b *Base) SignRequest(signer crypto.Signer, req *http.Request, opts ...SignOption) (label string, err error) {
	var cfg signConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.created.IsZero() {
		cfg.created = time.Now()
	}

	covered, err := b.resolve(requestMessage{req})
	if err != nil {
		return "", err
	}
	alg, signerOpts, err := chooseAlgorithm(signer.Public(), cfg.signerOpts)
	if err != nil {
		return "", err
	}
	params, err := b.params(&cfg, alg)
	if err != nil {
		return "", err
	}
	input, base, err := signatureBase(covered, params)
	if err != nil {
		return "", err
	}
	label, err = allocateLabel(req.Header, cfg)
	if err != nil {
		return "", err
	}

	sig, err := alg.SignMessage(signer, base, signerOpts)
	if err != nil {
		return "", fmt.Errorf("sign with %s: %w", alg.name, err)
	}

	inputField, err := sfv.EncodeDictionary(sfv.Dictionary{{Key: label, Item: input}})
	if err != nil {
		return "", fmt.Errorf("%w: serialise Signature-Input: %w", ErrInvalidParameter, err)
	}
	sigField, err := sfv.EncodeDictionary(sfv.Dictionary{{Key: label, Item: sfv.Item{Value: sig}}})
	if err != nil {
		return "", fmt.Errorf("serialise Signature: %w", err)
	}
	req.Header.Add(headerSignatureInput, inputField)
	req.Header.Add(headerSignature, sigField)
	return label, nil
}

// params returns the signature parameters, in the order of RFC 9421 section
// 2.3 followed by b's extra parameters in declaration order.
func (b *Base) params(cfg *signConfig, alg *algorithm) (sfv.Parameters, error) {
	var params sfv.Parameters
	if !b.noAlg {
		params = append(params, sfv.Parameter{Key: "alg", Value: alg.name})
	}
	if !cfg.created.IsZero() {
		params = append(params, sfv.Parameter{Key: "created", Value: cfg.created.Unix()})
	}
	if b.expiry != nil {
		params = append(params, sfv.Parameter{Key: "expires", Value: cfg.created.Add(*b.expiry).Unix()})
	}
	if cfg.nonce != "" && b.noNonce {
		return nil, ErrNonceNotEnabled
	}
	if !b.noNonce {
		nonce := cfg.nonce
		if nonce == "" {
			var buf [16]byte
			if _, err := io.ReadFull(rand.Reader, buf[:]); err != nil {
				return nil, fmt.Errorf("generate nonce: %w", err)
			}
			nonce = base64.RawURLEncoding.EncodeToString(buf[:])
		}
		if !sfv.IsValidString(nonce) {
			return nil, fmt.Errorf("%w: nonce %q is not a valid sf-string", ErrInvalidParameter, nonce)
		}
		params = append(params, sfv.Parameter{Key: "nonce", Value: nonce})
	}
	if cfg.hasKeyID {
		if !sfv.IsValidString(cfg.keyID) {
			return nil, fmt.Errorf("%w: keyid %q is not a valid sf-string", ErrInvalidParameter, cfg.keyID)
		}
		params = append(params, sfv.Parameter{Key: "keyid", Value: cfg.keyID})
	}
	if b.tag != "" {
		params = append(params, sfv.Parameter{Key: "tag", Value: b.tag})
	}

	extra := maps.Clone(b.extra)
	for name, value := range cfg.extra {
		if _, ok := b.extra[name]; !ok {
			return nil, fmt.Errorf("%w: %q is not declared by the base", ErrInvalidParameter, name)
		}
		extra[name] = value
	}
	for name, v := range extra {
		if v == nil {
			return nil, fmt.Errorf("%w: %q", ErrMissingParameter, name)
		}
		value, err := paramValue(v)
		if err != nil {
			return nil, fmt.Errorf("%w: %q: %w", ErrInvalidParameter, name, err)
		}
		params = append(params, sfv.Parameter{Key: name, Value: value})
	}
	return params, nil
}

// resolvedComponent is a covered component with its signature base value.
type resolvedComponent struct {
	component Component
	value     string
}

// resolve returns the value of each of b's components in msg, leaving out
// absent optional components.
func (b *Base) resolve(msg message) ([]resolvedComponent, error) {
	resolved := make([]resolvedComponent, 0, len(b.components))
	for _, c := range b.components {
		value, ok, err := c.resolve(msg)
		if err != nil {
			return nil, componentErr(c.Component, err)
		}
		if !ok {
			if c.optional {
				continue
			}
			return nil, componentErr(c.Component, ErrMissingComponent)
		}
		if strings.ContainsAny(value, "\r\n") {
			return nil, componentErr(c.Component, fmt.Errorf("%w: value contains CR or LF", ErrInvalidComponent))
		}
		resolved = append(resolved, resolvedComponent{component: c.Component, value: value})
	}
	return resolved, nil
}

// signatureBase returns the Signature-Input member (the @signature-params
// value) and the signature base (RFC 9421 section 2.5) for the covered
// components and params.
func signatureBase(covered []resolvedComponent, params sfv.Parameters) (sfv.Item, []byte, error) {
	ids := make(sfv.InnerList, 0, len(covered))
	for _, rc := range covered {
		ids = append(ids, rc.component.item())
	}
	input := sfv.Item{Value: ids, Parameters: params}
	sigParams, err := encodeMember(input)
	if err != nil {
		return sfv.Item{}, nil, fmt.Errorf("%w: serialise @signature-params: %w", ErrInvalidParameter, err)
	}

	var base strings.Builder
	for _, rc := range covered {
		base.WriteString(rc.component.String())
		base.WriteString(": ")
		base.WriteString(rc.value)
		base.WriteByte('\n')
	}
	base.WriteString(`"@signature-params": `)
	base.WriteString(sigParams)
	return input, []byte(base.String()), nil
}

// allocateLabel returns the label for a new signature on a request with the
// given header.
func allocateLabel(h http.Header, cfg signConfig) (string, error) {
	inputs, err := sfv.DecodeDictionary(h.Values(headerSignatureInput))
	if err != nil {
		return "", fmt.Errorf("%w: Signature-Input: %w", ErrMalformedSignature, err)
	}
	sigs, err := sfv.DecodeDictionary(h.Values(headerSignature))
	if err != nil {
		return "", fmt.Errorf("%w: Signature: %w", ErrMalformedSignature, err)
	}
	taken := func(label string) bool {
		return inputs.Get(label).Value != nil || sigs.Get(label).Value != nil
	}

	if cfg.hasLabel {
		if !validKey(cfg.label) {
			return "", fmt.Errorf("%w: %q is not a valid sf-key", ErrInvalidLabel, cfg.label)
		}
		if taken(cfg.label) {
			return "", fmt.Errorf("%w: %q", ErrLabelExists, cfg.label)
		}
		return cfg.label, nil
	}
	for n := inputs.Len() + 1; ; n++ {
		if label := "s" + strconv.Itoa(n); !taken(label) {
			return label, nil
		}
	}
}
