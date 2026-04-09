// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package tufext

type LinkProto string

const (
	// ProtoQuarryTufHTTPV1 is the standard TUF-over-HTTP protocol with a
	// static root URL for data and metadata objects.
	ProtoQuarryTufHTTPV1 LinkProto = "quarry/tuf-http-v1"
)

// LinkUpstream represents the upstream source of a repository. At the moment, Quarry only supports standard HTTP
type LinkUpstream struct {
	Proto LinkProto `json:"proto"`
}
