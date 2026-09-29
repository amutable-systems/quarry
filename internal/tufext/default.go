// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package tufext

import (
	"time"

	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"
)

// SignedRoot is the underlying type for TUF's root.json.
type SignedRoot = tufmetadata.Metadata[tufmetadata.RootType]

// SignedTimestamp is the underlying type for TUF's timestamp.json.
type SignedTimestamp = tufmetadata.Metadata[tufmetadata.TimestampType]

// SignedSnapshot is the underlying type for TUF's snapshot.json.
type SignedSnapshot = tufmetadata.Metadata[tufmetadata.SnapshotType]

// SignedTargets is the underlying type for TUF's targets.json.
type SignedTargets = tufmetadata.Metadata[tufmetadata.TargetsType]

func signed[T tufmetadata.Roles](inner T) *tufmetadata.Metadata[T] {
	return &tufmetadata.Metadata[T]{
		Signed:     inner,
		Signatures: []tufmetadata.Signature{},
	}
}

func defaultExpiry(expiry ...time.Time) time.Time {
	switch len(expiry) {
	case 0:
		return *new(time.Time)
	case 1:
		return expiry[0].UTC()
	default:
		panic("Default* can only have at most one expiry argument")
	}
}

// DefaultRoot returns a somewhat-reasonable value of a TUF targets.json.
func DefaultRoot(expiry ...time.Time) *SignedRoot {
	return signed(tufmetadata.RootType{
		Type:               tufmetadata.ROOT,
		SpecVersion:        tufmetadata.SPECIFICATION_VERSION,
		Version:            1,
		Expires:            defaultExpiry(expiry...),
		ConsistentSnapshot: true,
		Roles:              make(map[string]*tufmetadata.Role, 4),
		Keys:               make(map[string]*tufmetadata.Key, 16),
	})
}

// DefaultTimestamp returns a somewhat-reasonable value of a TUF timestamp.json.
func DefaultTimestamp(expiry ...time.Time) *SignedTimestamp {
	return signed(tufmetadata.TimestampType{
		Type:        tufmetadata.TIMESTAMP,
		SpecVersion: tufmetadata.SPECIFICATION_VERSION,
		Version:     -1, // bad value to make sure caller modifies it
		Expires:     defaultExpiry(expiry...),
		Meta:        make(map[string]*tufmetadata.MetaFiles, 1),
	})
}

// DefaultSnapshot returns a somewhat-reasonable value of a TUF snapshot.json.
func DefaultSnapshot(expiry ...time.Time) *SignedSnapshot {
	return signed(tufmetadata.SnapshotType{
		Type:        tufmetadata.SNAPSHOT,
		SpecVersion: tufmetadata.SPECIFICATION_VERSION,
		Version:     -1, // bad value to make sure caller modifies it
		Expires:     defaultExpiry(expiry...),
		Meta:        make(map[string]*tufmetadata.MetaFiles, 1),
	})
}

// DefaultTargets returns a somewhat-reasonable value of a TUF targets.json.
func DefaultTargets(expiry ...time.Time) *SignedTargets {
	return signed(tufmetadata.TargetsType{
		Type:        tufmetadata.TARGETS,
		SpecVersion: tufmetadata.SPECIFICATION_VERSION,
		Version:     -1, // bad value to make sure caller modifies it
		Expires:     defaultExpiry(expiry...),
		Targets:     make(map[string]*tufmetadata.TargetFiles, 64),
	})
}
