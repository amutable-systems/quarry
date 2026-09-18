// Copyright (C) 2026 Amutable GmbH

package tufext_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/generics"
	"go.amutable.dev/quarry/internal/tufext"
)

// keysOf returns the sorted keys. The iterator's within-role order is
// unspecified, so most tests compare sorted slices or sets.
func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func asSet(s []string) map[string]struct{} {
	out := make(map[string]struct{}, len(s))
	for _, v := range s {
		out[v] = struct{}{}
	}
	return out
}

// tf returns a [tufmetadata.TargetFiles] with the given Length, used as a
// distinctive identity to round-trip through the iterator.
func tf(size int64) *tufmetadata.TargetFiles {
	return &tufmetadata.TargetFiles{Length: size}
}

// dr builds a [tufmetadata.DelegatedRole]. Keys/threshold are zero-valued --
// [tufext.IterTargetRoles] does not consult them.
func dr(name string, terminating bool, paths ...string) tufmetadata.DelegatedRole {
	return tufmetadata.DelegatedRole{
		Name:        name,
		Threshold:   1,
		Terminating: terminating,
		Paths:       paths,
	}
}

// signedTargets builds a [tufext.SignedTargets]. Pass nil for delegatedRoles
// to omit the Delegations field entirely.
func signedTargets(targets map[string]*tufmetadata.TargetFiles, delegatedRoles []tufmetadata.DelegatedRole) *tufext.SignedTargets {
	st := &tufext.SignedTargets{
		Signed: tufmetadata.TargetsType{
			Type:        tufmetadata.TARGETS,
			SpecVersion: tufmetadata.SPECIFICATION_VERSION,
			Version:     1,
			Targets:     targets,
		},
	}
	if delegatedRoles != nil {
		st.Signed.Delegations = &tufmetadata.Delegations{
			Roles: delegatedRoles,
		}
	}
	return st
}

// permittedTargets emulates a target listing over IterTargetRoles: every
// target of every yielded role that the role's chain permits, keyed by path.
// It does not deduplicate, so a path permitted via more than one role fails
// the test; no fixture here has one. Priority between roles (first wins) is
// the consumer's concern and is tested in tufclient.
func permittedTargets(t *testing.T, targets map[string]*tufext.SignedTargets) map[string]*tufmetadata.TargetFiles {
	t.Helper()
	out := make(map[string]*tufmetadata.TargetFiles)
	for _, role := range rolesFrom(t, targets) {
		for path, meta := range role.Role.Signed.Targets {
			if !role.IsTargetPermitted(path) {
				continue
			}
			_, dup := out[path]
			require.False(t, dup, "path %q permitted via more than one role", path)
			out[path] = meta
		}
	}
	return out
}

// rolesFrom collects the roles yielded by IterTargetRoles over pre-loaded
// metadata, failing on any error.
func rolesFrom(t *testing.T, targets map[string]*tufext.SignedTargets) []tufext.RoleDelegationChain {
	t.Helper()
	got, err := generics.CollectErrorSeq(tufext.IterTargetRoles(t.Context(), tufext.TargetsMapFetcher(targets)))
	require.NoError(t, err)
	return got
}

// roleNames returns the role names in yield order.
func roleNames(roles []tufext.RoleDelegationChain) []string {
	out := make([]string, 0, len(roles))
	for _, role := range roles {
		out = append(out, role.Name)
	}
	return out
}

// roleByName returns the role with the given name, failing unless it was
// yielded exactly once.
func roleByName(t *testing.T, roles []tufext.RoleDelegationChain, name string) tufext.RoleDelegationChain {
	t.Helper()
	var found []tufext.RoleDelegationChain
	for _, role := range roles {
		if role.Name == name {
			found = append(found, role)
		}
	}
	require.Len(t, found, 1, "role %q must be yielded exactly once", name)
	return found[0]
}

func TestIterTargetRoles_OnlyTargets(t *testing.T) {
	top := signedTargets(map[string]*tufmetadata.TargetFiles{"a": tf(1)}, nil)
	roles := rolesFrom(t, map[string]*tufext.SignedTargets{tufmetadata.TARGETS: top})
	require.Len(t, roles, 1)

	got := roles[0]
	assert.Equal(t, tufmetadata.TARGETS, got.Name)
	assert.Same(t, top, got.Role, "Role must be the fetcher's pointer, not a copy")
	assert.True(t, got.ThisChain.IsEmpty(), "the top-level role has no delegations above it")
	assert.Empty(t, got.TerminatedChains)
	assert.True(t, got.IsTargetPermitted("anything/at/all"), "an unrestricted chain authorises every path")
}

func TestIterTargetRoles_PreOrderDepthFirst(t *testing.T) {
	// Pre-order DFS in declared order (s5.6.7), observed at the role level
	// where map-iteration randomness cannot interfere.
	roles := rolesFrom(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("a", false, "a/*"),
			dr("b", false, "b/*"),
		}),
		"a": signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("a-1", false, "a/1"),
			dr("a-2", false, "a/2"),
		}),
		"a-1": signedTargets(nil, nil),
		"a-2": signedTargets(nil, nil),
		"b":   signedTargets(nil, nil),
	})
	assert.Equal(t, []string{tufmetadata.TARGETS, "a", "a-1", "a-2", "b"}, roleNames(roles))
}

func TestIterTargetRoles_ChainReflectsPathTaken(t *testing.T) {
	roles := rolesFrom(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{dr("d1", false, "a/*/*")}),
		"d1":                signedTargets(nil, []tufmetadata.DelegatedRole{dr("d2", false, "a/foo/*")}),
		"d2":                signedTargets(nil, nil),
	})
	require.Equal(t, []string{tufmetadata.TARGETS, "d1", "d2"}, roleNames(roles))

	d1 := roleByName(t, roles, "d1")
	assert.Equal(t, 1, d1.ThisChain.Length())
	assert.True(t, d1.ThisChain.Contains(tufmetadata.TARGETS))
	assert.False(t, d1.ThisChain.Contains("d1"), "a chain records delegators, not the role itself")

	d2 := roleByName(t, roles, "d2")
	assert.Equal(t, 2, d2.ThisChain.Length())
	assert.True(t, d2.ThisChain.Contains("d1"))
	assert.True(t, d2.IsTargetPermitted("a/foo/x"))
	assert.False(t, d2.IsTargetPermitted("a/bar/x"), "every link must authorise the path")
}

func TestIterTargetRoles_YieldsUnreachableRolesButMatchRejects(t *testing.T) {
	// The role walk does not know which paths a consumer will ask about, so
	// it yields every role it can reach, including ones whose patterns do
	// not fit inside their parent's. Match is what enforces authority, which
	// is why consumers are required to call it.
	roles := rolesFrom(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{dr("d1", false, "b/*")}),
		"d1":                signedTargets(nil, []tufmetadata.DelegatedRole{dr("e1", false, "a/x")}),
		"e1":                signedTargets(nil, nil),
	})
	e1 := roleByName(t, roles, "e1")
	assert.False(t, e1.IsTargetPermitted("a/x"), "e1's own pattern matches but d1's does not")
	assert.False(t, e1.IsTargetPermitted("b/x"), "d1's pattern matches but e1's does not")
}

func TestIterTargetRoles_TerminatedChainsApplyToLaterRolesOnly(t *testing.T) {
	// Roles yielded before a terminating delegation takes effect -- the
	// terminating role itself and its descendants (s4.5) -- see no terminated
	// chains. Roles yielded afterwards see it, and Match rejects the paths it
	// covers even where their own chain would allow them.
	roles := rolesFrom(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("term", true, "a/*"),
			dr("later", false, "a/*", "b/*"),
		}),
		"term":  signedTargets(nil, []tufmetadata.DelegatedRole{dr("child", false, "a/*")}),
		"child": signedTargets(nil, nil),
		"later": signedTargets(nil, nil),
	})
	require.Equal(t, []string{tufmetadata.TARGETS, "term", "child", "later"}, roleNames(roles))

	for _, name := range []string{tufmetadata.TARGETS, "term", "child"} {
		assert.Empty(t, roleByName(t, roles, name).TerminatedChains, "%s is yielded before the termination applies", name)
	}
	child := roleByName(t, roles, "child")
	assert.True(t, child.IsTargetPermitted("a/x"), "descendants of a terminating role may still match")

	later := roleByName(t, roles, "later")
	require.Len(t, later.TerminatedChains, 1)
	assert.True(t, later.ThisChain.IsTargetPermitted("a/x"), "later's own chain allows a/*")
	assert.False(t, later.IsTargetPermitted("a/x"), "the terminated chain must override later's own chain")
	assert.True(t, later.IsTargetPermitted("b/x"), "paths outside the terminated chain are unaffected")
}

func TestIterTargetRoles_TerminatedChainsAreIndependentCopies(t *testing.T) {
	// The iterator keeps extending its own list of terminated chains, so each
	// yielded TerminatedChains slice must be a copy: a consumer that
	// overwrites a slot in the slice it was handed must not affect later
	// roles. (The chains themselves are immutable, so replacing a slot is the
	// only mutation a consumer can perform.)
	targets := map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("term", true, "a/*"),
			dr("first", false, "a/*"),
			dr("second", false, "a/*", "b/*"),
		}),
		"term":   signedTargets(nil, nil),
		"first":  signedTargets(nil, nil),
		"second": signedTargets(nil, nil),
	}
	var second tufext.RoleDelegationChain
	for role, err := range tufext.IterTargetRoles(t.Context(), tufext.TargetsMapFetcher(targets)) {
		require.NoError(t, err)
		switch role.Name {
		case "first":
			require.Len(t, role.TerminatedChains, 1)
			// Overwrite the terminated chain with an empty, match-all one.
			role.TerminatedChains[0] = tufext.DelegationChain{}
		case "second":
			second = role
		}
	}
	require.Len(t, second.TerminatedChains, 1)
	assert.False(t, second.TerminatedChains[0].IsEmpty(), "first's scribbling leaked into second")
	assert.True(t, second.IsTargetPermitted("b/x"), "a match-all terminated chain would have rejected this")
	assert.False(t, second.IsTargetPermitted("a/x"))
}

func TestIterTargetRoles_CycleSkipped(t *testing.T) {
	roles := rolesFrom(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{dr("d1", false, "x/*")}),
		"d1":                signedTargets(nil, []tufmetadata.DelegatedRole{dr("d1", false, "x/*")}),
	})
	assert.Equal(t, []string{tufmetadata.TARGETS, "d1"}, roleNames(roles))
}

func TestIterTargetRoles_DiamondWalkedOncePerPath(t *testing.T) {
	// "shared" is reachable via "a" and via "b": it is yielded once per path,
	// each time with that path's chain, and the fetcher is told the delegator
	// each time.
	type call struct{ role, delegator string }
	var calls []call
	fetch := func(_ context.Context, roleName, delegatorName string) (*tufext.SignedTargets, error) {
		calls = append(calls, call{roleName, delegatorName})
		switch roleName {
		case tufmetadata.TARGETS:
			return signedTargets(nil, []tufmetadata.DelegatedRole{
				dr("a", false, "x/*"),
				dr("b", false, "y/*"),
			}), nil
		case "a", "b":
			return signedTargets(nil, []tufmetadata.DelegatedRole{dr("shared", false, "x/*", "y/*")}), nil
		case "shared":
			return signedTargets(nil, nil), nil
		}
		return nil, fmt.Errorf("unexpected fetch %q", roleName)
	}
	roles, err := generics.CollectErrorSeq(tufext.IterTargetRoles(t.Context(), fetch))
	require.NoError(t, err)
	require.Equal(t, []string{tufmetadata.TARGETS, "a", "shared", "b", "shared"}, roleNames(roles))
	assert.Equal(t, []call{
		{tufmetadata.TARGETS, tufmetadata.ROOT},
		{"a", tufmetadata.TARGETS},
		{"shared", "a"},
		{"b", tufmetadata.TARGETS},
		{"shared", "b"},
	}, calls)

	viaA, viaB := roles[2], roles[4]
	assert.True(t, viaA.ThisChain.Contains("a"))
	assert.False(t, viaA.ThisChain.Contains("b"))
	assert.True(t, viaA.IsTargetPermitted("x/f"))
	assert.False(t, viaA.IsTargetPermitted("y/f"), "a only delegated x/*")
	assert.True(t, viaB.ThisChain.Contains("b"))
	assert.False(t, viaB.ThisChain.Contains("a"))
	assert.True(t, viaB.IsTargetPermitted("y/f"))
	assert.False(t, viaB.IsTargetPermitted("x/f"), "b only delegated y/*")
}

func TestIterTargetRoles_EarlyBreakStopsWalk(t *testing.T) {
	var fetches int
	fetch := func(_ context.Context, roleName, _ string) (*tufext.SignedTargets, error) {
		fetches++
		if roleName == tufmetadata.TARGETS {
			return signedTargets(nil, []tufmetadata.DelegatedRole{
				dr("d1", false, "x/*"),
				dr("d2", false, "y/*"),
			}), nil
		}
		return signedTargets(nil, nil), nil
	}
	for role, err := range tufext.IterTargetRoles(t.Context(), fetch) {
		require.NoError(t, err)
		assert.Equal(t, tufmetadata.TARGETS, role.Name)
		break
	}
	assert.Equal(t, 1, fetches, "nothing may be fetched after the consumer breaks")
}

func TestIterTargetRoles_FetchErrorAfterPartialYield(t *testing.T) {
	// Roles walked before the failure are delivered; the error then names
	// the role that could not be fetched and wraps the fetcher's error.
	roles, err := generics.CollectErrorSeq(tufext.IterTargetRoles(t.Context(), tufext.TargetsMapFetcher(map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("d1", false, "x/*"),
			dr("missing", false, "y/*"),
		}),
		"d1": signedTargets(nil, nil),
	})))
	require.Error(t, err)
	assert.ErrorIs(t, err, fs.ErrNotExist) //nolint:testifylint // assert is fine for error path checks
	assert.Contains(t, err.Error(), "missing")
	assert.Equal(t, []string{tufmetadata.TARGETS, "d1"}, roleNames(roles))
}

func TestIterTargetRoles_RoleYieldedBeforeUnsupportedDelegationError(t *testing.T) {
	// A role whose own delegations use an unsupported feature is still
	// yielded (its targets are fine); the error follows when the walk tries
	// to descend. A consumer listing targets therefore sees that role's own
	// targets before failing.
	bin := dr("bin", false /* no paths */)
	bin.PathHashPrefixes = []string{hashPrefix("x/y")}
	top := signedTargets(nil, []tufmetadata.DelegatedRole{bin})
	roles, err := generics.CollectErrorSeq(tufext.IterTargetRoles(t.Context(), tufext.TargetsMapFetcher(map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: top,
		"bin":               signedTargets(nil, nil),
	})))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "uses path prefixes")
	require.Len(t, roles, 1)
	assert.Same(t, top, roles[0].Role)
}

func TestIterTargetRoles_DepthCapMatchesGoTUF(t *testing.T) {
	// go-tuf's default MaxDelegations of 32 lets it visit 33 roles down a
	// pure chain ("targets" plus r0..r31); the depth cap must yield exactly
	// those and no more.
	const linearLen = 40
	all := map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{dr("r0", false, "x/*")}),
	}
	for i := 0; i < linearLen-1; i++ {
		all[fmt.Sprintf("r%d", i)] = signedTargets(nil, []tufmetadata.DelegatedRole{
			dr(fmt.Sprintf("r%d", i+1), false, "x/*"),
		})
	}
	all[fmt.Sprintf("r%d", linearLen-1)] = signedTargets(nil, nil)

	names := roleNames(rolesFrom(t, all))
	require.Len(t, names, 33)
	assert.Equal(t, tufmetadata.TARGETS, names[0])
	assert.Equal(t, "r0", names[1])
	assert.Equal(t, "r31", names[32])
}

// The tests below observe the walk through an emulated target listing (see
// permittedTargets): which paths the yielded roles are permitted to provide.
// That is the property IterTargetRoles exists to establish, and it is the
// most direct way to express terminating-delegation and path semantics.

func TestIterTargetRoles_GlobPatterns(t *testing.T) {
	// Spec s4.5: '*' and '?' are wildcards, but neither matches '/'.
	got := permittedTargets(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("d_star", false, "star/*.tgz"),
			dr("d_qmark", false, "qmark/foo-?.bin"),
		}),
		"d_star": signedTargets(map[string]*tufmetadata.TargetFiles{
			"star/foo.tgz":     tf(1), // matches
			"star/bar.tgz":     tf(2), // matches
			"star/foo.txt":     tf(3), // wrong extension
			"star/sub/foo.tgz": tf(4), // crosses path separator: must NOT match
		}, nil),
		"d_qmark": signedTargets(map[string]*tufmetadata.TargetFiles{
			"qmark/foo-1.bin":  tf(10), // matches
			"qmark/foo-a.bin":  tf(11), // matches
			"qmark/foo-ab.bin": tf(12), // ? is single-char, must NOT match
			"qmark/foo-1.txt":  tf(13), // wrong extension
		}, nil),
	})
	assert.Equal(t, map[string]struct{}{
		"star/foo.tgz":    {},
		"star/bar.tgz":    {},
		"qmark/foo-1.bin": {},
		"qmark/foo-a.bin": {},
	}, asSet(keysOf(got)))
}

func TestIterTargetRoles_LiteralPath(t *testing.T) {
	got := permittedTargets(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("d1", false, "exact/file.bin"),
		}),
		"d1": signedTargets(map[string]*tufmetadata.TargetFiles{
			"exact/file.bin":   tf(1), // matches
			"exact/other.bin":  tf(2), // doesn't match
			"exact/file.bin/x": tf(3), // doesn't match
		}, nil),
	})
	assert.Equal(t, []string{"exact/file.bin"}, keysOf(got))
}

func TestIterTargetRoles_TerminatingBlocksLaterSiblings(t *testing.T) {
	// After a terminating delegation's subtree, no later role may claim a
	// target matching its paths. "control" is a positive control: it must
	// still appear, so a drop-everything regression can't pass this test.
	control := tf(99)
	got := permittedTargets(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(
			map[string]*tufmetadata.TargetFiles{"control": control},
			[]tufmetadata.DelegatedRole{
				dr("d1", true, "a/*"),
				dr("d2", false, "a/*"),
			},
		),
		"d1": signedTargets(nil, nil),
		"d2": signedTargets(map[string]*tufmetadata.TargetFiles{
			"a/x": tf(1),
		}, nil),
	})
	assert.Equal(t, map[string]*tufmetadata.TargetFiles{"control": control}, got)
}

func TestIterTargetRoles_TerminatingDoesNotBlockUnrelatedPaths(t *testing.T) {
	bx := tf(7)
	got := permittedTargets(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("d1", true, "a/*"),
			dr("d2", false, "b/*"),
		}),
		"d1": signedTargets(nil, nil),
		"d2": signedTargets(map[string]*tufmetadata.TargetFiles{"b/x": bx}, nil),
	})
	assert.Equal(t, map[string]*tufmetadata.TargetFiles{"b/x": bx}, got)
}

func TestIterTargetRoles_TerminatingAllowsDescendants(t *testing.T) {
	// Spec s4.5: a terminating role's own descendants are still processed and
	// may match paths the terminating role claimed.
	leaf := tf(99)
	got := permittedTargets(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("d1", true, "a/*/*"),
		}),
		"d1": signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("e1", false, "a/foo/*"),
		}),
		"e1": signedTargets(map[string]*tufmetadata.TargetFiles{"a/foo/leaf": leaf}, nil),
	})
	assert.Equal(t, map[string]*tufmetadata.TargetFiles{"a/foo/leaf": leaf}, got)
}

func TestIterTargetRoles_TerminatingPropagatesAcrossSubtree(t *testing.T) {
	// A terminating role nested inside a non-terminating parent still blocks
	// later roles outside its parent's subtree. "control" is the positive
	// control to detect a drop-everything regression.
	control := tf(99)
	got := permittedTargets(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(
			map[string]*tufmetadata.TargetFiles{"control": control},
			[]tufmetadata.DelegatedRole{
				dr("d1", false, "a/*/*"),
				dr("d2", false, "a/foo/*"),
			},
		),
		"d1": signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("e1", true, "a/foo/*"),
		}),
		"e1": signedTargets(nil, nil),
		"d2": signedTargets(map[string]*tufmetadata.TargetFiles{
			"a/foo/leaf": tf(1),
		}, nil),
	})
	assert.Equal(t, map[string]*tufmetadata.TargetFiles{"control": control}, got)
}

func TestIterTargetRoles_TerminatingDoesNotApplyWhenChainMismatchedAtRoot(t *testing.T) {
	// e1's paths don't subset its parent d1's, so a TUF lookup for "a/x"
	// would never reach e1. The terminating effect must be scoped by the
	// full ancestor chain, not just e1's own Paths -- otherwise d2's "a/x"
	// would be wrongly suppressed.
	yielded := tf(42)
	got := permittedTargets(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("d1", false, "b/*"),
			dr("d2", false, "a/*"),
		}),
		"d1": signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("e1", true, "a/x"),
		}),
		"e1": signedTargets(nil, nil),
		"d2": signedTargets(map[string]*tufmetadata.TargetFiles{"a/x": yielded}, nil),
	})
	assert.Equal(t, map[string]*tufmetadata.TargetFiles{"a/x": yielded}, got)
}

func TestIterTargetRoles_TerminatingDoesNotApplyWhenChainMismatchedMidway(t *testing.T) {
	// Like the at-root variant, but the chain breaks at an intermediate
	// ancestor (d2's "b/*"), proving the chain check spans every layer, not
	// only the root.
	yielded := tf(42)
	got := permittedTargets(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("d1", false, "a/*/*"),
			dr("d3", false, "a/*/*"),
		}),
		"d1": signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("d2", false, "b/*"),
		}),
		"d2": signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("e1", true, "a/foo/x"),
		}),
		"e1": signedTargets(nil, nil),
		"d3": signedTargets(map[string]*tufmetadata.TargetFiles{"a/foo/x": yielded}, nil),
	})
	assert.Equal(t, map[string]*tufmetadata.TargetFiles{"a/foo/x": yielded}, got)
}

func TestIterTargetRoles_TerminatingChainBlocksWhenFullyMatched(t *testing.T) {
	// Companion to the chain-mismatch tests: in a well-formed chain, the
	// terminating effect still fires. "control" guards against a regression
	// that drops everything.
	control := tf(99)
	got := permittedTargets(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(
			map[string]*tufmetadata.TargetFiles{"control": control},
			[]tufmetadata.DelegatedRole{
				dr("d1", false, "a/*/*"),
				dr("d2", false, "a/*/*"),
			},
		),
		"d1": signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("e1", true, "a/foo/*"),
		}),
		"e1": signedTargets(nil, nil),
		"d2": signedTargets(map[string]*tufmetadata.TargetFiles{
			"a/foo/x": tf(1),
		}, nil),
	})
	assert.Equal(t, map[string]*tufmetadata.TargetFiles{"control": control}, got)
}

func TestIterTargetRoles_MultipleTerminatingChainsTrackedIndependently(t *testing.T) {
	// Two terminating delegations in disjoint subtrees: each suppresses only
	// targets matching its own chain.
	yielded := tf(7)
	got := permittedTargets(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{
			// First subtree: terminating on "a/*".
			dr("ta", true, "a/*"),
			// Second subtree: nested terminating on "b/foo/*".
			dr("db", false, "b/*/*"),
			// Sibling that should be blocked by ta but only for its own paths.
			dr("ta-sibling", false, "a/*"),
			// Sibling that should be blocked by the nested terminating.
			dr("db-sibling", false, "b/foo/*"),
			// Wholly unrelated sibling; nothing should suppress it.
			dr("c-sibling", false, "c/*"),
		}),
		"ta": signedTargets(nil, nil),
		"db": signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("eb", true, "b/foo/*"),
		}),
		"eb":         signedTargets(nil, nil),
		"ta-sibling": signedTargets(map[string]*tufmetadata.TargetFiles{"a/blocked": tf(1)}, nil),
		"db-sibling": signedTargets(map[string]*tufmetadata.TargetFiles{"b/foo/blocked": tf(2)}, nil),
		"c-sibling":  signedTargets(map[string]*tufmetadata.TargetFiles{"c/yielded": yielded}, nil),
	})
	assert.Equal(t, map[string]*tufmetadata.TargetFiles{"c/yielded": yielded}, got)
}

func TestIterTargetRoles_TerminatingAppliesEvenIfRoleSkippedByCycle(t *testing.T) {
	// go-tuf stops considering later roles the moment it *encounters* a
	// matching terminating delegation in a parent's list (s5.6.7.2.1), before
	// visiting the role. So the marker must be pushed when the delegation is
	// seen, not when the role is processed. Here "a" delegates terminatingly
	// to itself: the second visit is skipped as a cycle, and "b" must still
	// be blocked. "control" and "x/in-a" are positive controls.
	control, inA := tf(99), tf(1)
	got := permittedTargets(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(
			map[string]*tufmetadata.TargetFiles{"control": control},
			[]tufmetadata.DelegatedRole{
				dr("a", false, "x/*"),
				dr("b", false, "x/*"),
			},
		),
		"a": signedTargets(
			map[string]*tufmetadata.TargetFiles{"x/in-a": inA},
			[]tufmetadata.DelegatedRole{dr("a", true, "x/*")},
		),
		"b": signedTargets(map[string]*tufmetadata.TargetFiles{"x/from-b": tf(2)}, nil),
	})
	assert.Equal(t, map[string]*tufmetadata.TargetFiles{"control": control, "x/in-a": inA}, got)
}

func TestIterTargetRoles_TerminatingOnSecondPathBlocksLaterSiblings(t *testing.T) {
	// Diamond variant of the above: "shared" is reached via "a"
	// (non-terminating) and again via "b" (terminating); cycle detection is
	// per path, so the second visit is walked rather than skipped. A go-tuf
	// lookup for x/from-c clears its stack on encountering b's terminating
	// delegation, so "c" is never consulted, and the marker must apply after
	// the second visit's subtree however that visit is handled.
	control := tf(99)
	got := permittedTargets(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(
			map[string]*tufmetadata.TargetFiles{"control": control},
			[]tufmetadata.DelegatedRole{
				dr("a", false, "x/*"),
				dr("b", false, "x/*"),
				dr("c", false, "x/*"),
			},
		),
		"a":      signedTargets(nil, []tufmetadata.DelegatedRole{dr("shared", false, "x/*")}),
		"b":      signedTargets(nil, []tufmetadata.DelegatedRole{dr("shared", true, "x/*")}),
		"shared": signedTargets(nil, nil),
		"c":      signedTargets(map[string]*tufmetadata.TargetFiles{"x/from-c": tf(1)}, nil),
	})
	assert.Equal(t, map[string]*tufmetadata.TargetFiles{"control": control}, got)
}

func TestIterTargetRoles_TerminatingAppliesEvenIfRoleSkippedByDepthCap(t *testing.T) {
	// Companion to TerminatingAppliesEvenIfRoleSkippedByCycle for the other
	// reason a role can be skipped: r31 delegates terminatingly to r32, which
	// sits past the depth cap and is never walked. go-tuf clears its stack on
	// encountering the terminating delegation (and gives up at its own cap
	// right after), so the later top-level sibling "b" must still be blocked
	// for x/*. "control" is the positive control.
	const depth = 33 // r32 has a chain of length 33 > maxDelegationDepth
	control := tf(99)
	all := map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(
			map[string]*tufmetadata.TargetFiles{"control": control},
			[]tufmetadata.DelegatedRole{
				dr("r0", false, "x/*"),
				dr("b", false, "x/*"),
			},
		),
		"b": signedTargets(map[string]*tufmetadata.TargetFiles{"x/from-b": tf(2)}, nil),
	}
	for i := 0; i < depth-1; i++ {
		all[fmt.Sprintf("r%d", i)] = signedTargets(nil, []tufmetadata.DelegatedRole{
			dr(fmt.Sprintf("r%d", i+1), i == depth-2, "x/*"), // only r31 -> r32 terminates
		})
	}
	all[fmt.Sprintf("r%d", depth-1)] = signedTargets(map[string]*tufmetadata.TargetFiles{"x/deep": tf(3)}, nil)

	got := permittedTargets(t, all)
	assert.Equal(t, map[string]*tufmetadata.TargetFiles{"control": control}, got)
}

func TestIterTargetRoles_CycleTwoRoles(t *testing.T) {
	got := permittedTargets(t, map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{
			dr("d1", false, "x/*"),
		}),
		"d1": signedTargets(map[string]*tufmetadata.TargetFiles{"x/in-d1": tf(1)},
			[]tufmetadata.DelegatedRole{dr("d2", false, "x/*")},
		),
		"d2": signedTargets(map[string]*tufmetadata.TargetFiles{"x/in-d2": tf(2)},
			[]tufmetadata.DelegatedRole{dr("d1", false, "x/*")}, // closes the cycle
		),
	})
	assert.Equal(t, map[string]struct{}{
		"x/in-d1": {},
		"x/in-d2": {},
	}, asSet(keysOf(got)))
}

func TestIterTargetRoles_DeepDelegationsWithSiblings(t *testing.T) {
	// Regression for a chain aliasing bug: siblings derived from the same
	// parent shared the parent's backing storage (a slice with cap > len at
	// the time), so the second sibling clobbered the first. The chain is now
	// map-backed, but the depth sweep is cheap and guards the property
	// regardless of representation.
	for _, depth := range []int{2, 3, 4, 5, 6, 7, 8, 16} {
		t.Run(fmt.Sprintf("depth=%d", depth), func(t *testing.T) {
			leafA := tf(int64(depth)*10 + 1)
			leafB := tf(int64(depth)*10 + 2)
			all := map[string]*tufext.SignedTargets{}

			// targets -> r0 -> r1 -> ... -> r(depth-1) -> {leafA, leafB}.
			all[tufmetadata.TARGETS] = signedTargets(nil, []tufmetadata.DelegatedRole{
				dr("r0", false, "shared/*"),
			})
			for i := 0; i < depth-1; i++ {
				all[fmt.Sprintf("r%d", i)] = signedTargets(nil, []tufmetadata.DelegatedRole{
					dr(fmt.Sprintf("r%d", i+1), false, "shared/*"),
				})
			}
			all[fmt.Sprintf("r%d", depth-1)] = signedTargets(nil, []tufmetadata.DelegatedRole{
				dr("leafA", false, "shared/A"),
				dr("leafB", false, "shared/B"),
			})
			all["leafA"] = signedTargets(map[string]*tufmetadata.TargetFiles{"shared/A": leafA}, nil)
			all["leafB"] = signedTargets(map[string]*tufmetadata.TargetFiles{"shared/B": leafB}, nil)

			got := permittedTargets(t, all)
			assert.Equal(t, map[string]*tufmetadata.TargetFiles{
				"shared/A": leafA,
				"shared/B": leafB,
			}, got)
		})
	}
}

func TestIterTargetRoles_NoTargetsRole(t *testing.T) {
	// The algorithm starts at the "targets" role; missing it must error.
	_, err := generics.CollectErrorSeq(tufext.IterTargetRoles(t.Context(), tufext.TargetsMapFetcher(nil)))
	require.Error(t, err)
	assert.Contains(t, err.Error(), tufmetadata.TARGETS)
}

func TestIterTargetRoles_PathHashPrefixes_Rejected(t *testing.T) {
	// DelegationChain.IsTargetPermitted can evaluate hash-bin delegations (see
	// TestDelegationChain_PathHashPrefixes_Smoke), but IterTargetRoles
	// refuses to walk them while go-tuf's digest encoding is non-conformant
	// (see the NOTE on hashPrefix): a conformant repository would otherwise
	// be mis-binned identically by us and by the go-tuf client. The error
	// must fire wherever the delegation appears, not only at the top level.
	bin := dr("bin", false /* no paths */)
	bin.PathHashPrefixes = []string{hashPrefix("bins/x")}

	for _, tc := range []struct {
		name    string
		targets map[string]*tufext.SignedTargets
	}{
		{
			name: "top-level",
			targets: map[string]*tufext.SignedTargets{
				tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{bin}),
				"bin":               signedTargets(nil, nil),
			},
		},
		{
			name: "nested",
			targets: map[string]*tufext.SignedTargets{
				tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{dr("d1", false, "bins/*")}),
				"d1":                signedTargets(nil, []tufmetadata.DelegatedRole{bin}),
				"bin":               signedTargets(nil, nil),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := generics.CollectErrorSeq(tufext.IterTargetRoles(t.Context(), tufext.TargetsMapFetcher(tc.targets)))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "uses path prefixes")
			assert.Contains(t, err.Error(), "bin", "error must name the offending role")
		})
	}
}

func TestIterTargetRoles_SuccinctRoles(t *testing.T) {
	st := signedTargets(nil, nil)
	st.Signed.Delegations = &tufmetadata.Delegations{
		SuccinctRoles: &tufmetadata.SuccinctRoles{BitLength: 4, NamePrefix: "bin"},
	}
	_, err := generics.CollectErrorSeq(tufext.IterTargetRoles(t.Context(), tufext.TargetsMapFetcher(map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: st,
	})))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "succinct roles")
}

func TestIterTargetRoles_FetcherErrorSurfaces(t *testing.T) {
	// A fetcher error must be returned to the caller, wrapped with the role
	// name for context.
	sentinel := errors.New("fetcher boom")
	fetch := func(_ context.Context, roleName, _ string) (*tufext.SignedTargets, error) {
		if roleName == tufmetadata.TARGETS {
			return signedTargets(nil, []tufmetadata.DelegatedRole{dr("d1", false, "x/*")}), nil
		}
		return nil, sentinel
	}
	_, err := generics.CollectErrorSeq(tufext.IterTargetRoles(t.Context(), fetch))
	require.Error(t, err)
	assert.ErrorIs(t, err, sentinel) //nolint:testifylint // assert is fine for error path checks
	assert.Contains(t, err.Error(), "d1", "wrapped error must name the failing role")
}

func TestIterTargetRoles_FetcherSeesContext(t *testing.T) {
	// The context passed to IterTargetRoles is plumbed through to the
	// fetcher. Cancellation surfaced by the fetcher propagates as the
	// iterator's error.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	fetch := func(ctx context.Context, _, _ string) (*tufext.SignedTargets, error) {
		return nil, ctx.Err()
	}
	_, err := generics.CollectErrorSeq(tufext.IterTargetRoles(ctx, fetch))
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestIterTargetRoles_DepthCapOnlyPrunesDeepBranch(t *testing.T) {
	// Companion to DepthCapMatchesGoTUF: the depth cap skips only the
	// over-deep role and its subtree. A sibling declared after the deep
	// branch is still walked, unlike the total cap (see MaxDelegationsTotal),
	// which ends the whole walk.
	const linearLen = 40
	all := make(map[string]*tufext.SignedTargets, linearLen+2)
	all[tufmetadata.TARGETS] = signedTargets(nil, []tufmetadata.DelegatedRole{
		dr("r0", false, "x/*"),
		dr("shallow", false, "y/*"),
	})
	for i := 0; i < linearLen-1; i++ {
		all[fmt.Sprintf("r%d", i)] = signedTargets(nil, []tufmetadata.DelegatedRole{
			dr(fmt.Sprintf("r%d", i+1), false, "x/*"),
		})
	}
	all[fmt.Sprintf("r%d", linearLen-1)] = signedTargets(nil, nil)
	all["shallow"] = signedTargets(nil, nil)

	names := roleNames(rolesFrom(t, all))
	assert.Contains(t, names, "r31")
	assert.NotContains(t, names, "r32")
	assert.Equal(t, "shallow", names[len(names)-1], "the sibling after the deep branch must still be walked, last")
}

func TestIterTargetRoles_MaxDelegationsTotal(t *testing.T) {
	// Roles are not deduplicated globally, so a repository could make the
	// walk revisit a modest tree an enormous number of times. A hard cap on
	// fetched roles stops the walk, without an error, once reached. Unlike
	// the depth cap this ends the whole walk: nothing declared after the
	// cut-off is visited. The fetcher synthesises roles on demand so the
	// fixture stays small.
	const (
		totalCap = 4096
		fanOut   = totalCap + 100
	)
	roles := make([]tufmetadata.DelegatedRole, 0, fanOut)
	for i := range fanOut {
		roles = append(roles, dr(fmt.Sprintf("c%d", i), false, "c/*"))
	}
	var fetches int
	fetch := func(_ context.Context, roleName, _ string) (*tufext.SignedTargets, error) {
		fetches++
		if roleName == tufmetadata.TARGETS {
			return signedTargets(nil, roles), nil
		}
		if !strings.HasPrefix(roleName, "c") {
			return nil, fmt.Errorf("unexpected fetch %q", roleName)
		}
		return signedTargets(nil, nil), nil
	}
	got, err := generics.CollectErrorSeq(tufext.IterTargetRoles(t.Context(), fetch))
	require.NoError(t, err, "hitting the total cap must not produce an error")

	// "targets" is the first fetch, so totalCap-1 children are walked, in
	// declared order, before the cap trips.
	assert.Equal(t, totalCap, fetches)
	names := roleNames(got)
	assert.Len(t, names, totalCap)
	assert.Equal(t, tufmetadata.TARGETS, names[0])
	assert.Equal(t, "c0", names[1])
	assert.Equal(t, fmt.Sprintf("c%d", totalCap-2), names[len(names)-1])
	assert.NotContains(t, names, fmt.Sprintf("c%d", totalCap-1))
}

func TestIterTargetRoles_Reusable(t *testing.T) {
	// The returned iter.Seq2 must be safe to range over more than once: each
	// range re-runs the walk from scratch.
	seq := tufext.IterTargetRoles(t.Context(), tufext.TargetsMapFetcher(map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{dr("d1", false, "x/*")}),
		"d1":                signedTargets(nil, nil),
	}))
	for range 2 {
		got, err := generics.CollectErrorSeq(seq)
		require.NoError(t, err)
		assert.Equal(t, []string{tufmetadata.TARGETS, "d1"}, roleNames(got))
	}
}

func TestIterTargetRoles_BreakAfterError(t *testing.T) {
	// Breaking after an error yield must be safe, and the seq must remain
	// reusable on a fresh range loop. "targets" is yielded first, then the
	// missing role produces exactly one error yield and nothing after it.
	seq := tufext.IterTargetRoles(t.Context(), tufext.TargetsMapFetcher(map[string]*tufext.SignedTargets{
		tufmetadata.TARGETS: signedTargets(nil, []tufmetadata.DelegatedRole{dr("missing", false, "x/*")}),
	}))
	for pass, breakOnError := range []bool{true, false} {
		var values, errs int
		for _, err := range seq {
			if err != nil {
				errs++
				if breakOnError {
					break
				}
				continue
			}
			values++
		}
		assert.Equal(t, 1, values, "pass %d: only targets is yielded before the error", pass)
		assert.Equal(t, 1, errs, "pass %d: the error is delivered exactly once", pass)
	}
}

func TestRoleDelegationChain_Match(t *testing.T) {
	// Match is "no terminated chain covers the path" AND "this chain
	// authorises the path". The zero value authorises everything, matching
	// what the top-level role is yielded with.
	var zero tufext.RoleDelegationChain
	assert.True(t, zero.IsTargetPermitted("anything"))

	rc := tufext.RoleDelegationChain{
		ThisChain:        chainOf(dr("d1", false, "a/*", "b/*")),
		TerminatedChains: []tufext.DelegationChain{chainOf(dr("t", true, "a/*"))},
	}
	assert.False(t, rc.IsTargetPermitted("a/x"), "covered by a terminated chain")
	assert.True(t, rc.IsTargetPermitted("b/x"))
	assert.False(t, rc.IsTargetPermitted("c/x"), "not authorised by this chain")
}

// chainOf builds a [tufext.DelegationChain] from the given delegations,
// ordered from the delegation closest to "targets" down to the leaf. Each
// link is recorded under the role that made the delegation: "targets" for the
// first, then the previous link's role name, mirroring how IterTargetRoles
// builds chains.
func chainOf(delegations ...tufmetadata.DelegatedRole) tufext.DelegationChain {
	var chain tufext.DelegationChain
	fromRole := tufmetadata.TARGETS
	for _, delegation := range delegations {
		chain = chain.Extend(fromRole, &delegation)
		fromRole = delegation.Name
	}
	return chain
}

// hashPrefixLen is long enough that two arbitrary test paths landing in the
// same bin is not a realistic concern.
const hashPrefixLen = 8

// hashPrefix returns a PathHashPrefixes entry that go-tuf will treat as
// covering path: the first hashPrefixLen characters of the base64url-encoded
// SHA-256 digest of path.
//
// NOTE: base64url mirrors go-tuf's IsDelegatedPath, which deviates from the
// TUF specification (s4.5 says PATH_HASH_PREFIXES are prefixes of the
// hexadecimal digest, which is what python-tuf and go-tuf v1 implement). If
// go-tuf is fixed to use hex, this helper must change with it.
// <https://github.com/theupdateframework/go-tuf/pull/783>
func hashPrefix(path string) string {
	sum := sha256.Sum256([]byte(path))
	return base64.URLEncoding.EncodeToString(sum[:])[:hashPrefixLen]
}

func TestDelegationChain_ZeroValueMatchesEverything(t *testing.T) {
	// An empty chain represents the top-level "targets" role, which has
	// authority over every path.
	var chain tufext.DelegationChain
	for _, path := range []string{"", "a", "a/b", "deep/er/path.bin"} {
		assert.True(t, chain.IsTargetPermitted(path), "path %q", path)
	}
}

func TestDelegationChain_SingleLink(t *testing.T) {
	chain := chainOf(dr("d1", false, "a/*"))
	assert.True(t, chain.IsTargetPermitted("a/x"))
	assert.False(t, chain.IsTargetPermitted("b/x"), "wrong directory")
	assert.False(t, chain.IsTargetPermitted("a/x/y"), "'*' must not cross '/'")
	assert.False(t, chain.IsTargetPermitted("a"), "component count must match")
}

func TestDelegationChain_PatternsWithinLinkAreOr(t *testing.T) {
	chain := chainOf(dr("d1", false, "a/*", "b/*"))
	assert.True(t, chain.IsTargetPermitted("a/x"))
	assert.True(t, chain.IsTargetPermitted("b/x"))
	assert.False(t, chain.IsTargetPermitted("c/x"))
}

func TestDelegationChain_LinksAreAnd(t *testing.T) {
	// Every link in the chain must match: a path that satisfies the ancestor
	// but not the leaf (or vice versa) is not authorised.
	chain := chainOf(
		dr("d1", false, "a/*/*"),
		dr("d2", false, "a/foo/*"),
	)
	assert.True(t, chain.IsTargetPermitted("a/foo/x"))
	assert.False(t, chain.IsTargetPermitted("a/bar/x"), "matches ancestor only")
	assert.False(t, chain.IsTargetPermitted("b/foo/x"), "matches neither")

	// A leaf whose patterns are wider than its parent's is clamped by the
	// parent.
	wide := chainOf(
		dr("d1", false, "a/foo/*"),
		dr("d2", false, "a/*/*"),
	)
	assert.True(t, wide.IsTargetPermitted("a/foo/x"))
	assert.False(t, wide.IsTargetPermitted("a/bar/x"), "matches leaf only")
}

func TestDelegationChain_LinkWithoutPathsMatchesNothing(t *testing.T) {
	// Unlike an empty chain, a chain containing a delegation with no paths
	// (and no hash prefixes) can never match: that role was delegated
	// nothing.
	chain := chainOf(dr("d1", false /* no paths */))
	assert.False(t, chain.IsTargetPermitted(""))
	assert.False(t, chain.IsTargetPermitted("a"))
	assert.False(t, chain.IsTargetPermitted("a/b"))

	// This holds even when sandwiched between links that do match.
	middle := chainOf(
		dr("d1", false, "a/*"),
		dr("d2", false /* no paths */),
		dr("d3", false, "a/*"),
	)
	assert.False(t, middle.IsTargetPermitted("a/x"))
}

func TestDelegationChain_ExtendNarrowsAuthority(t *testing.T) {
	// Each appended link is one more pattern the path must satisfy, so a
	// longer chain never authorises more than the chain it was derived from.
	// Chains are immutable: Extend derives a new one and leaves the
	// receiver untouched.
	var root tufext.DelegationChain
	require.True(t, root.IsTargetPermitted("b/x"))

	d1 := dr("d1", false, "a/*")
	one := root.Extend(tufmetadata.TARGETS, &d1)
	assert.True(t, one.IsTargetPermitted("a/x"))
	assert.False(t, one.IsTargetPermitted("b/x"))
	assert.True(t, root.IsEmpty(), "receiver must be untouched")
	assert.True(t, root.IsTargetPermitted("b/x"), "receiver must be untouched")

	d2 := dr("d2", false, "a/y")
	two := one.Extend("d1", &d2)
	assert.True(t, two.IsTargetPermitted("a/y"))
	assert.False(t, two.IsTargetPermitted("a/x"))
	assert.Equal(t, 2, two.Length())
	assert.Equal(t, 1, one.Length(), "receiver must be untouched")
	assert.True(t, one.IsTargetPermitted("a/x"), "receiver must be untouched")
}

func TestDelegationChain_IsEmpty(t *testing.T) {
	// Only the root "targets" role has an empty chain, so IsEmpty is how a
	// consumer tells "unrestricted" apart from "restricted to these paths".
	var chain tufext.DelegationChain
	assert.True(t, chain.IsEmpty(), "zero value")

	d1 := dr("d1", false, "a/*")
	child := chain.Extend(tufmetadata.TARGETS, &d1)
	assert.False(t, child.IsEmpty(), "Extend result")
	assert.True(t, chain.IsEmpty(), "Extend must not touch the receiver")
	assert.False(t, child.Extend("d1", &d1).IsEmpty(), "extending a non-empty chain")
}

func TestDelegationChain_ContainsAndLength(t *testing.T) {
	// A chain records the roles that *delegated* along the path, keyed by
	// delegator, so the leaf itself is never a member. IterTargetRoles relies
	// on exactly this for cycle detection: a role is skipped only if it has
	// already delegated on the current path.
	var chain tufext.DelegationChain
	assert.Equal(t, 0, chain.Length())
	assert.False(t, chain.Contains(tufmetadata.TARGETS))

	chain = chainOf(dr("d1", false, "a/*"), dr("d2", false, "a/*")) // targets -> d1 -> d2
	assert.Equal(t, 2, chain.Length())
	assert.True(t, chain.Contains(tufmetadata.TARGETS))
	assert.True(t, chain.Contains("d1"))
	assert.False(t, chain.Contains("d2"), "the leaf has not delegated anything on this path")
	assert.False(t, chain.Contains("unrelated"))
}

func TestDelegationChain_DuplicateDelegatorPanics(t *testing.T) {
	// A path can only pass through a delegator once, so a second delegation
	// under the same role is a programming error rather than a metadata
	// error, and the failed append must leave the receiver untouched.
	d1 := dr("d1", false, "a/*")
	d2 := dr("d2", false, "a/*")
	chain := chainOf(d1) // {targets: d1}
	assert.Panics(t, func() { _ = chain.Extend(tufmetadata.TARGETS, &d2) })
	assert.Equal(t, 1, chain.Length())

	// A different delegator is fine.
	var longer tufext.DelegationChain
	assert.NotPanics(t, func() { longer = chain.Extend("d1", &d2) })
	assert.Equal(t, 2, longer.Length())
	assert.Equal(t, 1, chain.Length())
}

func TestDelegationChain_ExtendNilIsNoop(t *testing.T) {
	// A nil delegation is dropped rather than stored, so Match never has to
	// dereference it (which would panic inside go-tuf) and the chain's
	// authority is unchanged. The nil check also precedes the duplicate
	// delegator check, so a nil under an already-used delegator must not
	// panic either.
	var empty tufext.DelegationChain
	stillEmpty := empty.Extend(tufmetadata.TARGETS, nil)
	assert.True(t, stillEmpty.IsEmpty())
	assert.True(t, stillEmpty.IsTargetPermitted("anything/at/all"))

	d1 := dr("d1", false, "a/*")
	restricted := chainOf(d1) // {targets: d1}
	var same tufext.DelegationChain
	assert.NotPanics(t, func() { same = restricted.Extend(tufmetadata.TARGETS, nil) })
	assert.Equal(t, 1, same.Length())
	assert.True(t, same.IsTargetPermitted("a/x"))
	assert.False(t, same.IsTargetPermitted("b/x"))

	// A nil in the middle of a sequence of appends must not poison the
	// links either side of it.
	d2 := dr("d2", false, "a/y")
	longer := restricted.Extend("d1", nil).Extend("d1", &d2)
	assert.Equal(t, 2, longer.Length())
	assert.True(t, longer.IsTargetPermitted("a/y"))
	assert.False(t, longer.IsTargetPermitted("a/x"))
}

func TestDelegationChain_ExtendDoesNotAliasSiblings(t *testing.T) {
	// Companion to TestIterTargetRoles_DeepDelegationsWithSiblings at the
	// DelegationChain level: two siblings derived from the same parent get
	// their own storage and the parent is untouched. Both siblings are
	// appended under the same delegator, so shared storage would either
	// clobber one leaf or trip the duplicate-delegator check. This is also
	// what exercises the unexported clone: Extend clones before
	// appending, so a clone that shared the map would fail here.
	parent := chainOf(dr("p", false, "shared/*")) // {targets: p}
	leafA := dr("leafA", false, "shared/A")
	leafB := dr("leafB", false, "shared/B")
	a := parent.Extend("p", &leafA)
	b := parent.Extend("p", &leafB)

	assert.True(t, a.IsTargetPermitted("shared/A"))
	assert.False(t, a.IsTargetPermitted("shared/B"), "sibling B clobbered A's leaf")
	assert.True(t, b.IsTargetPermitted("shared/B"))
	assert.False(t, b.IsTargetPermitted("shared/A"), "sibling A clobbered B's leaf")

	// The parent has no leaf restriction and must accept both.
	assert.Equal(t, 1, parent.Length())
	assert.True(t, parent.IsTargetPermitted("shared/A"))
	assert.True(t, parent.IsTargetPermitted("shared/B"))
}

func TestDelegationChain_MalformedPatternNeverMatches(t *testing.T) {
	// go-tuf treats a pattern that filepath.IsTargetPermitted rejects as matching
	// nothing. The matcher that DelegationChain replaced had a
	// literal-equality fast path which would have accepted "a/[b" for
	// itself. We must not diverge from go-tuf here: a mismatch between what
	// the TUF client resolves and what we iterate is exactly the class of
	// bug this type exists to prevent.
	chain := chainOf(dr("d1", false, "a/[b"))
	assert.False(t, chain.IsTargetPermitted("a/[b"))
	assert.False(t, chain.IsTargetPermitted("a/b"))
}

func TestDelegationChain_PathHashPrefixes_Smoke(t *testing.T) {
	// We don't use hash-bin delegations, but DelegationChain.IsTargetPermitted must at
	// least honour them the way go-tuf does, so that a chain containing one
	// can't silently accept everything (or nothing).
	const (
		covered   = "bins/covered.bin"
		uncovered = "bins/uncovered.bin"
	)
	prefix := hashPrefix(covered)
	require.NotEqual(t, prefix, hashPrefix(uncovered), "test paths must land in different bins")

	bin := dr("bin", false /* no paths */)
	bin.PathHashPrefixes = []string{prefix}

	chain := chainOf(bin)
	assert.True(t, chain.IsTargetPermitted(covered))
	assert.False(t, chain.IsTargetPermitted(uncovered))

	// Hash-bin links compose with pattern links like any other link.
	nested := chainOf(dr("d1", false, "bins/*"), bin)
	assert.True(t, nested.IsTargetPermitted(covered))
	assert.False(t, nested.IsTargetPermitted(uncovered))
}

func TestDelegationChain_BothPathsAndHashPrefixes_PathsWin(t *testing.T) {
	// Spec s4.5 requires exactly one of "paths" and "path_hash_prefixes".
	// go-tuf only enforces that when marshalling, so a delegation that
	// arrives with both set is accepted on parse; IsDelegatedPath then
	// consults Paths and ignores PathHashPrefixes entirely. Pin that so a
	// change in go-tuf's precedence (or a hex fix, see hashPrefix) shows up
	// here rather than as a silent change in which role is authorised.
	const hashed = "b/x"
	both := dr("both", false, "a/*")
	both.PathHashPrefixes = []string{hashPrefix(hashed)}

	chain := chainOf(both)
	assert.True(t, chain.IsTargetPermitted("a/x"), "Paths must still be honoured")
	assert.False(t, chain.IsTargetPermitted(hashed), "PathHashPrefixes must be ignored when Paths is set")
}
