// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Amutable GmbH

package tufext

import (
	"context"
	"fmt"
	"io/fs"
	"iter"
	"maps"
	"slices"

	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/generics"
	"go.amutable.dev/quarry/internal/third_party/assert"
)

// DelegationChain represents the chain of TUF delegations that were followed
// to reach a given target role (or file).
//
// If an API returns a [DelegationChain] along with some TUF metadata, users
// must ensure that they use [DelegationChain.IsTargetPermitted] as part of
// ensuring a delegated role cannot provide a file they have no authority to
// provide.
//
// A [DelegationChain] is immutable once created (and may share storage with
// other chains), which is why [DelegationChain.Extend] creates a clone when
// extending the chain.
//
// TODO: This does not currently handle succinct delegations.
type DelegationChain struct {
	// NOTE: The order of iteration doesn't matter for IsTargetPermitted.
	links map[string]*tufmetadata.DelegatedRole
}

// Length returns the number of entries in the [DelegationChain].
func (chain DelegationChain) Length() int {
	return len(chain.links)
}

// IsEmpty returns whether the [DelegationChain] is empty (this can only be
// true for the root "targets" role).
func (chain DelegationChain) IsEmpty() bool {
	return chain.Length() == 0
}

// clone makes a shallow copy of a [DelegationChain]. Not exported because
// [DelegationChain]s are immutable in the public API.
func (chain DelegationChain) clone() DelegationChain {
	return DelegationChain{
		links: maps.Clone(chain.links),
	}
}

// Contains returns true if the given role name was walked through in this
// delegation chain (these are the same role names passed to
// [DelegationChain.Extend]).
func (chain DelegationChain) Contains(roleName string) bool {
	return generics.MapContains(chain.links, roleName)
}

// Extend returns a copy of the [DelegationChain] with the given delegation
// appended, indicating that the delegation came from the given role. The
// receiver is left untouched. This function will panic if several delegations
// from the same role are appended.
func (chain DelegationChain) Extend(fromRole string, delegations ...*tufmetadata.DelegatedRole) DelegationChain {
	clone := chain.clone()
	for _, delegation := range delegations {
		if delegation == nil {
			continue
		}
		assert.Assertf(!chain.Contains(fromRole),
			"DelegationChain must not have the same role %q inserted multiple times", fromRole)
		if clone.links == nil {
			clone.links = make(map[string]*tufmetadata.DelegatedRole, 32)
		}
		clone.links[fromRole] = delegation
	}
	return clone
}

// IsTargetPermitted returns whether the [DelegationChain] (of a targets role)
// is authorised to provide a target with the given path. An empty
// [DelegationChain] will match any path, as it represents the root "targets"
// role.
func (chain DelegationChain) IsTargetPermitted(targetPath string) bool {
	for _, delegation := range chain.links {
		// NOTE: go-tuf internally uses filepath.Match which actually accepts
		// more things than the spec allows. This is really not ideal but for
		// now we need to just accept that they do it that way so that fetching
		// a target is consistent.
		// <https://github.com/theupdateframework/go-tuf/security/advisories/GHSA-qr6c-8mjc-hpp5>
		if ok, err := delegation.IsDelegatedPath(targetPath); !ok || err != nil {
			return false
		}
	}
	return true
}

// TargetMetadataFetchFunc is a helper function for [IterTargetRoles] (and thus
// [IterTargetFiles]) which is called to fetch a particular target role by
// name.
//
// For [tuftrustedmetadata.TrustedMetadata] backends it provides the necessary
// information to be able to automatically verify the corresponding target
// file, and such backends are expected to validate the data before returning
// it.
//
// TODO: Maybe we should make this return generic role data so that we can
// fetch "root" in [IterTargetRoles] and do the validation there regardless of
// the [TargetMetadataFetchFunc] implementation?
type TargetMetadataFetchFunc = func(ctx context.Context, roleName, delegatorName string) (*SignedTargets, error)

// TargetsMapFetcher returns a [TargetMetadataFetchFunc] backed by the provided
// map, for use with [IterTargetRoles] or [IterTargetFiles] when all of the
// target role metadata has already been pre-loaded by a user.
func TargetsMapFetcher(targets map[string]*SignedTargets) TargetMetadataFetchFunc {
	return func(_ context.Context, roleName, _ string) (*SignedTargets, error) {
		role, ok := targets[roleName]
		if !ok {
			return nil, fmt.Errorf("role %s: %w", roleName, fs.ErrNotExist)
		}
		return role, nil
	}
}

// RoleDelegationChain describes the [DelegationChain] that [IterTargetRoles]
// encountered when reaching a target role as well as the target role itself.
//
// Aside from the obvious bits of information (the target role name, data, and
// [DelegationChain] used to reach the role), this structure also provides
// information about the set of terminating delegations reached up to this
// point in [IterTargetRoles]. As this information is very security-critical,
// callers that plan to yield target files from this role *MUST* use
// [RoleDelegationChain.IsTargetPermitted] to filter out forbidden target files
// so that terminating delegations are respected correctly.
//
// Note that the [DelegationChain] used to reach a target role might not be
// unique, as roles can be delegated to via several distinct chains (though
// this usage is quite rare in practice).
type RoleDelegationChain struct {
	// Name is the name of the delegated target role. "targets" is the
	// top-level targets role.
	Name string
	// Role is the [SignedTargets] data for this role, as returned by the
	// corresponding [TargetMetadataFetchFunc] call. This value must be treated
	// as read-only.
	Role *SignedTargets
	// ThisChain is the [DelegationChain] used to reach this role.
	ThisChain DelegationChain
	// TerminatedChains is the set of [DelegationChain] to terminating roles up
	// until now in the iteration of target roles -- target files that match
	// these terminated chains *MUST NOT BE YIELDED*. This is used by
	// [RoleDelegationChain.IsTargetPermitted].
	TerminatedChains []DelegationChain
}

// IsTargetPermitted returns whether the [RoleDelegationChain] reached during
// an [IterTargetRoles] walk is authorised to provide a target with the given
// path. Users that yield target files when iterating over [IterTargetRoles]
// *MUST* make use of this method.
func (chain RoleDelegationChain) IsTargetPermitted(targetPath string) bool {
	if !chain.ThisChain.IsTargetPermitted(targetPath) {
		return false
	}
	for _, badChain := range chain.TerminatedChains {
		// A permitted target path is *bad* for terminated chains!
		if badChain.IsTargetPermitted(targetPath) {
			return false
		}
	}
	return true
}

// IterTargetRoles iterates over all target roles from a single repository in a
// pre-order depth-first traversal order (as defined in s5.6.7 of the TUF
// specification).
//
// The provided [TargetMetadataFetchFunc] is called each time a target's role
// metadata needs to be loaded.
//
// Users that yield target files when iterating over [IterTargetRoles] *MUST*
// make use of [RoleDelegationChain.IsTargetPermitted] to ensure they do not
// violate the security properties of terminating delegations in TUF. Note that
// it is possible for the same role to be reached via different
// [DelegationChain]s, in which case [IterTargetRoles] will yield the same role
// multiple times.
func IterTargetRoles(ctx context.Context, fetchFn TargetMetadataFetchFunc) iter.Seq2[RoleDelegationChain, error] {
	// TODO: Pass these in as configuration so that this matches tufclient's
	// limits exactly and potentially works better with links?
	const (
		maxDelegationDepth = 32 // go-tuf default limit
		maxDelegations     = 4096
	)
	return generics.ErrorIter(func(yield func(RoleDelegationChain) bool) error {
		// roleTodo indicates that we need to walk into the given role.
		type roleTodo struct {
			name, delegator string
			// The delegation chain followed to reach this role. Target files
			// provided by this role are only valid if every link authorises it
			// (the top-level "targets" role authorises everything).
			chain DelegationChain
		}

		// Once we hit a terminating delegation we need to make sure that the
		// paths it matches cannot be yielded afterwards.
		terminatedDelegationChains := make([]DelegationChain, 0, 128)
		// terminationTodo is a marker to indicate terminatedDelegationChains
		// needs to be updated to include this DelegationChain. This needs be
		// deferred this way because s4.5 of the TUF spec allows for child
		// delegations of a terminating delegation to match terminating paths
		// -- meaning that the DelegationChain cannot be added to the set of
		// forbidden patterns until all child delegations have been processed.
		type terminationTodo DelegationChain

		var seenDelegations int
		// Stack of remaining delegations to visit.
		todo := []any{roleTodo{
			name:      tufmetadata.TARGETS,
			delegator: tufmetadata.ROOT,
		}}
	roles:
		for len(todo) > 0 {
			next := todo[len(todo)-1]
			todo = todo[:len(todo)-1]

			var thisRole roleTodo
			switch next := next.(type) {
			case terminationTodo:
				terminatedDelegationChains = append(terminatedDelegationChains, DelegationChain(next))
				continue roles
			case roleTodo:
				thisRole = next
			default:
				panic(fmt.Sprintf("unexpected type %T", next))
			}

			// s5.6.7.1 places several restrictions on walking into delegations
			// to avoid unbounded loops or DoSes:
			switch {
			// Skip walking into roles that were already seen in this
			// delegation chain, to avoid cycles.
			//
			// TODO: The current text of the TUF specification (s5.6.7.1)
			// implies that this needs to be a global seen list but based on
			// recent upstream discussions, do it this way instead.
			// See <https://github.com/theupdateframework/specification/issues/321>.
			case thisRole.chain.Contains(thisRole.name):
				continue roles

			// When fetching a target file, if you hit too many delegations you
			// need to stop iterating and just return *without an error* (to
			// avoid a DoS). This is a global limit for each target file
			// lookup.
			//
			// TODO(links): We must make sure that the delegation iteration
			// limits here apply to links so links don't reset the delegation
			// depth restriction.
			//
			// Unfortunately, we cannot really guarantee the exact same
			// behaviour when iterating over delegations because we are
			// effectively emulating a virtual lookup for *all* target files.
			// The completely "correct" mechanism would be to track the degree
			// of overlap between different delegation path patterns (good luck
			// with hash-based delegations) and restrict iteration based on
			// that, but that is not really workable. I think we just have to
			// accept that we will iterate over delegations that are not
			// reachable when actually fetching. This issue was briefly
			// mentioned in <https://github.com/theupdateframework/specification/issues/321>.
			//
			// So, we have two heuristics to try to have somewhat reasonable
			// behaviour:
			case thisRole.chain.Length() > maxDelegationDepth:
				// 1. Skip delegation chains longer than maxDelegationDepth,
				// as they would be skipped by clients as per s5.6.7.1.
				//
				// TODO(log): Add logging...?
				continue roles
			case seenDelegations >= maxDelegations:
				// 2. Add a hard upper bound on the number of total delegations
				// in a repository. This might not violate s5.6.7.1 but such a
				// repository is clearly "wrong". If we didn't do this, a bad
				// repository could create one 32-deep delegation tree then
				// delegate to it millions of times.
				//
				// TODO: Find a better solution.
				// TODO(log): Add logging...?
				break roles
			}
			role, err := fetchFn(ctx, thisRole.name, thisRole.delegator)
			if err != nil {
				return fmt.Errorf("target role walk aborted: failed to get role %s: %w", thisRole.name, err)
			}
			// TODO: Validate the delegation signatures here as well (the real
			// fetchFn used by clients does so implicitly but we should do it
			// for everything -- though "targets" might be a bit tricky to
			// validate since we don't have the root here). This might also
			// allow us to skip bad delegations...?
			seenDelegations++

			val := RoleDelegationChain{
				Name:      thisRole.name,
				Role:      role,
				ThisChain: thisRole.chain,
				// terminatedDelegationChains gets mutated later so use a copy.
				TerminatedChains: slices.Clone(terminatedDelegationChains),
			}
			if !yield(val) {
				return nil
			}

			// Now append the set of delegations to the todo queue.
			if delegations := role.Signed.Delegations; delegations != nil {
				// TODO: Supporting this would require more work in
				// DelegationChain to properly support, and we do not support
				// this in the rest of tufrepo and tufext anyway.
				if delegations.SuccinctRoles != nil {
					return fmt.Errorf("role %s uses succinct roles: unsupported feature", thisRole.name)
				}
				// Append the delegations in reverse order so the first entry
				// ends up at the top of the stack (tail of todo), to match
				// s5.6.7 of the TUF spec.
				for delegatedRole := range generics.ReverseIter(delegations.Roles) {
					// TODO: In principle we support path hash prefixes since
					// DelegationChain.IsTargetPermitted uses go-tuf's matching
					// logic, but go-tuf upstream has a bug in how they compute
					// these hashes and so we are best to disallow them for
					// now. <https://github.com/theupdateframework/go-tuf/pull/783>
					if len(delegatedRole.PathHashPrefixes) > 0 {
						return fmt.Errorf("role %s uses path prefixes: unsupported feature", delegatedRole.Name)
					}
					newChain := thisRole.chain.Extend(thisRole.name, &delegatedRole)
					// If this is a terminating delegation then we need to
					// push a termination marker beneath the role so that roles
					// already on the todo stack (i.e., later siblings and
					// ancestors' later siblings) cannot provide matching
					// targets, while children of this role (pushed above the
					// marker) still can, to match s4.5 of the TUF spec.
					if delegatedRole.Terminating {
						todo = append(todo, terminationTodo(newChain))
					}
					todo = append(todo, roleTodo{
						name:      delegatedRole.Name,
						delegator: thisRole.name,
						chain:     newChain,
					})
				}
			}
		}
		return nil
	})
}
