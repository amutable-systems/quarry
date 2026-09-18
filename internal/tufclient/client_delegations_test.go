// Copyright (C) 2026 Amutable GmbH

package tufclient_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"io/fs"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tufmetadata "github.com/theupdateframework/go-tuf/v2/metadata"

	"go.amutable.dev/quarry/internal/testrepo"
	"go.amutable.dev/quarry/internal/tufext"
	"go.amutable.dev/quarry/internal/tufrepo"
)

// roleKey is an in-memory ed25519 key for a delegated targets role. Delegated
// roles are signed directly rather than through the server's keystore so a
// test can control exactly which keys each delegator trusts.
type roleKey struct {
	priv ed25519.PrivateKey
	pub  *tufmetadata.Key
	id   string
}

func newRoleKey(t *testing.T) *roleKey {
	t.Helper()
	pubKey, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pub, err := tufmetadata.KeyFromPublicKey(pubKey)
	require.NoError(t, err)
	id, err := pub.ID()
	require.NoError(t, err)
	return &roleKey{priv: priv, pub: pub, id: id}
}

// sign adds a signature over meta.Signed, replacing any earlier signature by
// the same key.
func (key *roleKey) sign(t *testing.T, meta *tufext.SignedTargets) {
	t.Helper()
	payload, err := cjson.EncodeCanonical(meta.Signed)
	require.NoError(t, err)
	meta.Signatures = slices.DeleteFunc(meta.Signatures, func(sig tufmetadata.Signature) bool {
		return sig.KeyID == key.id
	})
	meta.Signatures = append(meta.Signatures, tufmetadata.Signature{
		KeyID:     key.id,
		Signature: ed25519.Sign(key.priv, payload),
	})
}

// delegatedRole describes a delegated targets role to be created by
// delegationsOp: its targets and the keys that sign it.
type delegatedRole struct {
	name    string
	targets map[string]*tufmetadata.TargetFiles
	signers []*roleKey
}

// delegation describes one edge of the delegation graph: from delegates the
// given paths to to, trusting keys (threshold 1) to sign it.
type delegation struct {
	from, to string
	paths    []string
	keys     []*roleKey
}

// delegationsOp returns a TxnOp that creates the given delegated roles and
// adds the given delegation edges. Roles named in edges but not in roles must
// already exist in the transaction (or be "targets"); they are re-read,
// extended, and written back. Every role in roles is fully assembled (targets
// and outgoing delegations) before it is signed, so its signatures are valid
// at Sign time and the transaction does not need keystore keys for it.
func delegationsOp(t *testing.T, roles []delegatedRole, edges []delegation) tufrepo.TxnOp {
	return tufrepo.NewTxnOp("test: install delegations", func(ctx context.Context, tx *tufrepo.Transaction) error {
		metas := make(map[string]*tufext.SignedTargets, len(roles)+1)
		signers := make(map[string][]*roleKey, len(roles))
		for _, role := range roles {
			meta := tufext.DefaultTargets(tx.RefTime.Add(tufrepo.DefaultTargetsExpiry))
			meta.Signed.Version = 1
			for path, target := range role.targets {
				meta.Signed.Targets[path] = target
			}
			metas[role.name] = meta
			signers[role.name] = role.signers
		}
		for _, edge := range edges {
			delegator, ok := metas[edge.from]
			if !ok {
				existing, err := tx.TargetsRoleData(ctx, edge.from)
				if err != nil {
					return err
				}
				delegator, metas[edge.from] = existing, existing
			}
			if delegator.Signed.Delegations == nil {
				delegator.Signed.Delegations = &tufmetadata.Delegations{
					Keys: make(map[string]*tufmetadata.Key),
				}
			}
			keyIDs := make([]string, 0, len(edge.keys))
			for _, key := range edge.keys {
				delegator.Signed.Delegations.Keys[key.id] = key.pub
				keyIDs = append(keyIDs, key.id)
			}
			delegator.Signed.Delegations.Roles = append(delegator.Signed.Delegations.Roles, tufmetadata.DelegatedRole{
				Name:      edge.to,
				KeyIDs:    keyIDs,
				Threshold: 1,
				Paths:     edge.paths,
			})
		}
		for name, meta := range metas {
			for _, key := range signers[name] {
				key.sign(t, meta)
			}
			if err := tx.UpdateRoleData(name, meta); err != nil {
				return err
			}
		}
		return nil
	})
}

// countMetaFetches serves the repository metadata itself (at the "meta"
// subdirectory, which the server must have been created with) and counts
// requests for the given role's versioned metadata file.
func countMetaFetches(srv *testrepo.Server, roleName string) *atomic.Int32 {
	var count atomic.Int32
	suffix := "." + roleName + ".json"
	// A single-segment wildcard is more specific than the server's "/meta/"
	// catch-all, so it takes over metadata requests.
	srv.Handle("/meta/{file}", http.HandlerFunc(func(wtr http.ResponseWriter, req *http.Request) {
		file := req.PathValue("file")
		if strings.HasSuffix(file, suffix) {
			count.Add(1)
		}
		rdr, _, err := srv.Repo.GetBlob(req.Context(), file)
		if err != nil {
			http.NotFound(wtr, req)
			return
		}
		defer func() { _ = rdr.Close() }()
		_, _ = io.Copy(wtr, rdr)
	}))
	return &count
}

// Diamond: targets -> a (x/*) and targets -> b (y/*) both delegate to
// "shared", which is signed by a key both delegators trust. Per-path cycle
// detection walks "shared" twice, so both x/file (reachable only via a) and
// y/file (only via b) are listed, but the fetcher must download shared.json
// only once and re-verify the cached copy against b's delegation.
func TestClient_DelegationDiamond_SharedFetchedOnce(t *testing.T) {
	srv := testrepo.New(t, testrepo.WithMetaSubdir("meta"))
	sharedFetches := countMetaFetches(srv, "shared")

	keyA, keyB, keyShared := newRoleKey(t), newRoleKey(t), newRoleKey(t)
	xFile := srv.WriteTarget(t, "x/file", bytes.NewReader([]byte("x")))
	yFile := srv.WriteTarget(t, "y/file", bytes.NewReader([]byte("y")))
	srv.Publish(t, delegationsOp(t,
		[]delegatedRole{
			{name: "a", signers: []*roleKey{keyA}},
			{name: "b", signers: []*roleKey{keyB}},
			{name: "shared", signers: []*roleKey{keyShared}, targets: map[string]*tufmetadata.TargetFiles{
				"x/file": xFile,
				"y/file": yFile,
			}},
		},
		[]delegation{
			{from: tufmetadata.TARGETS, to: "a", paths: []string{"x/*"}, keys: []*roleKey{keyA}},
			{from: tufmetadata.TARGETS, to: "b", paths: []string{"y/*"}, keys: []*roleKey{keyB}},
			{from: "a", to: "shared", paths: []string{"x/*", "y/*"}, keys: []*roleKey{keyShared}},
			{from: "b", to: "shared", paths: []string{"x/*", "y/*"}, keys: []*roleKey{keyShared}},
		},
	))

	client := newClient(t, testrepo.Config(t, srv.ConfigBlock("diamond")))
	var paths []string
	for info, err := range client.IterTargetFiles(t.Context()) {
		require.NoError(t, err)
		paths = append(paths, info.Path)
	}
	slices.Sort(paths)
	assert.Equal(t, []string{"x/file", "y/file"}, paths)
	assert.Equal(t, int32(1), sharedFetches.Load(), "shared.json must be downloaded once and served from the trusted set afterwards")
}

// The same diamond, but b trusts a key that never signed "shared". A real
// go-tuf lookup of y/file goes through b and fails verification, so the walk
// must not list y/file on the strength of a's trust: the cached copy is
// re-verified against b and the failure aborts the walk.
//
// Delegation keys come from the delegatee's publisher and are recorded by the
// delegator, so a mismatch like this is a publisher error rather than a
// supported configuration. The client-side abort is the security measure; it
// is not something the repository tooling is expected to catch, which is why
// the second transaction publishes without complaint.
func TestClient_DelegationDiamond_ReverifyFailureAborts(t *testing.T) {
	srv := testrepo.New(t, testrepo.WithMetaSubdir("meta"))

	keyA, keyB, keyShared, keyWrong := newRoleKey(t), newRoleKey(t), newRoleKey(t), newRoleKey(t)
	xFile := srv.WriteTarget(t, "x/file", bytes.NewReader([]byte("x")))
	yFile := srv.WriteTarget(t, "y/file", bytes.NewReader([]byte("y")))
	srv.Publish(t, delegationsOp(t,
		[]delegatedRole{
			{name: "a", signers: []*roleKey{keyA}},
			{name: "shared", signers: []*roleKey{keyShared}, targets: map[string]*tufmetadata.TargetFiles{
				"x/file": xFile,
				"y/file": yFile,
			}},
		},
		[]delegation{
			{from: tufmetadata.TARGETS, to: "a", paths: []string{"x/*"}, keys: []*roleKey{keyA}},
			{from: "a", to: "shared", paths: []string{"x/*", "y/*"}, keys: []*roleKey{keyShared}},
		},
	))
	srv.Publish(t, delegationsOp(t,
		[]delegatedRole{
			{name: "b", signers: []*roleKey{keyB}},
		},
		[]delegation{
			{from: tufmetadata.TARGETS, to: "b", paths: []string{"y/*"}, keys: []*roleKey{keyB}},
			{from: "b", to: "shared", paths: []string{"x/*", "y/*"}, keys: []*roleKey{keyWrong}},
		},
	))

	client := newClient(t, testrepo.Config(t, srv.ConfigBlock("diamond")))
	var paths []string
	var walkErr error
	for info, err := range client.IterTargetFiles(t.Context()) {
		if err != nil {
			walkErr = err
			break
		}
		paths = append(paths, info.Path)
	}
	require.Error(t, walkErr)
	assert.Contains(t, walkErr.Error(), "shared", "the error must name the role that failed re-verification")
	assert.Equal(t, []string{"x/file"}, paths, "the a-path is walked first and is still trusted; y/file must never appear")
}

// Within one repository a path provided by several roles is listed from the
// first role a lookup would reach: the top-level role outranks delegations,
// and delegations rank in declared order (s5.6.7). go-tuf's real lookup must
// agree with the listing. Distinct content lengths identify each role's entry.
func TestClient_DelegationPriority_FirstRoleWins(t *testing.T) {
	srv := testrepo.New(t, testrepo.WithMetaSubdir("meta"))
	keyD1, keyD2 := newRoleKey(t), newRoleKey(t)
	write := func(path, data string) *tufmetadata.TargetFiles {
		return srv.WriteTarget(t, path, bytes.NewReader([]byte(data)))
	}
	topShared := write("x/shared", "T")
	d1Shared, d1Both := write("x/shared", "D1"), write("x/both", "D1")
	d2Shared, d2Both := write("x/shared", "D22"), write("x/both", "D22")
	srv.Publish(t,
		testrepo.AddTargetOp("x/shared", topShared),
		delegationsOp(t,
			[]delegatedRole{
				{name: "d1", signers: []*roleKey{keyD1}, targets: map[string]*tufmetadata.TargetFiles{
					"x/shared": d1Shared, "x/both": d1Both, "x/only-d1": write("x/only-d1", "1"),
				}},
				{name: "d2", signers: []*roleKey{keyD2}, targets: map[string]*tufmetadata.TargetFiles{
					"x/shared": d2Shared, "x/both": d2Both, "x/only-d2": write("x/only-d2", "2"),
				}},
			},
			[]delegation{
				{from: tufmetadata.TARGETS, to: "d1", paths: []string{"x/*"}, keys: []*roleKey{keyD1}},
				{from: tufmetadata.TARGETS, to: "d2", paths: []string{"x/*"}, keys: []*roleKey{keyD2}},
			},
		),
	)

	client := newClient(t, testrepo.Config(t, srv.ConfigBlock("priority")))
	lengths := make(map[string]int64)
	for info, err := range client.IterTargetFiles(t.Context()) {
		require.NoError(t, err)
		_, dup := lengths[info.Path]
		require.False(t, dup, "path %s listed twice", info.Path)
		lengths[info.Path] = info.Length
	}
	assert.Equal(t, map[string]int64{
		"x/shared":  topShared.Length, // targets outranks both delegations
		"x/both":    d1Both.Length,    // d1 is declared before d2
		"x/only-d1": 1,
		"x/only-d2": 1,
	}, lengths)

	for path, want := range map[string]int64{"x/shared": topShared.Length, "x/both": d1Both.Length} {
		info, err := client.GetTargetInfo(t.Context(), path)
		require.NoError(t, err)
		assert.Equal(t, want, info.Length, "lookup of %s must agree with the listing", path)
	}
}

// A terminating delegation stops later roles from providing the paths it
// covers (s4.5), even when the terminating role itself lacks the target. The
// listing must exclude such targets, and go-tuf's real lookup must fail to
// find them, while paths outside the terminating patterns are unaffected.
func TestClient_TerminatingDelegation_BlocksLaterRole(t *testing.T) {
	srv := testrepo.New(t, testrepo.WithMetaSubdir("meta"))
	keyTerm, keyLater := newRoleKey(t), newRoleKey(t)
	write := func(path string) *tufmetadata.TargetFiles {
		return srv.WriteTarget(t, path, bytes.NewReader([]byte(path)))
	}
	srv.Publish(t, delegationsOp(t,
		[]delegatedRole{
			{name: "term", signers: []*roleKey{keyTerm}, targets: map[string]*tufmetadata.TargetFiles{
				"x/in-term": write("x/in-term"),
			}},
			{name: "later", signers: []*roleKey{keyLater}, targets: map[string]*tufmetadata.TargetFiles{
				"x/from-later": write("x/from-later"), // covered by term's terminating x/*
				"z/free":       write("z/free"),       // outside it
			}},
		},
		[]delegation{
			{from: tufmetadata.TARGETS, to: "term", paths: []string{"x/*"}, keys: []*roleKey{keyTerm}},
			{from: tufmetadata.TARGETS, to: "later", paths: []string{"x/*", "z/*"}, keys: []*roleKey{keyLater}},
		},
	))
	// delegationsOp does not expose the terminating flag; set it on the
	// published metadata in a second transaction so the fixture stays small.
	srv.Publish(t, tufrepo.NewTxnOp("test: mark term terminating", func(ctx context.Context, tx *tufrepo.Transaction) error {
		top, err := tx.TargetsRoleData(ctx, tufmetadata.TARGETS)
		if err != nil {
			return err
		}
		for i := range top.Signed.Delegations.Roles {
			if top.Signed.Delegations.Roles[i].Name == "term" {
				top.Signed.Delegations.Roles[i].Terminating = true
			}
		}
		return tx.UpdateRoleData(tufmetadata.TARGETS, top)
	}))

	client := newClient(t, testrepo.Config(t, srv.ConfigBlock("terminating")))
	var paths []string
	for info, err := range client.IterTargetFiles(t.Context()) {
		require.NoError(t, err)
		paths = append(paths, info.Path)
	}
	slices.Sort(paths)
	assert.Equal(t, []string{"x/in-term", "z/free"}, paths)

	_, err := client.GetTargetInfo(t.Context(), "x/from-later")
	require.ErrorIs(t, err, fs.ErrNotExist, "go-tuf's lookup must also stop at the terminating delegation")
	_, err = client.GetTargetInfo(t.Context(), "z/free")
	require.NoError(t, err)
}
