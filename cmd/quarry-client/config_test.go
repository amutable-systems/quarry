// Copyright (C) 2026 Amutable GmbH

package main

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func repoBlock(rootTrust string) string {
	return `
[repo.example]
` + rootTrust + `
meta_root_url = "https://example.com/repo"
data_root_url = "https://example.com/data"
`
}

func TestParseConfig_RootTrust_Valid(t *testing.T) {
	for _, tc := range []struct {
		name      string
		rootTrust string
		want      RootTrustSource
	}{
		{
			name:      "TofuPlainString",
			rootTrust: `root_trust = "insecure-tofu"`,
			want:      tofuRootTrust{},
		},
		{
			name:      "TofuInlineTable",
			rootTrust: `root_trust = { type = "insecure-tofu" }`,
			want:      tofuRootTrust{},
		},
		{
			name:      "BundledInlineTable",
			rootTrust: `root_trust = { type = "bundled", path = "/etc/root.json" }`,
			want:      bundledRootTrust{Path: "/etc/root.json"},
		},
		{
			name:      "BundledEmptyPath",
			rootTrust: `root_trust = { type = "bundled", path = "" }`,
			want:      bundledRootTrust{Path: ""},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf, err := parseConfig(strings.NewReader(repoBlock(tc.rootTrust)))
			require.NoError(t, err)
			require.Contains(t, conf.Repos, "example")
			require.NotNil(t, conf.Repos["example"].RootTrust)
			assert.Equal(t, tc.want, conf.Repos["example"].RootTrust.RootTrustSource)
		})
	}
}

func TestParseConfig_RootTrust_Invalid(t *testing.T) {
	for _, tc := range []struct {
		name      string
		rootTrust string
		wantErr   string
	}{
		{
			name:      "BundledPlainString",
			rootTrust: `root_trust = "bundled"`,
			wantErr:   `cannot be instantiated using a plain string`,
		},
		{
			name:      "UnknownPlainString",
			rootTrust: `root_trust = "no-such-mode"`,
			wantErr:   `invalid root_trust value`,
		},
		{
			name:      "EmptyString",
			rootTrust: `root_trust = ""`,
			wantErr:   `invalid root_trust value`,
		},
		{
			name:      "InlineTableMissingType",
			rootTrust: `root_trust = { path = "/etc/root.json" }`,
			wantErr:   `must contain "type" field`,
		},
		{
			name:      "InlineTableNonStringType",
			rootTrust: `root_trust = { type = 42 }`,
			wantErr:   `"type" must be string`,
		},
		{
			name:      "InlineTableUnknownType",
			rootTrust: `root_trust = { type = "no-such-mode" }`,
			wantErr:   `unsupported root_trust type "no-such-mode"`,
		},
		{
			name:      "BundledMissingPath",
			rootTrust: `root_trust = { type = "bundled" }`,
			wantErr:   `missing required field "path"`,
		},
		{
			name:      "BundledNonStringPath",
			rootTrust: `root_trust = { type = "bundled", path = 7 }`,
			wantErr:   `"path" has unsupported value type`,
		},
		{
			name:      "BundledExtraField",
			rootTrust: `root_trust = { type = "bundled", path = "/x", extra = "y" }`,
			wantErr:   `unsupported fields: [extra]`,
		},
		{
			name:      "TofuExtraField",
			rootTrust: `root_trust = { type = "insecure-tofu", path = "/x" }`,
			wantErr:   `unsupported fields: [path]`,
		},
		{
			name:      "Integer",
			rootTrust: `root_trust = 42`,
			wantErr:   `unsupported toml type int64`,
		},
		{
			name:      "Array",
			rootTrust: `root_trust = ["insecure-tofu"]`,
			wantErr:   `unsupported toml type []`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseConfig(strings.NewReader(repoBlock(tc.rootTrust)))
			require.Error(t, err)
			assert.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestParseConfig_Empty(t *testing.T) {
	conf, err := parseConfig(strings.NewReader(""))
	require.NoError(t, err)
	assert.Empty(t, conf.Repos)
}

func TestParseConfig_RepoMissingRootTrust(t *testing.T) {
	_, err := parseConfig(strings.NewReader(`
[repo.example]
meta_root_url = "https://example.com"
`))
	require.Error(t, err)
	assert.ErrorContains(t, err, "missing root_trust specification")
}

func TestParseConfig_RepoNameFromKey(t *testing.T) {
	conf, err := parseConfig(strings.NewReader(`
[repo."updates.example.com/alpha"]
root_trust = "insecure-tofu"
meta_root_url = "https://example.com"
`))
	require.NoError(t, err)
	require.Contains(t, conf.Repos, "updates.example.com/alpha")
	assert.Equal(t, "updates.example.com/alpha", conf.Repos["updates.example.com/alpha"].Name)
}

func TestParseConfig_DefaultMetaRootURL(t *testing.T) {
	conf, err := parseConfig(strings.NewReader(`
[repo."updates.example.com/alpha"]
root_trust = "insecure-tofu"
`))
	require.NoError(t, err)
	repo := conf.Repos["updates.example.com/alpha"]
	require.NotNil(t, repo.MetaRootURL)
	assert.Equal(t, "https://updates.example.com/alpha", repo.MetaRootURL.String())
	require.NotNil(t, repo.DataRootURL)
	assert.Equal(t, "https://updates.example.com/alpha/targets", repo.DataRootURL.String())
}

func TestParseConfig_DefaultDataRootURL(t *testing.T) {
	conf, err := parseConfig(strings.NewReader(`
[repo.example]
root_trust = "insecure-tofu"
meta_root_url = "https://meta.example.com/sub"
`))
	require.NoError(t, err)
	repo := conf.Repos["example"]
	assert.Equal(t, "https://meta.example.com/sub", repo.MetaRootURL.String())
	require.NotNil(t, repo.DataRootURL)
	assert.Equal(t, "https://meta.example.com/sub/targets", repo.DataRootURL.String())
}

func TestParseConfig_CustomURLs(t *testing.T) {
	conf, err := parseConfig(strings.NewReader(`
[repo.example]
root_trust = "insecure-tofu"
meta_root_url = "https://meta.example.com"
data_root_url = "https://data.example.com/blobs"
`))
	require.NoError(t, err)
	repo := conf.Repos["example"]
	assert.Equal(t, "https://meta.example.com", repo.MetaRootURL.String())
	assert.Equal(t, "https://data.example.com/blobs", repo.DataRootURL.String())
}

func TestParseConfig_MultipleRepos(t *testing.T) {
	conf, err := parseConfig(strings.NewReader(`
[repo.alpha]
root_trust = "insecure-tofu"
meta_root_url = "https://alpha.example.com"

[repo.beta]
root_trust = { type = "bundled", path = "/etc/beta-root.json" }
meta_root_url = "https://beta.example.com"
data_root_url = "https://beta.example.com/data"
`))
	require.NoError(t, err)
	require.Len(t, conf.Repos, 2)

	require.Contains(t, conf.Repos, "alpha")
	assert.Equal(t, "alpha", conf.Repos["alpha"].Name)
	assert.Equal(t, tofuRootTrust{}, conf.Repos["alpha"].RootTrust.RootTrustSource)
	assert.Equal(t, "https://alpha.example.com/targets", conf.Repos["alpha"].DataRootURL.String())

	require.Contains(t, conf.Repos, "beta")
	assert.Equal(t, "beta", conf.Repos["beta"].Name)
	assert.Equal(t, bundledRootTrust{Path: "/etc/beta-root.json"}, conf.Repos["beta"].RootTrust.RootTrustSource)
	assert.Equal(t, "https://beta.example.com/data", conf.Repos["beta"].DataRootURL.String())
}

func TestParseConfig_UnknownTopLevelKey(t *testing.T) {
	_, err := parseConfig(strings.NewReader(`
some_unknown_key = "value"

[repo.example]
root_trust = "insecure-tofu"
meta_root_url = "https://example.com"
`))
	require.Error(t, err)
	assert.ErrorContains(t, err, "unknown toml keys")
}

func TestParseConfig_UnknownRepoKey(t *testing.T) {
	_, err := parseConfig(strings.NewReader(`
[repo.example]
root_trust = "insecure-tofu"
meta_root_url = "https://example.com"
not_a_real_field = "oops"
`))
	require.Error(t, err)
	assert.ErrorContains(t, err, "unknown toml keys")
}

func TestParseConfig_InvalidTOML(t *testing.T) {
	_, err := parseConfig(strings.NewReader("this is not = valid = toml ="))
	require.Error(t, err)
	assert.ErrorContains(t, err, "invalid config")
}

func TestParseConfig_BadURL(t *testing.T) {
	// [toml.ParseError] has no Unwrap so [errors.As] cannot reach the
	// underlying [url.EscapeError]; match a structural substring instead.
	_, err := parseConfig(strings.NewReader(`
[repo.example]
root_trust = "insecure-tofu"
meta_root_url = "https://example.com/%zz"
`))
	require.Error(t, err)
	assert.ErrorContains(t, err, "meta_root_url")
}

func TestParseConfig_ExampleFile(t *testing.T) {
	f, err := os.Open("../../contrib/quarry-client.toml") //nolint:forbidigo // test code
	require.NoError(t, err)
	defer f.Close() //nolint:errcheck // test code

	conf, err := parseConfig(f)
	require.NoError(t, err)

	const repoName = "updates.example.com/alpha"
	require.Contains(t, conf.Repos, repoName)
	repo := conf.Repos[repoName]

	assert.Equal(t, repoName, repo.Name)
	assert.Equal(t,
		bundledRootTrust{Path: "/usr/share/amutable-os/updates.example.com-alpha-root.json"},
		repo.RootTrust.RootTrustSource)
	assert.Equal(t, "https://updates.example.com/alpha", repo.MetaRootURL.String())
	assert.Equal(t, "https://updates.example.com/update", repo.DataRootURL.String())
}

// [tomlRootTrust.UnmarshalTOML]'s parser-dispatch loop relies on
// [errWrongType] propagating from [parseTomlRootTrust] when the TOML data is
// tagged for a different [RootTrustSource] type. Pin that contract here.
func TestParseTomlRootTrust_WrongType(t *testing.T) {
	for _, tc := range []struct {
		name string
		fn   func(any) (RootTrustSource, error)
		data any
	}{
		{"TofuParser_BundledString", parseTomlRootTrust[tofuRootTrust], "bundled"},
		{"TofuParser_BundledTable", parseTomlRootTrust[tofuRootTrust], map[string]any{"type": "bundled", "path": "/x"}},
		{"BundledParser_TofuString", parseTomlRootTrust[bundledRootTrust], "insecure-tofu"},
		{"BundledParser_TofuTable", parseTomlRootTrust[bundledRootTrust], map[string]any{"type": "insecure-tofu"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.fn(tc.data)
			assert.ErrorIs(t, err, errWrongType)
		})
	}
}

func TestRootTrustSource_String(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  RootTrustSource
		want string
	}{
		{"Tofu", tofuRootTrust{}, "insecure-tofu"},
		{"Bundled", bundledRootTrust{Path: "/etc/root.json"}, "bundled:/etc/root.json"},
		{"BundledEmptyPath", bundledRootTrust{}, "bundled:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.src.String())
			assert.Equal(t, strings.SplitN(tc.want, ":", 2)[0], tc.src.Type())
		})
	}
}
