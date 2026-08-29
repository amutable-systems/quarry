// Copyright (C) 2026 Amutable GmbH

package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const uuidPat = `[0-9a-f]{32}`

var uuidRe = regexp.MustCompile(`^` + uuidPat + `$`)

func repoBlock(rootTrust string) string {
	return `
config_version = 1
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
		{
			name:      "InlineInlineTable",
			rootTrust: `root_trust = { type = "inline", "root.json" = '{"signed": {}}' }`,
			want:      inlineRootTrust{RootJSON: `{"signed": {}}`},
		},
		{
			name:      "InlineEmptyRootJSON",
			rootTrust: `root_trust = { type = "inline", "root.json" = "" }`,
			want:      inlineRootTrust{RootJSON: ""},
		},
		{
			// Unlike bundled paths, inline root.json data is exempt from
			// %-expansion, so % sequences must be preserved verbatim.
			name:      "InlinePercentNotExpanded",
			rootTrust: `root_trust = { type = "inline", "root.json" = '{"pct": "100%Z"}' }`,
			want:      inlineRootTrust{RootJSON: `{"pct": "100%Z"}`},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf, err := Parse(strings.NewReader(repoBlock(tc.rootTrust)))
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
			wantErr:   `missing required field "type"`,
		},
		{
			name:      "InlineTableNonStringType",
			rootTrust: `root_trust = { type = 42 }`,
			wantErr:   `"type" has incorrect value type`,
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
			wantErr:   `"path" has incorrect value type`,
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
			name:      "InlinePlainString",
			rootTrust: `root_trust = "inline"`,
			wantErr:   `cannot be instantiated using a plain string`,
		},
		{
			name:      "InlineMissingRootJSON",
			rootTrust: `root_trust = { type = "inline" }`,
			wantErr:   `missing required field "root.json"`,
		},
		{
			// An unquoted root.json key is a TOML dotted key (a nested
			// "root" table), not the literal "root.json" key inline needs.
			name:      "InlineUnquotedRootJSONKey",
			rootTrust: `root_trust = { type = "inline", root.json = "{}" }`,
			wantErr:   `missing required field "root.json"`,
		},
		{
			name:      "InlineNonStringRootJSON",
			rootTrust: `root_trust = { type = "inline", "root.json" = 42 }`,
			wantErr:   `"root.json" has incorrect value type`,
		},
		{
			name:      "InlineExtraField",
			rootTrust: `root_trust = { type = "inline", "root.json" = "{}", extra = "y" }`,
			wantErr:   `unsupported fields: [extra]`,
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
			_, err := Parse(strings.NewReader(repoBlock(tc.rootTrust)))
			require.Error(t, err)
			assert.ErrorContains(t, err, tc.wantErr)
		})
	}
}

// The typical way to embed a root.json is a multi-line literal string in a
// dedicated sub-table, so make sure that form survives parsing verbatim.
func TestParseConfig_RootTrust_InlineMultiline(t *testing.T) {
	conf, err := Parse(strings.NewReader(`
config_version = 1
[repo.example]
meta_root_url = "https://example.com/repo"

[repo.example.root_trust]
type = "inline"
"root.json" = '''
{"signed": {"_type": "root", "version": 1}}
'''
`))
	require.NoError(t, err)
	require.Contains(t, conf.Repos, "example")
	require.NotNil(t, conf.Repos["example"].RootTrust)
	assert.Equal(t,
		inlineRootTrust{RootJSON: "{\"signed\": {\"_type\": \"root\", \"version\": 1}}\n"},
		conf.Repos["example"].RootTrust.RootTrustSource)
}

func TestParseConfig_OnlyVersion(t *testing.T) {
	conf, err := Parse(strings.NewReader(`config_version = 1`))
	require.NoError(t, err)
	assert.Empty(t, conf.Repos)
}

func TestParseConfig_VersionMissing(t *testing.T) {
	_, err := Parse(strings.NewReader(`
[repo.example]
root_trust = "insecure-tofu"
meta_root_url = "https://example.com"
`))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedVersion)
}

// Files with no toml content at all (such as a symlink to /dev/null used to
// mask a drop-in, or a file containing only comments) are valid configurations
// and are exempt from the config_version requirement.
func TestParseConfig_Empty(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
	}{
		{"NoBytes", ""},
		{"Newlines", "\n\n\n"},
		// Only toml-legal whitespace can appear here -- other whitespace
		// characters (\v, \f) are control characters rejected by the decoder.
		{"SpacesAndTabs", " \t \t"},
		{"WindowsLineEndings", "\r\n\r\n"},
		{"CommentOnly", "# this drop-in was disabled\n"},
		{"CommentsAndWhitespace", " \t# c1\n\n# c2\r\n\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf, err := Parse(strings.NewReader(tc.input))
			require.NoError(t, err)
			assert.Equal(t, int64(ConfigVersion), conf.Version)
			assert.Empty(t, conf.Repos)
		})
	}
}

// Any toml content is enough to disqualify a file from the empty exemption,
// so it must declare a config_version like any other non-empty fragment. The
// Undecoded* cases assert that [toml.MetaData.Keys] also counts keys that
// nothing decodes into (i.e., ones [toml.MetaData.Undecoded] would report) --
// if it didn't, these files would be misdetected as empty and parse without
// any error at all.
func TestParseConfig_ContentIsNotEmpty(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
	}{
		{"BareTable", "[repo.example]\n"},
		{"UndecodedKey", "no_such_key = 1\n"},
		{"UndecodedBareTable", "[no_such_table]\n"},
		{"UndecodedTableKey", "[no_such_table]\nno_such_key = \"x\"\n"},
		{"CommentAndUndecodedKey", "# comment\nno_such_key = 1\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(tc.input))
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrUnsupportedVersion)
		})
	}
}

func TestParseConfig_VersionUnsupported(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version string
	}{
		{"Zero", "0"},
		{"Future", "2"},
		{"Negative", "-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(`config_version = ` + tc.version))
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrUnsupportedVersion)
		})
	}
}

func TestParseConfig_RepoMissingRootTrust(t *testing.T) {
	_, err := Parse(strings.NewReader(`
config_version = 1
[repo.example]
meta_root_url = "https://example.com"
`))
	require.Error(t, err)
	assert.ErrorContains(t, err, "missing root_trust specification")
}

func TestParseConfig_RepoNameFromKey(t *testing.T) {
	conf, err := Parse(strings.NewReader(`
config_version = 1
[repo."updates.example.com/alpha"]
root_trust = "insecure-tofu"
meta_root_url = "https://example.com"
`))
	require.NoError(t, err)
	require.Contains(t, conf.Repos, "updates.example.com/alpha")
	assert.Equal(t, "updates.example.com/alpha", conf.Repos["updates.example.com/alpha"].Name)
}

func TestParseConfig_DefaultMetaRootURL(t *testing.T) {
	conf, err := Parse(strings.NewReader(`
config_version = 1
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
	conf, err := Parse(strings.NewReader(`
config_version = 1
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
	conf, err := Parse(strings.NewReader(`
config_version = 1
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

func TestParseConfig_OrderIndex(t *testing.T) {
	for _, tc := range []struct {
		name       string
		orderIndex string
		want       int64
	}{
		{"Default", ``, 100},
		{"Explicit", `order_index = 500`, 500},
		{"SameAsDefault", `order_index = 100`, 100},
		{"Zero", `order_index = 0`, 0},
		{"Negative", `order_index = -10`, -10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf, err := Parse(strings.NewReader(`
config_version = 1
[repo.example]
root_trust = "insecure-tofu"
meta_root_url = "https://example.com"
` + tc.orderIndex + "\n"))
			require.NoError(t, err)
			repo := conf.Repos["example"]
			require.NotNil(t, repo)
			if tc.orderIndex == "" {
				assert.Nil(t, repo.RawOrderIndex, "unset order_index must stay nil after parsing")
			} else {
				require.NotNil(t, repo.RawOrderIndex)
				assert.Equal(t, tc.want, *repo.RawOrderIndex)
			}
			assert.Equal(t, tc.want, repo.OrderIndex())
		})
	}
}

func TestParseConfig_OrderIndex_InvalidType(t *testing.T) {
	for _, tc := range []struct {
		name       string
		orderIndex string
	}{
		{"String", `order_index = "first"`},
		{"Float", `order_index = 1.5`},
		{"Array", `order_index = [100]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(`
config_version = 1
[repo.example]
root_trust = "insecure-tofu"
meta_root_url = "https://example.com"
` + tc.orderIndex + "\n"))
			require.Error(t, err)
			assert.ErrorContains(t, err, "order_index")
		})
	}
}

func TestParseConfig_MultipleRepos(t *testing.T) {
	conf, err := Parse(strings.NewReader(`
config_version = 1
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
	_, err := Parse(strings.NewReader(`
config_version = 1
some_unknown_key = "value"

[repo.example]
root_trust = "insecure-tofu"
meta_root_url = "https://example.com"
`))
	require.Error(t, err)
	assert.ErrorContains(t, err, "unknown toml keys")
}

func TestParseConfig_UnknownRepoKey(t *testing.T) {
	_, err := Parse(strings.NewReader(`
config_version = 1
[repo.example]
root_trust = "insecure-tofu"
meta_root_url = "https://example.com"
not_a_real_field = "oops"
`))
	require.Error(t, err)
	assert.ErrorContains(t, err, "unknown toml keys")
}

func TestParseConfig_InvalidTOML(t *testing.T) {
	_, err := Parse(strings.NewReader("this is not = valid = toml ="))
	require.Error(t, err)
	assert.ErrorContains(t, err, "invalid config")
}

func TestParseConfig_BadURL(t *testing.T) {
	// [toml.ParseError] has no Unwrap so [errors.As] cannot reach the
	// underlying [url.EscapeError]; match a structural substring instead.
	_, err := Parse(strings.NewReader(`
config_version = 1
[repo.example]
root_trust = "insecure-tofu"
meta_root_url = "https://example.com/%zz"
`))
	require.Error(t, err)
	assert.ErrorContains(t, err, "meta_root_url")
}

func TestParseConfig_ExampleFile(t *testing.T) {
	f, err := os.Open("../../../contrib/quarry-client/config.toml.d/10-AmutableOS.toml") //nolint:forbidigo // test code
	require.NoError(t, err)
	defer f.Close() //nolint:errcheck // test code

	conf, err := Parse(f)
	require.NoError(t, err)

	const repoName = "updates.example.com/base-os/nightly"
	require.Contains(t, conf.Repos, repoName)
	repo := conf.Repos[repoName]

	assert.Equal(t, repoName, repo.Name)
	assert.Nil(t, repo.RawOrderIndex) // not specified
	assert.Equal(t, int64(100), repo.OrderIndex())
	assert.Equal(t,
		bundledRootTrust{Path: `/usr/share/amutable/quarry/trusted/updates.example.com-base\x2dos-nightly-root.json`},
		repo.RootTrust.RootTrustSource)
	assert.Equal(t, "https://updates.example.com/update", repo.MetaRootURL.String())
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
		{"TofuParser_InlineTable", parseTomlRootTrust[tofuRootTrust], map[string]any{"type": "inline", "root.json": "{}"}},
		{"BundledParser_InlineTable", parseTomlRootTrust[bundledRootTrust], map[string]any{"type": "inline", "root.json": "{}"}},
		{"InlineParser_TofuString", parseTomlRootTrust[inlineRootTrust], "insecure-tofu"},
		{"InlineParser_BundledTable", parseTomlRootTrust[inlineRootTrust], map[string]any{"type": "bundled", "path": "/x"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.fn(tc.data)
			assert.ErrorIs(t, err, errWrongType)
		})
	}
}

func TestInlineRootTrust_FetchRoot(t *testing.T) {
	const rootJSON = `{"signed": {"_type": "root"}}`
	data, err := inlineRootTrust{RootJSON: rootJSON}.FetchRoot(t.Context(), nil)
	require.NoError(t, err)
	assert.Equal(t, []byte(rootJSON), data) //nolint:testifylint // we are doing a direct byte-for-byte comparison here
}

func TestParseConfig_Expand_RepoName(t *testing.T) {
	for _, tc := range []struct {
		name       string
		key        string
		wantNameRe string
	}{
		{"LiteralPercent", "100%%-secure", `^100%-secure$`},
		{"MachineID", "machine/%m", `^machine/` + uuidPat + `$`},
		{"MachineIDEscaped", "%em", `^` + uuidPat + `$`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf, err := Parse(strings.NewReader(`
config_version = 1
[repo."` + tc.key + `"]
root_trust = "insecure-tofu"
meta_root_url = "https://example.com"
`))
			require.NoError(t, err)
			require.Len(t, conf.Repos, 1)
			var gotName string
			for k := range conf.Repos {
				gotName = k
			}
			assert.Regexp(t, tc.wantNameRe, gotName)
			assert.Equal(t, gotName, conf.Repos[gotName].Name)
		})
	}
}

func TestParseConfig_Expand_RepoName_MachineIDConsistent(t *testing.T) {
	conf, err := Parse(strings.NewReader(`
config_version = 1
[repo."a/%m"]
root_trust = "insecure-tofu"
meta_root_url = "https://example.com/%m"
data_root_url = "https://example.com/%m/data"
`))
	require.NoError(t, err)
	require.Len(t, conf.Repos, 1)
	var repo *Repository
	for _, r := range conf.Repos {
		repo = r
	}

	id, ok := strings.CutPrefix(repo.Name, "a/")
	require.True(t, ok, "repo name %q lacks expected prefix", repo.Name)
	assert.Regexp(t, uuidRe, id)

	assert.Equal(t, "https://example.com/"+id, repo.MetaRootURL.String())
	assert.Equal(t, "https://example.com/"+id+"/data", repo.DataRootURL.String())
}

func mergeFragments(t *testing.T, fragments ...string) *Config {
	t.Helper()
	cfg := &Config{Version: ConfigVersion, Repos: make(map[string]*Repository)}
	for _, fragment := range fragments {
		parsed, err := parseToml(strings.NewReader(fragment))
		require.NoError(t, err)
		require.NoError(t, cfg.merge(parsed))
	}
	require.NoError(t, cfg.expandAndValidate())
	return cfg
}

func TestMerge_EmptyURLResetsToDefault(t *testing.T) {
	cfg := mergeFragments(t, `
config_version = 1
[repo."example.com/base-os"]
root_trust = "insecure-tofu"
meta_root_url = "https://mirror.example"
data_root_url = "https://mirror.example/data"
`, `
config_version = 1
[repo."example.com/base-os"]
meta_root_url = ""
data_root_url = ""
`)

	repo := cfg.Repos["example.com/base-os"]
	require.NotNil(t, repo)
	assert.Equal(t, "https://example.com/base-os", repo.MetaRootURL.String())
	assert.Equal(t, "https://example.com/base-os/targets", repo.DataRootURL.String())
}

func TestMerge_EmptyURLResetsOnFirstDefinition(t *testing.T) {
	cfg := mergeFragments(t, `
config_version = 1
[repo."example.com/base-os"]
root_trust = "insecure-tofu"
meta_root_url = ""
`)

	repo := cfg.Repos["example.com/base-os"]
	require.NotNil(t, repo)
	assert.Equal(t, "https://example.com/base-os", repo.MetaRootURL.String())
}

func TestMerge_UnsetURLKeepsOverride(t *testing.T) {
	cfg := mergeFragments(t, `
config_version = 1
[repo."example.com/base-os"]
root_trust = "insecure-tofu"
meta_root_url = "https://mirror.example"
`, `
config_version = 1
[repo."example.com/base-os"]
data_root_url = "https://data.example"
`)

	repo := cfg.Repos["example.com/base-os"]
	require.NotNil(t, repo)
	assert.Equal(t, "https://mirror.example", repo.MetaRootURL.String())
	assert.Equal(t, "https://data.example", repo.DataRootURL.String())
}

func TestMerge_OrderIndexOverride(t *testing.T) {
	cfg := mergeFragments(t, `
config_version = 1
[repo."example.com/base-os"]
root_trust = "insecure-tofu"
order_index = 500
`, `
config_version = 1
[repo."example.com/base-os"]
order_index = 10
`)

	repo := cfg.Repos["example.com/base-os"]
	require.NotNil(t, repo)
	require.NotNil(t, repo.RawOrderIndex)
	assert.Equal(t, int64(10), *repo.RawOrderIndex)
}

func TestMerge_UnsetOrderIndexKeepsOverride(t *testing.T) {
	cfg := mergeFragments(t, `
config_version = 1
[repo."example.com/base-os"]
root_trust = "insecure-tofu"
order_index = 500
`, `
config_version = 1
[repo."example.com/base-os"]
meta_root_url = "https://mirror.example"
`)

	repo := cfg.Repos["example.com/base-os"]
	require.NotNil(t, repo)
	require.NotNil(t, repo.RawOrderIndex)
	assert.Equal(t, int64(500), *repo.RawOrderIndex)
}

func TestMerge_OrderIndexAddedByDropIn(t *testing.T) {
	cfg := mergeFragments(t, `
config_version = 1
[repo."example.com/base-os"]
root_trust = "insecure-tofu"
`, `
config_version = 1
[repo."example.com/base-os"]
order_index = 42
`)

	repo := cfg.Repos["example.com/base-os"]
	require.NotNil(t, repo)
	require.NotNil(t, repo.RawOrderIndex)
	assert.Equal(t, int64(42), *repo.RawOrderIndex)
}

// A repository whose order index is never set by any fragment stays unset
// (nil) and reports the default order index.
func TestMerge_OrderIndexDefault(t *testing.T) {
	cfg := mergeFragments(t, `
config_version = 1
[repo."example.com/base-os"]
root_trust = "insecure-tofu"
`, `
config_version = 1
[repo."example.com/base-os"]
meta_root_url = "https://mirror.example"
`)

	repo := cfg.Repos["example.com/base-os"]
	require.NotNil(t, repo)
	assert.Nil(t, repo.RawOrderIndex)
	assert.Equal(t, int64(100), repo.OrderIndex())
}

// Empty fragments (a drop-in masked with a /dev/null symlink, or one
// containing only comments) must merge as no-ops regardless of where they
// appear in the merge order.
func TestMerge_EmptyFragmentIsNoop(t *testing.T) {
	cfg := mergeFragments(t, "", `
config_version = 1
[repo."example.com/base-os"]
root_trust = "insecure-tofu"
meta_root_url = "https://mirror.example"
`, "\n \t\n", "# this drop-in was disabled\n")

	require.Len(t, cfg.Repos, 1)
	repo := cfg.Repos["example.com/base-os"]
	require.NotNil(t, repo)
	assert.Equal(t, "https://mirror.example", repo.MetaRootURL.String())
}

func TestParseToml_RepoNameExpandedBeforeMerge(t *testing.T) {
	main, err := parseToml(strings.NewReader(`
config_version = 1
[repo."a/%m"]
root_trust = "insecure-tofu"
meta_root_url = "https://main.example"
`))
	require.NoError(t, err)
	require.Len(t, main.Repos, 1)

	var name string
	for n := range main.Repos {
		name = n
	}
	require.NotContains(t, name, "%")

	dropIn, err := parseToml(strings.NewReader(fmt.Sprintf(`
config_version = 1
[repo.%q]
meta_root_url = "https://dropin.example"
`, name)))
	require.NoError(t, err)

	cfg := &Config{Version: ConfigVersion, Repos: make(map[string]*Repository)}
	require.NoError(t, cfg.merge(main))
	require.NoError(t, cfg.merge(dropIn))
	require.NoError(t, cfg.expandAndValidate())

	require.Len(t, cfg.Repos, 1, "a drop-in naming the expanded repo must not add a second one")
	repo := cfg.Repos[name]
	require.NotNil(t, repo)
	assert.Equal(t, "https://dropin.example", repo.MetaRootURL.String())
	assert.Equal(t, "insecure-tofu", repo.RootTrust.Type())
}

func TestParseConfig_Expand_URL(t *testing.T) {
	for _, tc := range []struct {
		name       string
		template   string
		wantMeta   string
		wantMetaRe string
	}{
		{
			name:     "RepoName",
			template: "https://meta.example.com/%R",
			wantMeta: "https://meta.example.com/example.com/foo",
		},
		{
			name:     "RepoNameEscaped",
			template: "https://meta.example.com/%eR",
			wantMeta: "https://meta.example.com/example.com-foo",
		},
		{
			name:     "PredicateAfterSourceIsLiteral",
			template: "https://meta.example.com/%Re-suffix",
			wantMeta: "https://meta.example.com/example.com/fooe-suffix",
		},
		{
			name:     "LiteralPercent",
			template: "https://example.com/%%25",
			wantMeta: "https://example.com/%25",
		},
		{
			name:       "MachineID",
			template:   "https://example.com/m/%m",
			wantMetaRe: `^https://example\.com/m/` + uuidPat + `$`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf, err := Parse(strings.NewReader(`
config_version = 1
[repo."example.com/foo"]
root_trust = "insecure-tofu"
meta_root_url = "` + tc.template + `"
`))
			require.NoError(t, err)
			repo := conf.Repos["example.com/foo"]
			require.NotNil(t, repo)
			if tc.wantMetaRe != "" {
				assert.Regexp(t, tc.wantMetaRe, repo.MetaRootURL.String())
			} else {
				assert.Equal(t, tc.wantMeta, repo.MetaRootURL.String())
			}
		})
	}
}

func TestParseConfig_Expand_URL_PercentEncoded(t *testing.T) {
	conf, err := Parse(strings.NewReader(`
config_version = 1
[repo.example]
root_trust = "insecure-tofu"
meta_root_url = "https://example.com/100%25-uptime/%2A/%aF"
`))
	require.NoError(t, err)
	repo := conf.Repos["example"]
	require.NotNil(t, repo)
	assert.Equal(t, "https://example.com/100%25-uptime/%2A/%aF", repo.MetaRootURL.String())
	// data_root_url is defaulted from the expanded meta URL, so the %XX
	// sequences pass through a second Expand pass.
	assert.Equal(t, "https://example.com/100%25-uptime/%2A/%aF/targets", repo.DataRootURL.String())
}

func TestParseConfig_Expand_URL_PerRepoR(t *testing.T) {
	conf, err := Parse(strings.NewReader(`
config_version = 1
[repo.alpha]
root_trust = "insecure-tofu"
meta_root_url = "https://example.com/%R"

[repo.beta]
root_trust = "insecure-tofu"
meta_root_url = "https://example.com/%R"
`))
	require.NoError(t, err)
	require.Len(t, conf.Repos, 2)
	assert.Equal(t, "https://example.com/alpha", conf.Repos["alpha"].MetaRootURL.String())
	assert.Equal(t, "https://example.com/beta", conf.Repos["beta"].MetaRootURL.String())
}

func TestParseConfig_Expand_Bundled(t *testing.T) {
	for _, tc := range []struct {
		name       string
		path       string
		wantPath   string
		wantPathRe string
	}{
		{
			name:     "LiteralPercent",
			path:     `/etc/root%%foo.json`,
			wantPath: `/etc/root%foo.json`,
		},
		{
			name:     "RepoName",
			path:     `/etc/%R/root.json`,
			wantPath: `/etc/example.com/foo/root.json`,
		},
		{
			name:     "RepoNameEscaped",
			path:     `/etc/quarry/trusted/%eR-root.json`,
			wantPath: `/etc/quarry/trusted/example.com-foo-root.json`,
		},
		{
			name:       "MachineID",
			path:       `/etc/quarry/keys/%m.json`,
			wantPathRe: `^/etc/quarry/keys/` + uuidPat + `\.json$`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf, err := Parse(strings.NewReader(`
config_version = 1
[repo."example.com/foo"]
root_trust = { type = "bundled", path = "` + tc.path + `" }
meta_root_url = "https://example.com"
`))
			require.NoError(t, err)
			repo := conf.Repos["example.com/foo"]
			require.NotNil(t, repo)
			bundled, ok := repo.RootTrust.RootTrustSource.(bundledRootTrust)
			require.True(t, ok)
			if tc.wantPathRe != "" {
				assert.Regexp(t, tc.wantPathRe, bundled.Path)
			} else {
				assert.Equal(t, tc.wantPath, bundled.Path)
			}
		})
	}
}

func TestParseConfig_Expand_CacheDir(t *testing.T) {
	for _, tc := range []struct {
		name      string
		cacheDir  string
		wantDir   string
		wantDirRe string
	}{
		{
			name:     "Empty",
			cacheDir: ``,
			wantDir:  ``,
		},
		{
			name:     "Literal",
			cacheDir: `/var/cache/quarry`,
			wantDir:  `/var/cache/quarry`,
		},
		{
			name:     "LiteralPercent",
			cacheDir: `/var/cache/100%%`,
			wantDir:  `/var/cache/100%`,
		},
		{
			name:      "MachineID",
			cacheDir:  `/var/cache/quarry/%m`,
			wantDirRe: `^/var/cache/quarry/` + uuidPat + `$`,
		},
		{
			name:      "MachineIDEscaped",
			cacheDir:  `/var/cache/quarry/%em`,
			wantDirRe: `^/var/cache/quarry/` + uuidPat + `$`,
		},
		{
			name:     "PercentEncoded",
			cacheDir: `/var/cache/quarry/%2Ffoo`,
			wantDir:  `/var/cache/quarry/%2Ffoo`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf, err := Parse(strings.NewReader(`
config_version = 1
cache_dir = "` + tc.cacheDir + `"
`))
			require.NoError(t, err)
			if tc.wantDirRe != "" {
				assert.Regexp(t, tc.wantDirRe, conf.CacheDir)
			} else {
				assert.Equal(t, tc.wantDir, conf.CacheDir)
			}
		})
	}
}

func TestParseConfig_Expand_Invalid(t *testing.T) {
	for _, tc := range []struct {
		name    string
		config  string
		wantErr string
	}{
		{
			name: "UnknownPredicateInRepoName",
			config: `
config_version = 1
[repo."%Z"]
root_trust = "insecure-tofu"
meta_root_url = "https://example.com"`,
			wantErr: `invalid predicate Z`,
		},
		{
			name: "RepoNameSourceNotInRepoName",
			config: `
config_version = 1
[repo."%R"]
root_trust = "insecure-tofu"
meta_root_url = "https://example.com"`,
			wantErr: `invalid predicate R`,
		},
		{
			name: "TrailingPercentInRepoName",
			config: `
config_version = 1
[repo."foo%"]
root_trust = "insecure-tofu"
meta_root_url = "https://example.com"`,
			wantErr: `trailing % at end of string`,
		},
		{
			name: "IncompletePredicateInRepoName",
			config: `
config_version = 1
[repo."foo/%e"]
root_trust = "insecure-tofu"
meta_root_url = "https://example.com"`,
			wantErr: `incomplete expando "%e"`,
		},
		{
			name: "UnknownPredicateInURL",
			config: `
config_version = 1
[repo.example]
root_trust = "insecure-tofu"
meta_root_url = "https://example.com/%Z"`,
			wantErr: `invalid predicate Z`,
		},
		{
			name: "TrailingPercentInURL",
			config: `
config_version = 1
[repo.example]
root_trust = "insecure-tofu"
meta_root_url = "https://example.com/%"`,
			wantErr: `trailing % at end of string`,
		},
		{
			name: "TruncatedPercentEncodedInURL",
			config: `
config_version = 1
[repo.example]
root_trust = "insecure-tofu"
meta_root_url = "https://example.com/%2"`,
			wantErr: `truncated http expando "%2"`,
		},
		{
			name: "InvalidPercentEncodedInURL",
			config: `
config_version = 1
[repo.example]
root_trust = "insecure-tofu"
meta_root_url = "https://example.com/%2X"`,
			wantErr: `invalid char X in http expando "%2X"`,
		},
		{
			name: "DuplicatePredicateInURL",
			config: `
config_version = 1
[repo.example]
root_trust = "insecure-tofu"
meta_root_url = "https://example.com/%eeR"`,
			wantErr: `duplicate predicate e`,
		},
		{
			name: "UnknownPredicateInBundledPath",
			config: `
config_version = 1
[repo.example]
root_trust = { type = "bundled", path = "/etc/%Z" }
meta_root_url = "https://example.com"`,
			wantErr: `invalid predicate Z`,
		},
		{
			name: "UnknownPredicateInCacheDir",
			config: `
config_version = 1
cache_dir = "/var/cache/%Z"`,
			wantErr: `invalid predicate Z`,
		},
		{
			name: "RepoNameSourceNotInCacheDir",
			config: `
config_version = 1
cache_dir = "/var/cache/%R"`,
			wantErr: `invalid predicate R`,
		},
		{
			name: "RelativeCacheDir",
			config: `
config_version = 1
cache_dir = "var/cache/quarry"`,
			wantErr: `must be an absolute path`,
		},
		{
			name: "RelativeAfterExpansion",
			config: `
config_version = 1
cache_dir = "%m"`,
			wantErr: `must be an absolute path`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(tc.config))
			require.Error(t, err)
			assert.ErrorContains(t, err, tc.wantErr)
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
		{"Inline", inlineRootTrust{RootJSON: `{"a": 1}`}, `inline:"{\"a\": 1}"`},
		{"InlineEmpty", inlineRootTrust{}, `inline:""`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.src.String())
			assert.Equal(t, strings.SplitN(tc.want, ":", 2)[0], tc.src.Type())
		})
	}
}
