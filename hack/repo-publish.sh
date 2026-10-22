#!/bin/bash

# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Amutable GmbH

# repo-publish.sh -- create a new repository locally

set -Eeuo pipefail

function _log() {
	prefix="$1"
	shift
	echo "[$prefix]" "$@" >&2
}

function bail() {
	_log fatal "$@"
	exit 1
}

function error() {
	_log error "$@"
}

function warn() {
	_log warn "$@"
}

function info() {
	_log info "$@"
}

HARDHAT="${HARDHAT:-"$(readlink -f "$(dirname "${BASH_SOURCE[0]}")/..")/hardhat"}"
if ( command hardhat --help &>/dev/null ); then
	HARDHAT="$(which hardhat)"
fi

function hardhat() {
	_log "exec" hardhat "$@"
	"$HARDHAT" "$@"
}

hardhat --help &>/dev/null || bail "hardhat is not available (set HARDHAT to executable path)"

TMPFILE_PREFIX="quarry-$(basename "$0")"
TMPFILES_LIST="$(mktemp --tmpdir "$TMPFILE_PREFIX-tmpfiles.txt.XXXXXX")"
trap 'xargs -a "$TMPFILES_LIST" rm -f ; rm -f "$TMPFILES_LIST"' EXIT

# mktempfile [<name>] -- make a temporary file that is removed on exit
function mktempfile() {
	local tmpfile
	tmpfile="$(mktemp --tmpdir "$TMPFILE_PREFIX-${1:-tmpfile}.XXXXXX")"
	chmod 0600 "$tmpfile"
	echo "$tmpfile" | tee -a "$TMPFILES_LIST"
}

# count_components <path> -- count the number of path components in the path
function count_components() {
	# Count the number of slashes + 1 to figure out the number of lexical path
	# components in the given path. Note that we have to strip off the leading
	# slash(es) if it is an absolute path.
	path="$(tr -s / <<<"$1")"
	echo "$(($(tr -dc / <<<"${path/#\//}" | wc -c) + 1))"
}

function usage() {
	[ "$#" -gt 0 ] && error "$@"
	cat <<EOF
Usage: $0
            [--[no-]merge] [--[no-]include-targets]
            --keystore=<key-dir=${QUARRY_KEYSTORE:-\$QUARRY_KEYSTORE}>
            <repo-dir>
            [[<format>=]<targets.json>]...

Options:

    --[no-]merge                 include entries from the old targets.json
                                 in the new snapshot (default: --merge)

    --[no-]include-targets       add target files in <repo-dir>/targets
                                 to the new snapshot (default: --no-include-targets)

Description:

  Publish a new set of target files to a Quarry repository.

  The <repo-dir> and <keydir> arguments must be the same as those provided to
  hack/repo-create.sh. However, unlike hack/repo-create.sh, the repository
  directory is a single argument rather than a combination of <repo-rootdir>
  and <repo-name>! See the examples for more details.

  All of the provided targets.json files are merged, and the combination is
  signed and published to the repository directory, with the following flags
  controlling its contents:

  - The --merge flag controls whether entries in the old targets file should be
    inherited in the new repository snapshot (new entries in the provided
    targets.json take precedence).

  - The --include-targets flag will add any files present in <repo-dir>/targets
    to the generated targets.json (these take priority over every other
    targets.json source). This requires the files to be re-hashed so it
    probably makes more sense to generate these yourself if you can.

  You can specify more than one targets.json file, in which case they are all
  merged (with later entries taking precedence). If no targets.json files are
  specified, the repository will still be published but without merging in any
  external targets.json files.

  <format> indicates which subsection of a TUF targets JSON file is being
  provided in targets.json. There are currently four supported formats (if
  unspecified, it defaults to "signed"):

  - "sha256sum" is a SHA256SUM file that is in a directory containing the files
    it references. This is effectively equivalent to the --pre-hashed option
    from hardhat targets.

  - "bakery" is a shortcut for hack/quarry-bakery to generate a targets.json
    for a flatcar/sysext-bakery component. This is mostly just a tech demo.

  - "signed" is a complete TUF targets JSON file. This is primarily useful when
    taking an existing signed target.json (from some repository, or from tools
    like quarry-bakery) and importing it into this repository. This file is
    permitted to have invalid signatures or bogus fields, but the general
    structure looks like:

    {
        "signatures": [...],
        "signed": {
            "_type": "targets",
            "expires": "...",
            "spec_version": "1.x.y",
            "targets": {
                ...
                "target-path.ext": {
                    "length": 1234,
                    "hashes": {
                        "sha256": "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c",
                    }
                    [, "x-quarry-override-url": "https://foo.bar.com/..."]
                },
                ...
            }
        }
    }

  - "raw" is just the ".signed.targets" portion of the TUF targets JSON file,
    and only includes a JSON map of target file information. This is probably
    more useful for tools that are manually generating targets.json data and
    have no means to sign it, and is probably going to be structure used in the
    quarryd protocol format. It looks like the following:


    {
        ...
        "target-path.ext": {
            "length": 1234,
            "hashes": {
                "sha256": "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c",
            }
            [, "x-quarry-override-url": "https://foo.bar.com/..."]
        },
        ...
    }

  The "x-quarry-override-url" field is an optional extension which will tell
  sysupdate and "quarry-client fetch" to download a particular target file from
  an alternative location. This is particularly useful for external resources
  as well as for emulating cross-repository links.

Examples:

  Create a new repository and publish a targets.json generated by quarry-bakery
  (using a flatcar/sysext-bakery extension). First we create the repository:

    \$ export QUARRY_KEYSTORE=/tmp/keys
    \$ hack/repo-create.sh ./repo/machine-id dead-beef-cafe

  Then we generate a targets.json using quarry-bakery (users would instead
  generate their own targets.json file here, this is just an example):

    \$ hack/quarry-bakery wasmtime \\
                  --keystore=\$QUARRY_KEYSTORE/builder-keys \\
                  --from-root=./repo/machine-id/dead-beef-cafe/1.root.json \\
                  -o wasmtime-targets.json

  (If you want to see a real targets.json file, you can look at that one.)

  We can then publish the repository with the new targets file:

    \$ hack/repo-publish.sh ./repo/machine-id/dead-beef-cafe wasmtime-targets.json

EOF
	# shellcheck disable=SC2048 # We want to only expand to nothing or 1.
	exit ${*:+1}
}

GETOPT="$(getopt -o h --long help,keystore:,merge,no-merge,include-targets,no-include-targets -- "$@")"
eval set -- "$GETOPT"

merge_old_targets=1
include_repodir_targets=
KEY_DIR="${QUARRY_KEYSTORE:-}"
while true; do
	case "$1" in
		--keystore) KEY_DIR="$2"; shift 2 ;;
		--merge)    merge_old_targets=1; shift ;;
		--no-merge) merge_old_targets=;  shift ;;
		--include-targets)    include_repodir_targets=1; shift ;;
		--no-include-targets) include_repodir_targets=;  shift ;;
		--) shift; break ;;
		-h | --help) usage ;;
		*)           usage "unknown argument $1" ;;
	esac
done
[ -n "$KEY_DIR" ] || usage "missing --keystore argument"

[ "$#" -ge 1 ] || usage "missing <repo-dir> argument"
REPO_DIR="$1"
shift

TARGETS_WRAPPER="$(cat <<EOF
{
	"signed": {
		"_type": "targets",
		"expires": "$(date  +'%Y-%m-%dT%H:%M:%S.%NZ' --utc --date="1997-03-25")",
		"version": 0,
		"spec_version": "1.0.31",
		"targets": .
	},
	"signatures": []
}
EOF
)"

BUILDER_KEYSTORE="$KEY_DIR/builder-keys"
hardhat_targets_flags=("--keystore=$BUILDER_KEYSTORE")

# Parse out the builder signing keyids from the latest root.json. For proper
# signing setups this would not really be necessary because you would only have
# builder keys and so you would only ever need to sign with those.
root_json_file="$(find "$REPO_DIR" -maxdepth 1 -name "*.root.json" | sort -t. -k 1nr | head -n1)"
read -ra builder_keyids <<<"$(jq -rM '.signed.roles.targets.keyids[]' <"$root_json_file")"
# Add --keyid=$keyid arguments.
builder_sign_flags=("${builder_keyids[@]/#/--keyid=}")
hardhat_targets_flags+=("${builder_sign_flags[@]}")

# The repository state everything below is computed from. Another publisher may
# commit before we do; snapshot then refuses to commit instead of silently
# dropping what they published. Only timestamp.json is rewritten in place, so
# read it just once; the versioned files it leads to never change.
base_timestamp_version=0
if [ -f "$REPO_DIR/timestamp.json" ]; then
	base_timestamp_json="$(mktempfile timestamp.json)"
	cp "$REPO_DIR/timestamp.json" "$base_timestamp_json"
	base_timestamp_version="$(jq -rM '.signed.version' <"$base_timestamp_json")"
fi

if [ -n "$merge_old_targets" ]; then
	# Figure out the latest targets.json.
	# If the repository was just initialised, we skip this.
	if [ "$base_timestamp_version" != 0 ]; then
		latest_snapshot_json="$REPO_DIR/$(jq -rM '.signed.meta["snapshot.json"].version' <"$base_timestamp_json").snapshot.json"
		latest_targets_json="$REPO_DIR/$(jq -rM '.signed.meta["targets.json"].version' <"$latest_snapshot_json").targets.json"
		hardhat_targets_flags+=("--include-from=$latest_targets_json")
	else
		info "Repository $REPO_DIR is empty and so --merge is a no-op -- ignoring."
	fi
fi
for target in "$@"; do
	case "$target" in
		bakery=*)
			component="${target#bakery=}"
			tmptarget="$(mktempfile "targets.json-from-bakery-$component")"
			"$(dirname "${BASH_SOURCE[0]}")"/quarry-bakery \
				"$component" \
				-o "$tmptarget" \
				--keystore="$BUILDER_KEYSTORE" \
				"${builder_sign_flags[@]}"
			target="$tmptarget"
			;;
		sha256sum=*)
			sumfile="${target#sha256sum=}"
			tmptarget="$(mktempfile "targets.json-from-sha256sum-${sumfile//\//.}")"
			# TODO: Hardhat should support outputting unsigned targets.json
			# data, so we don't need to sign then re-sign these blobs...
			hardhat targets -o "$tmptarget" \
				--keystore="$BUILDER_KEYSTORE" \
				"${builder_sign_flags[@]}" \
				--pre-hashed \
				--strip-components="$(($(count_components "$sumfile") - 1))" \
				"$sumfile"
			target="$tmptarget"
			;;
		raw=*)
			target="${target#raw=}"
			tmptarget="$(mktempfile "targets.json-from-raw-${target//\//.}")"
			jq "$TARGETS_WRAPPER" <"$target" >"$tmptarget"
			target="$tmptarget"
			;;
		signed=*)
			target="${target#signed=}"
			;;
	esac
	hardhat_targets_flags+=("--include-from=$target")
done

hardhat_targets_flags+=("${builder_keyids[@]/#/--keyid=}")

if [ -n "$include_repodir_targets" ]; then
	targets_dir="$REPO_DIR/targets"
	hardhat_targets_flags+=("--strip-components=$(count_components "$targets_dir")" "$targets_dir")
fi

targets_json="$(mktempfile targets.json)"
hardhat targets -o "$targets_json" \
	"${hardhat_targets_flags[@]}"

PUBLISHER_KEYSTORE="$KEY_DIR/quarryd-keys"
hardhat repoctl snapshot \
	--keystore="$PUBLISHER_KEYSTORE" \
	--repo-metadir="$REPO_DIR" \
	--if-timestamp-version="$base_timestamp_version" \
	targets="$targets_json"
