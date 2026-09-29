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
trap 'xargs -a "$TMPFILES_LIST" rm -rf ; rm -f "$TMPFILES_LIST"' EXIT

# mktempdir [<name>] -- make a temporary file that is removed on exit
function mktempdir() {
	local tmpfile
	tmpfile="$(mktemp -d --tmpdir "$TMPFILE_PREFIX-${1:-tmpfile}.XXXXXX")"
	chmod 0700 "$tmpfile"
	echo "$tmpfile" | tee -a "$TMPFILES_LIST"
}

function usage() {
	[ "$#" -gt 0 ] && error "$@"
	cat <<EOF
Usage: $0
            --keystore=<key-dir=${QUARRY_KEYSTORE:-\$QUARRY_KEYSTORE}>
            <repo-dir>

Description:

  Refresh the TUF metadata if it is close to expiry. This needs to be run
  fairly regularly (read: once or twice a day), as some TUF metadata has
  default expiries of a day.

  The <repo-dir> and <keydir> arguments must be the same as those provided to
  hack/repo-create.sh. However, unlike hack/repo-create.sh, the repository
  directory is a single argument rather than a combination of <repo-rootdir>
  and <repo-name>! See the examples for more details.

Examples:

  Create a new repository and publish some pre-created targets.json:

    \$ export QUARRY_KEYSTORE=/tmp/keys
    \$ hack/repo-create.sh ./repo/machine-id dead-beef-cafe
    \$ hack/repo-publish.sh ./repo/machine-id/dead-beef-cafe custom-targets.json

  Then you can run the following command in a cron job to refresh the
  repository (whenver it is close to expiry):

	\$ hack/repo-refresh.sh ./repo/machine-id/dead-beef-cafe

EOF
	# shellcheck disable=SC2048 # We want to only expand to nothing or 1.
	exit ${*:+1}
}

GETOPT="$(getopt -o h --long help,keystore: -- "$@")"
eval set -- "$GETOPT"

KEY_DIR="${QUARRY_KEYSTORE:-}"
while true; do
	case "$1" in
		--keystore) KEY_DIR="$2"; shift 2 ;;
		--) shift; break ;;
		-h | --help) usage ;;
		*)           usage "unknown argument $1" ;;
	esac
done
[ -n "$KEY_DIR" ] || usage "missing --keystore argument"

[ "$#" -ge 1 ] || usage "missing <repo-dir> argument"
REPO_DIR="$1"
shift
[ "$#" -eq 0 ] || usage "too many arguments:" "$@"

BUILDER_KEYSTORE="$KEY_DIR/builder-keys"
PUBLISHER_KEYSTORE="$KEY_DIR/quarryd-keys"

# Create a combined key directory so that the builder and publisher roles can
# get bumped. In the real deployment with split signing roles, the builder
# would just refresh its own targets.json and then request quarryd to do a new
# release, but for the all-unified setup it's easier to just refresh everything
# in one shot.
keystores=("$BUILDER_KEYSTORE" "$PUBLISHER_KEYSTORE")
tmp_keystore="$(mktempdir keys)"
find "${keystores[@]}" -type f -print0 | \
	xargs -0 cp -nvt "$tmp_keystore"

hardhat repoctl refresh \
	--keystore="$tmp_keystore" \
	--repo-metadir="$REPO_DIR"
