#!/bin/bash

# Copyright (C) 2026 Amutable GmbH
# repo-create.sh -- create a new repository locally

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

# keyid_to_publickey <keystore> <keyid>
function keyid_to_publickey() {
	keystore="$1"
	keyid="$2"

	pkix="$(hardhat keyctl info --pkix=base64 --keystore="$keystore" "$keyid")"
	echo "pkix:$pkix"
}

function usage() {
	[ "$#" -gt 0 ] && error "$@"
	cat <<EOF
Usage: $0
            --keystore=<key-dir=${QUARRY_KEYSTORE:-\$QUARRY_KEYSTORE}>
            --server-url=<repo-url=${REPO_SERVER_URL:-\$REPO_SERVER_URL}>
            <repo-rootdir> [<repo-name>]

Create a new Quarry repository, storing the necessary keys in <key-dir> and
placing the repository in <repo-rootdir>. (If \$QUARRY_KEYSTORE is set,
<key-dir> defaults to use that directory.)

If <repo-name> is specified then the repository is actually stored in a
subdirectory of the same name (i.e., <repodir>/<repo-name>). This feature is
particularly useful if you want a single HTTP server to serve more than one
repository. Note that the keys will still be stored in <keydir> (whether you
wish to store per-repo keys separately or as one thing is up to you).

Once the repository has been created, a sample quarry-client configuration file
is returned. This file includes the upstream Amutable OS update repository, but
that section can be removed if you wish. Be aware that the trust model defaults
to "insecure-tofu". The --server-url option indicates where the repository
*root* (i.e., <repo-rootdir>) will be hosted, and will be included in the
generated configuration file.

If you are running this script outside of
If the hardhat binary is not in the current directory,
Set

[[ TODO: We could add a root_trust that embeds the entire root.json? ]]

Examples:

  Create a new repository for the current machine in ./repo/machine-id, storing
  the keys in ./keys. To publish target files in this repository, store them in
  ./repo/machine-id/<machine-id>/targets.

    \$ $0 --keystore=./keys ./repo machine-id/\$(systemd-id128 machine-id -a 04ec60eb-87dd-434a-9733-1009bb5c4b34)

  Note that in this case the generated quarry-client.toml will hard-code the
  actual machine-id for *_root_url rather than using the "%m" expansion.
EOF
	# shellcheck disable=SC2048 # We want to only expand to nothing or 1.
	exit ${*:+1}
}

GETOPT="$(getopt -o h --long help,keystore:,server-url: -- "$@")"
eval set -- "$GETOPT"

REPO_SERVER_URL="${REPO_SERVER_URL:-}"
KEY_DIR="${QUARRY_KEYSTORE:-}"
while true; do
	case "$1" in
		--keystore)   KEY_DIR="$2";         shift 2 ;;
		--server-url) REPO_SERVER_URL="$2"; shift 2 ;;
		--) shift; break ;;
		-h | --help) usage ;;
		*)           usage "unknown argument $1" ;;
	esac
done
[ -n "$KEY_DIR" ] || usage "missing --keystore argument"

[ "$#" -ge 1 ] || usage "missing <repo-rootdir> argument"
REPO_DIR="$1"
shift
REPO_NAME="${1:-}"
[ -z "$REPO_NAME" ] || {
	REPO_DIR+="/$REPO_NAME"
	shift
}
[ "$#" -eq 0 ] || usage "too many arguments:" "$@"

[ -e "$REPO_DIR" ] && bail "Repository $REPO_DIR already exists."

[ -n "$REPO_SERVER_URL" ] || {
	warn "--server-url is empty, using http://localhost:8080/ by default"
	REPO_SERVER_URL="http://localhost:8080"
	sleep 2s
}

# Store the root, targets, and publishing (snapshot+timestamp) keys in separate
# keydirs to make sure that we never cross-pollinate the signing roles
BUILDER_KEYSTORE="$KEY_DIR/builder-keys"
targets_keyid="$(hardhat keyctl --keystore="$BUILDER_KEYSTORE" generate)"
targets_publickey="$(keyid_to_publickey "$BUILDER_KEYSTORE" "$targets_keyid")"

PUBLISHER_KEYSTORE="$KEY_DIR/quarryd-keys"
snapshot_keyid="$(hardhat keyctl --keystore="$PUBLISHER_KEYSTORE" generate)"
snapshot_publickey="$(keyid_to_publickey "$PUBLISHER_KEYSTORE" "$snapshot_keyid")"
timestamp_keyid="$(hardhat keyctl --keystore="$PUBLISHER_KEYSTORE" generate)"
timestamp_publickey="$(keyid_to_publickey "$PUBLISHER_KEYSTORE" "$timestamp_keyid")"

ROOT_KEYSTORE="$KEY_DIR/root-keys"
root_keyid="$(hardhat keyctl --keystore="$ROOT_KEYSTORE" generate)"

# Create the repository (you can also split this by pre-generating the repo's
# root.json with "hardhat root" so that the repo metadata is not touched by the
# thing generating your initial root.json, but that doesn't really make sense
# for this particular setup).
hardhat repoctl init \
	--keystore="$ROOT_KEYSTORE" \
	--repo-metadir="$REPO_DIR" \
	--keys root="$root_keyid" \
	--keys targets="$targets_publickey" \
	--keys snapshot="$snapshot_publickey" \
	--keys timestamp="$timestamp_publickey" >/dev/null

# Repo-specific data needs to live in $REPO_DIR/targets.
mkdir -p "$REPO_DIR/targets"

echo "Created repository $REPO_DIR."

cat <<EOF
============================  quarry-client.conf  ============================

# Copyright (C) 2026 Amutable GmbH

config_version = 1
cache_dir = "/var/run/quarry-client/cache"

# Official AmutableOS update repository.
[repo."updates.example.com/alpha"]
root_trust = "insecure-tofu" # NOTE: Only for testing purposes.
meta_root_url = "https://updates.example.com/base-os/nightly"
data_root_url = "https://updates.example.com/update"

# Per-machine repository.
[repo."userdata.example.com/tenant/machine/%m"]
root_trust = "insecure-tofu" # TODO: Make this use the TPM-encrypted trust model.
meta_root_url = "$REPO_SERVER_URL/$REPO_NAME"
#data_root_url = "$REPO_SERVER_URL/$REPO_NAME/targets" # NOTE: This is the default.

==============================================================================
EOF

echo "Repository target file directory: $REPO_DIR/targets"
