#!/bin/sh

set -eu

repo_dir=$(
    CDPATH=
    cd "$(dirname "$0")/.."
    pwd
)
tmp_dir=$(mktemp -d /tmp/dev-env-update-hosts-tests.XXXXXX)

cleanup() {
    rm -rf "$tmp_dir"
}
trap cleanup EXIT HUP INT TERM

binary="$tmp_dir/trust-policy-harness"

cc -Wall -O2 -o "$binary" "$repo_dir/tests/trust_policy_harness.c"
"$binary" "$tmp_dir"