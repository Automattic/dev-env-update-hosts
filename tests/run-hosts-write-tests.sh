#!/bin/sh

set -eu

repo_dir=$(
    CDPATH=
    cd "$(dirname "$0")/.."
    pwd
)
tmp_dir=$(mktemp -d /tmp/dev-env-update-hosts-hosts-tests.XXXXXX)

cleanup() {
    rm -rf "$tmp_dir"
}
trap cleanup EXIT HUP INT TERM

binary="$tmp_dir/hosts-write-harness"

cc -Wall -O2 -o "$binary" "$repo_dir/tests/hosts_write_harness.c"
"$binary" "$tmp_dir"