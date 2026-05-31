#!/bin/sh

set -eu

repo_dir=$(
    CDPATH=
    cd "$(dirname "$0")/.."
    pwd
)
tmp_dir=$(mktemp -d /tmp/dev-env-update-hosts-windows-path-tests.XXXXXX)

cleanup() {
    rm -rf "$tmp_dir"
}
trap cleanup EXIT HUP INT TERM

binary="$tmp_dir/windows-hosts-path-harness"

cc -Wall -O2 -Werror -o "$binary" "$repo_dir/tests/windows_hosts_path_harness.c"
"$binary"

windows_resolver_source=$(sed -n '/#if defined(_WIN32) || defined(DEV_ENV_UPDATE_HOSTS_TESTING)/,/#endif \/\/ defined(_WIN32)/p' "$repo_dir/cc/dev-env-update-hosts.c")

if printf '%s\n' "$windows_resolver_source" | grep -Eq 'SystemRoot|getenv|_wgetenv|_dupenv_s|GetEnvironmentVariable|GetEnvironmentStrings|ExpandEnvironmentStrings'; then
    echo "not ok - Windows resolver source does not use mutable environment fallback"
    exit 1
fi

echo "ok - Windows resolver source does not use mutable environment fallback"
