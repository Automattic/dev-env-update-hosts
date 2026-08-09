#!/bin/sh

set -eu

repo_dir=$(
    CDPATH=
    cd "$(dirname "$0")/.."
    pwd
)
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/dev-env-update-hosts-windows-path-tests.XXXXXX")

cleanup() {
    rm -rf "$tmp_dir"
}
trap cleanup EXIT HUP INT TERM

binary="$tmp_dir/windows-hosts-path-harness"

cc -Wall -O2 -Werror -o "$binary" "$repo_dir/tests/windows_hosts_path_harness.c"
"$binary"

resolver_source_file="$repo_dir/cc/dev-env-update-hosts.c"

outer_open_count=$(grep -cFx '#if defined(_WIN32) || defined(DEV_ENV_UPDATE_HOSTS_TESTING)' "$resolver_source_file")
outer_close_count=$(grep -cFx '#endif // defined(_WIN32) || defined(DEV_ENV_UPDATE_HOSTS_TESTING)' "$resolver_source_file")
inner_sentinel_count=$(grep -cFx 'typedef BOOL (WINAPI *is_wow64_process_api)(HANDLE, PBOOL);' "$resolver_source_file")

if [ "$outer_open_count" -ne 1 ] || [ "$outer_close_count" -ne 1 ] || [ "$inner_sentinel_count" -ne 1 ]; then
    echo "not ok - Windows resolver block guard anchors are not unique (outer_open=$outer_open_count outer_close=$outer_close_count inner_sentinel=$inner_sentinel_count)"
    exit 1
fi

echo "ok - Windows resolver block guard anchors are unique"

outer_block=$(sed -n '/^#if defined(_WIN32) || defined(DEV_ENV_UPDATE_HOSTS_TESTING)$/,/^#endif \/\/ defined(_WIN32) || defined(DEV_ENV_UPDATE_HOSTS_TESTING)$/p' "$resolver_source_file")
inner_block=$(awk '
    /^#endif \/\/ defined\(_WIN32\) \|\| defined\(DEV_ENV_UPDATE_HOSTS_TESTING\)$/ { collecting = 1; next }
    collecting && /^#endif \/\/ defined\(_WIN32\)$/ { print; exit }
    collecting { print }
' "$resolver_source_file")

windows_resolver_source=$(printf '%s\n%s\n' "$outer_block" "$inner_block")

if printf '%s\n' "$windows_resolver_source" | grep -Eiq 'SystemRoot|getenv|_wgetenv|_dupenv_s|GetEnvironmentVariable|GetEnvironmentStrings|ExpandEnvironmentStrings|windir|SHGetFolderPath|SHGetKnownFolderPath|RegOpenKey|ProcessEnvironmentBlock|RtlGetCurrentPeb'; then
    echo "not ok - Windows resolver source uses mutable environment fallback"
    exit 1
fi

echo "ok - Windows resolver source does not use mutable environment fallback"
