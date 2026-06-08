#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define DEV_ENV_UPDATE_HOSTS_TESTING
#define main dev_env_update_hosts_main
#include "../cc/dev-env-update-hosts.c"
#undef main

static int failures = 0;

static void check_true(bool condition, const char* message)
{
    if (condition) {
        printf("ok - %s\n", message);
        return;
    }

    printf("not ok - %s\n", message);
    ++failures;
}

static void check_string_equal(const char* actual, const char* expected, const char* message)
{
    check_true(actual != NULL && strcmp(actual, expected) == 0, message);
}

struct mock_windows_resolver_context {
    enum windows_wow64_status wow64_status;
    const char* native_system_directory;
    const char* windows_directory;
    const char* system_directory;
    bool fail_native_system_directory;
    bool fail_windows_directory;
    bool fail_system_directory;
};

struct mock_directory_api_context {
    const char* directory;
    unsigned int first_required_length;
    unsigned int calls;
};

static struct mock_directory_api_context* resizing_directory_context = NULL;

static char* duplicate_string(const char* value)
{
    size_t length = strlen(value) + 1;
    char* duplicated = (char*)malloc(length);
    if (duplicated != NULL) {
        memcpy(duplicated, value, length);
    }

    return duplicated;
}

static char* mock_native_system_directory(void* context)
{
    struct mock_windows_resolver_context* mock = (struct mock_windows_resolver_context*)context;
    if (mock->fail_native_system_directory || mock->native_system_directory == NULL) {
        return NULL;
    }

    return duplicate_string(mock->native_system_directory);
}

static enum windows_wow64_status mock_wow64_status(void* context)
{
    struct mock_windows_resolver_context* mock = (struct mock_windows_resolver_context*)context;
    return mock->wow64_status;
}

static char* mock_windows_directory(void* context)
{
    struct mock_windows_resolver_context* mock = (struct mock_windows_resolver_context*)context;
    if (mock->fail_windows_directory || mock->windows_directory == NULL) {
        return NULL;
    }

    return duplicate_string(mock->windows_directory);
}

static char* mock_system_directory(void* context)
{
    struct mock_windows_resolver_context* mock = (struct mock_windows_resolver_context*)context;
    if (mock->fail_system_directory || mock->system_directory == NULL) {
        return NULL;
    }

    return duplicate_string(mock->system_directory);
}

static unsigned int resizing_directory_api(char* buffer, unsigned int buffer_size)
{
    struct mock_directory_api_context* context = resizing_directory_context;

    ++context->calls;
    if (context->calls == 1) {
        (void)buffer;
        (void)buffer_size;
        return context->first_required_length;
    }

    size_t directory_length = strlen(context->directory);
    if (buffer_size <= directory_length) {
        return (unsigned int)directory_length + 1;
    }

    memcpy(buffer, context->directory, directory_length + 1);
    return (unsigned int)directory_length;
}

static char* resolve_with_mock(struct mock_windows_resolver_context* context, bool native_api_available)
{
    struct windows_native_system_directory_resolver resolver = {
        context,
        native_api_available ? mock_native_system_directory : NULL,
        mock_wow64_status,
        mock_windows_directory,
        mock_system_directory,
    };

    return resolve_windows_native_system_directory_with_resolver(&resolver);
}

static void test_normal_native_system_directory_path(void)
{
    const char system_dir[] = "C:\\Windows\\System32";
    char* hosts_path = make_windows_hosts_file_path_from_system_dir(system_dir, strlen(system_dir));

    check_string_equal(hosts_path, "C:\\Windows\\System32\\drivers\\etc\\hosts", "normal native system directory path is suffixed");
    free(hosts_path);
}

static void test_exact_suffix_and_null_placement(void)
{
    const char system_dir[] = "C:\\Windows\\System32";
    size_t system_dir_length = strlen(system_dir);
    size_t expected_length = system_dir_length + strlen(WINDOWS_HOSTS_PATH_SUFFIX);
    char* hosts_path = make_windows_hosts_file_path_from_system_dir(system_dir, system_dir_length);

    check_true(hosts_path != NULL, "exact suffix/null placement path is constructed");
    if (hosts_path != NULL) {
        check_true(strlen(hosts_path) == expected_length, "constructed path length excludes exactly one null terminator");
        check_true(hosts_path[expected_length] == '\0', "constructed path null terminator is placed after suffix");
        check_true(strcmp(hosts_path + system_dir_length, WINDOWS_HOSTS_PATH_SUFFIX) == 0, "suffix begins at native system directory boundary");
    }

    free(hosts_path);
}

static void test_empty_native_system_directory_input(void)
{
    char* hosts_path = make_windows_hosts_file_path_from_system_dir("", 0);

    check_true(hosts_path == NULL, "empty native system directory input is rejected");
    free(hosts_path);
}

static void test_overflow_is_rejected_before_allocation(void)
{
    char* hosts_path = make_windows_hosts_file_path_from_system_dir("ignored", SIZE_MAX);

    check_true(hosts_path == NULL, "overflow-sized native system directory length is rejected");
}

static void test_native_system_directory_api_success_is_used(void)
{
    struct mock_windows_resolver_context context = {
        WINDOWS_WOW64_STATUS_WOW64,
        "C:\\Windows\\System32",
        "C:\\Windows",
        "C:\\Windows\\SysWOW64",
        false,
        false,
        false,
    };
    char* system_dir = resolve_with_mock(&context, true);

    check_string_equal(system_dir, "C:\\Windows\\System32", "native system directory API success is used first");
    free(system_dir);
}

static void test_native_api_unavailable_wow64_uses_sysnative(void)
{
    struct mock_windows_resolver_context context = {
        WINDOWS_WOW64_STATUS_WOW64,
        NULL,
        "C:\\Windows",
        "C:\\Windows\\SysWOW64",
        false,
        false,
        false,
    };
    char* system_dir = resolve_with_mock(&context, false);

    check_string_equal(system_dir, "C:\\Windows\\Sysnative", "native API unavailable and WOW64 uses Sysnative path");
    free(system_dir);
}

static void test_wow64_sysnative_strips_trailing_backslash(void)
{
    struct mock_windows_resolver_context context = {
        WINDOWS_WOW64_STATUS_WOW64,
        NULL,
        "C:\\",
        "C:\\Windows\\SysWOW64",
        false,
        false,
        false,
    };
    char* system_dir = resolve_with_mock(&context, false);

    check_string_equal(system_dir, "C:\\Sysnative", "WOW64 with drive-root Windows directory strips trailing backslash before Sysnative suffix");
    free(system_dir);
}

static void test_native_api_unavailable_not_wow64_uses_system_directory(void)
{
    struct mock_windows_resolver_context context = {
        WINDOWS_WOW64_STATUS_NOT_WOW64,
        NULL,
        "C:\\Windows",
        "C:\\Windows\\System32",
        false,
        false,
        false,
    };
    char* system_dir = resolve_with_mock(&context, false);

    check_string_equal(system_dir, "C:\\Windows\\System32", "native API unavailable and non-WOW64 uses system directory fallback");
    free(system_dir);
}

static void test_wow64_status_error_fails_closed(void)
{
    struct mock_windows_resolver_context context = {
        WINDOWS_WOW64_STATUS_ERROR,
        NULL,
        "C:\\Windows",
        "C:\\Windows\\System32",
        false,
        false,
        false,
    };
    char* system_dir = resolve_with_mock(&context, false);

    check_true(system_dir == NULL, "WOW64 status error fails closed");
    free(system_dir);
}

static void test_directory_api_failure_fails_closed(void)
{
    struct mock_windows_resolver_context native_failure_context = {
        WINDOWS_WOW64_STATUS_NOT_WOW64,
        "C:\\Windows\\System32",
        "C:\\Windows",
        "C:\\Windows\\System32",
        true,
        false,
        false,
    };
    char* system_dir = resolve_with_mock(&native_failure_context, true);
    check_true(system_dir == NULL, "native directory API failure fails closed");
    free(system_dir);

    struct mock_windows_resolver_context windows_failure_context = {
        WINDOWS_WOW64_STATUS_WOW64,
        NULL,
        "C:\\Windows",
        "C:\\Windows\\System32",
        false,
        true,
        false,
    };
    system_dir = resolve_with_mock(&windows_failure_context, false);
    check_true(system_dir == NULL, "WOW64 Windows directory API failure fails closed");
    free(system_dir);

    struct mock_windows_resolver_context system_failure_context = {
        WINDOWS_WOW64_STATUS_NOT_WOW64,
        NULL,
        "C:\\Windows",
        "C:\\Windows\\System32",
        false,
        false,
        true,
    };
    system_dir = resolve_with_mock(&system_failure_context, false);
    check_true(system_dir == NULL, "system directory API fallback failure fails closed");
    free(system_dir);
}

static void test_directory_api_buffer_resize(void)
{
    struct mock_directory_api_context context = {
        "C:\\Windows\\System32\\VeryLongDirectoryName",
        WINDOWS_DIRECTORY_INITIAL_CAPACITY + 16,
        0,
    };
    resizing_directory_context = &context;
    char* directory = get_windows_directory_from_api(resizing_directory_api, "MockDirectoryApi");

    check_string_equal(directory, context.directory, "directory API buffer resize retries with required capacity");
    check_true(context.calls == 2, "directory API buffer resize calls API twice");
    free(directory);
}

int main(void)
{
    test_normal_native_system_directory_path();
    test_exact_suffix_and_null_placement();
    test_empty_native_system_directory_input();
    test_overflow_is_rejected_before_allocation();
    test_native_system_directory_api_success_is_used();
    test_native_api_unavailable_wow64_uses_sysnative();
    test_wow64_sysnative_strips_trailing_backslash();
    test_native_api_unavailable_not_wow64_uses_system_directory();
    test_wow64_status_error_fails_closed();
    test_directory_api_failure_fails_closed();
    test_directory_api_buffer_resize();

    printf("summary - %d failure(s)\n", failures);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}