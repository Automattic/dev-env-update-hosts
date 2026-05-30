#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define main dev_env_update_hosts_main
#include "../cc/dev-env-update-hosts.c"
#undef main

static int failures = 0;
static int skips = 0;

static void check_true(bool condition, const char* message)
{
    if (condition) {
        printf("ok - %s\n", message);
        return;
    }

    printf("not ok - %s\n", message);
    ++failures;
}

static void skip_check(const char* message)
{
    printf("skip - %s\n", message);
    ++skips;
}

static bool starts_with(const char* value, const char* prefix)
{
    return strncmp(value, prefix, strlen(prefix)) == 0;
}

static bool is_path_below_directory(const char* path, const char* directory)
{
    size_t directory_len = strlen(directory);
    return starts_with(path, directory) && path[directory_len] == '/';
}

static char* join_path(const char* directory, const char* name)
{
    size_t directory_len = strlen(directory);
    size_t name_len = strlen(name);
    size_t needed = directory_len + name_len + 2;
    char* path = malloc(needed);
    if (!path) {
        return NULL;
    }

    int written = snprintf(path, needed, "%s/%s", directory, name);
    if (written < 0 || (size_t)written >= needed) {
        free(path);
        return NULL;
    }

    return path;
}

static bool write_executable(const char* path)
{
    FILE* file = fopen(path, "w");
    if (!file) {
        fprintf(stderr, "Error creating test executable %s: %s\n", path, strerror(errno));
        return false;
    }

    if (fputs("#!/bin/sh\nexit 0\n", file) == EOF) {
        fprintf(stderr, "Error writing test executable %s\n", path);
        fclose(file);
        return false;
    }

    if (fclose(file) != 0) {
        fprintf(stderr, "Error closing test executable %s: %s\n", path, strerror(errno));
        return false;
    }

    if (chmod(path, 0755) != 0) {
        fprintf(stderr, "Error making test executable %s executable: %s\n", path, strerror(errno));
        return false;
    }

    return true;
}

static const char* first_available_system_executable(void)
{
    const char* candidates[] = { "/bin/sh", "/usr/bin/env" };

    for (size_t candidate_index = 0; candidate_index < sizeof(candidates) / sizeof(candidates[0]); ++candidate_index) {
        struct stat candidate_stat;
        if (stat(candidates[candidate_index], &candidate_stat) == 0 && S_ISREG(candidate_stat.st_mode)) {
            return candidates[candidate_index];
        }
    }

    return NULL;
}

static void test_relative_executable_path_is_rejected(const char* temp_directory)
{
    char* relative_executable = join_path(temp_directory, "relative-helper");
    if (!relative_executable || !write_executable(relative_executable)) {
        check_true(false, "set up relative executable fixture");
        free(relative_executable);
        return;
    }

    if (chdir(temp_directory) != 0) {
        fprintf(stderr, "Error changing to test directory %s: %s\n", temp_directory, strerror(errno));
        check_true(false, "set up relative executable fixture");
        free(relative_executable);
        return;
    }

    check_true(!is_trusted_executable("relative-helper"), "relative executable path is rejected");
    free(relative_executable);
}

static void test_temp_parent_paths_are_rejected(const char* temp_directory)
{
    char* temp_executable = join_path(temp_directory, "temp-helper");
    if (!temp_executable || !write_executable(temp_executable)) {
        check_true(false, "set up temp executable fixture");
        free(temp_executable);
        return;
    }

    check_true(!has_trusted_parent_directories(temp_executable), "temp parent chain is rejected");
    check_true(!is_trusted_executable(temp_executable), "executable below temp parent is rejected");
    check_true(!has_trusted_parent_directories("/tmp/dev-env-update-hosts-parent-probe"), "/tmp parent chain is rejected");
    free(temp_executable);
}

static void test_system_executable_is_accepted_when_available(void)
{
    const char* system_executable = first_available_system_executable();
    if (!system_executable) {
        skip_check("trusted system executable assertion skipped because neither /bin/sh nor /usr/bin/env is present");
        return;
    }

    const char* candidates[] = { system_executable };
    char* trusted_helper = find_trusted_helper(candidates, sizeof(candidates) / sizeof(candidates[0]));
    check_true(trusted_helper != NULL, "trusted system executable is accepted");
    free(trusted_helper);
}

static void test_temp_symlink_helper_is_rejected(const char* temp_directory)
{
    const char* system_executable = first_available_system_executable();
    if (!system_executable) {
        skip_check("temp symlink helper assertion skipped because neither /bin/sh nor /usr/bin/env is present");
        return;
    }

    char* temp_symlink = join_path(temp_directory, "helper-symlink");
    if (!temp_symlink) {
        check_true(false, "set up temp symlink helper fixture");
        return;
    }

    if (symlink(system_executable, temp_symlink) != 0) {
        fprintf(stderr, "Error creating test symlink %s: %s\n", temp_symlink, strerror(errno));
        skip_check("temp symlink helper assertion skipped because symlink creation failed");
        free(temp_symlink);
        return;
    }

    const char* candidates[] = { temp_symlink };
    char* trusted_helper = find_trusted_helper(candidates, sizeof(candidates) / sizeof(candidates[0]));
    check_true(trusted_helper == NULL, "symlink helper below temp parent is rejected");
    free(trusted_helper);
    free(temp_symlink);
}

static void test_current_tmp_binary_is_rejected(const char* temp_directory)
{
    char* self_path = get_self_path();
    if (!self_path) {
        check_true(false, "resolve current test binary path");
        return;
    }

    char* resolved_temp_directory = realpath(temp_directory, NULL);
    if (!resolved_temp_directory) {
        fprintf(stderr, "Error resolving temp directory %s: %s\n", temp_directory, strerror(errno));
        check_true(false, "resolve temp directory path");
        free(self_path);
        return;
    }

    check_true(is_path_below_directory(self_path, resolved_temp_directory), "current test binary path is under temp directory");
    check_true(!is_trusted_executable(self_path), "current test binary under temp directory is rejected");
    free(resolved_temp_directory);
    free(self_path);
}

int main(int argc, char** argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <temp-directory>\n", argv[0]);
        return EXIT_FAILURE;
    }

    test_relative_executable_path_is_rejected(argv[1]);
    test_temp_parent_paths_are_rejected(argv[1]);
    test_system_executable_is_accepted_when_available();
    test_temp_symlink_helper_is_rejected(argv[1]);
    test_current_tmp_binary_is_rejected(argv[1]);

    printf("summary - %d failure(s), %d skip(s)\n", failures, skips);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}