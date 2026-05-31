#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__) || defined(__APPLE__)
#include <fcntl.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

static int failures = 0;
static int skips = 0;
static int hosts_entry_write_count = 0;
static int fail_hosts_entry_write_number = 0;
static bool fail_fflush_once = false;
static bool fail_fsync_once = false;
static bool fail_fclose_once = false;
static bool fail_lock_once = false;
static int lock_attempt_marker_fd = -1;
static bool lock_attempt_marker_sent = false;
static int write_marker_fd = -1;
static bool write_marker_sent = false;

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

static void reset_fault_injection(void)
{
    hosts_entry_write_count = 0;
    fail_hosts_entry_write_number = 0;
    fail_fflush_once = false;
    fail_fsync_once = false;
    fail_fclose_once = false;
    fail_lock_once = false;
    lock_attempt_marker_fd = -1;
    lock_attempt_marker_sent = false;
    write_marker_fd = -1;
    write_marker_sent = false;
}

static int test_fprintf(FILE* stream, const char* format, ...)
{
    if (strcmp(format, "127.0.0.1\t%s\n") == 0) {
        ++hosts_entry_write_count;
        if (write_marker_fd != -1 && !write_marker_sent) {
            char marker = 'w';
            if (write(write_marker_fd, &marker, sizeof(marker)) == (ssize_t)sizeof(marker)) {
                write_marker_sent = true;
            }
        }

        if (fail_hosts_entry_write_number == hosts_entry_write_count) {
            errno = EIO;
            return -1;
        }
    }

    va_list args;
    va_start(args, format);
    int result = vfprintf(stream, format, args);
    va_end(args);
    return result;
}

static int test_fflush(FILE* stream)
{
    if (fail_fflush_once) {
        fail_fflush_once = false;
        errno = EIO;
        return EOF;
    }

    return fflush(stream);
}

#if defined(__linux__) || defined(__APPLE__)
static int test_fsync(int fd)
{
    if (fail_fsync_once) {
        fail_fsync_once = false;
        errno = EIO;
        return -1;
    }

    return fsync(fd);
}

static int test_fcntl(int fd, int command, ...)
{
    va_list args;
    va_start(args, command);
    void* argument = va_arg(args, void*);
    va_end(args);

    if (command == F_SETLKW && lock_attempt_marker_fd != -1 && !lock_attempt_marker_sent) {
        char marker = 'l';
        if (write(lock_attempt_marker_fd, &marker, sizeof(marker)) == (ssize_t)sizeof(marker)) {
            lock_attempt_marker_sent = true;
        }
    }

    if (fail_lock_once && command == F_SETLKW) {
        fail_lock_once = false;
        errno = EIO;
        return -1;
    }

    return fcntl(fd, command, argument);
}
#endif

static int test_fclose(FILE* stream)
{
    if (fail_fclose_once) {
        fail_fclose_once = false;
        int close_result = fclose(stream);
        errno = EIO;
        return close_result == 0 ? EOF : close_result;
    }

    return fclose(stream);
}

#define main dev_env_update_hosts_main
#define fprintf test_fprintf
#define fflush test_fflush
#define fclose test_fclose
#if defined(__linux__) || defined(__APPLE__)
#define fsync test_fsync
#define fcntl test_fcntl
#endif
#include "../cc/dev-env-update-hosts.c"
#undef main
#undef fprintf
#undef fflush
#undef fclose
#if defined(__linux__) || defined(__APPLE__)
#undef fsync
#undef fcntl
#endif

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

static bool write_text_file(const char* path, const char* contents)
{
    FILE* file = fopen(path, "wb");
    if (!file) {
        fprintf(stderr, "Error creating fixture %s: %s\n", path, strerror(errno));
        return false;
    }

    if (fputs(contents, file) == EOF) {
        fprintf(stderr, "Error writing fixture %s: %s\n", path, strerror(errno));
        fclose(file);
        return false;
    }

    if (fclose(file) != 0) {
        fprintf(stderr, "Error closing fixture %s: %s\n", path, strerror(errno));
        return false;
    }

    return true;
}

static char* read_text_file(const char* path)
{
    FILE* file = fopen(path, "rb");
    if (!file) {
        fprintf(stderr, "Error opening fixture %s: %s\n", path, strerror(errno));
        return NULL;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        fprintf(stderr, "Error seeking fixture %s: %s\n", path, strerror(errno));
        fclose(file);
        return NULL;
    }

    long length = ftell(file);
    if (length < 0) {
        fprintf(stderr, "Error measuring fixture %s: %s\n", path, strerror(errno));
        fclose(file);
        return NULL;
    }

    if (fseek(file, 0, SEEK_SET) != 0) {
        fprintf(stderr, "Error rewinding fixture %s: %s\n", path, strerror(errno));
        fclose(file);
        return NULL;
    }

    char* contents = malloc((size_t)length + 1);
    if (!contents) {
        fclose(file);
        return NULL;
    }

    size_t bytes_read = fread(contents, 1, (size_t)length, file);
    if (bytes_read != (size_t)length) {
        fprintf(stderr, "Error reading fixture %s: %s\n", path, ferror(file) ? strerror(errno) : "short read");
        free(contents);
        fclose(file);
        return NULL;
    }

    contents[length] = '\0';
    if (fclose(file) != 0) {
        fprintf(stderr, "Error closing fixture %s: %s\n", path, strerror(errno));
        free(contents);
        return NULL;
    }

    return contents;
}

static void check_file_equals(const char* path, const char* expected, const char* message)
{
    char* actual = read_text_file(path);
    check_true(actual != NULL && strcmp(actual, expected) == 0, message);
    free(actual);
}

static void check_contains(const char* text, const char* needle, const char* message)
{
    check_true(text != NULL && strstr(text, needle) != NULL, message);
}

static int update_hosts_capturing_stderr(
    const char* path,
    const char** domains,
    size_t ndomains,
    const char* temp_directory,
    const char* stderr_name,
    char** stderr_output
)
{
#if defined(__linux__) || defined(__APPLE__)
    *stderr_output = NULL;
    char* stderr_path = join_path(temp_directory, stderr_name);
    if (!stderr_path) {
        check_true(false, "set up stderr capture path");
        return EXIT_FAILURE;
    }

    int capture_fd = open(stderr_path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (capture_fd == -1) {
        fprintf(stderr, "Error creating stderr capture %s: %s\n", stderr_path, strerror(errno));
        free(stderr_path);
        check_true(false, "set up stderr capture file");
        return EXIT_FAILURE;
    }

    int saved_stderr = dup(STDERR_FILENO);
    if (saved_stderr == -1) {
        fprintf(stderr, "Error saving stderr: %s\n", strerror(errno));
        close(capture_fd);
        free(stderr_path);
        check_true(false, "save stderr for capture");
        return EXIT_FAILURE;
    }

    fflush(stderr);
    if (dup2(capture_fd, STDERR_FILENO) == -1) {
        fprintf(stderr, "Error redirecting stderr: %s\n", strerror(errno));
        close(saved_stderr);
        close(capture_fd);
        free(stderr_path);
        check_true(false, "redirect stderr for capture");
        return EXIT_FAILURE;
    }

    int result = update_hosts(path, domains, ndomains);

    fflush(stderr);
    if (dup2(saved_stderr, STDERR_FILENO) == -1) {
        close(saved_stderr);
        close(capture_fd);
        free(stderr_path);
        check_true(false, "restore stderr after capture");
        return EXIT_FAILURE;
    }

    close(saved_stderr);
    close(capture_fd);
    *stderr_output = read_text_file(stderr_path);
    remove(stderr_path);
    free(stderr_path);
    return result;
#else
    (void)temp_directory;
    (void)stderr_name;
    *stderr_output = NULL;
    return update_hosts(path, domains, ndomains);
#endif
}

static char* create_hosts_fixture(const char* temp_directory, const char* name, const char* contents)
{
    char* path = join_path(temp_directory, name);
    if (!path || !write_text_file(path, contents)) {
        check_true(false, "set up hosts fixture");
        free(path);
        return NULL;
    }

    return path;
}

static void test_missing_trailing_newline_gets_separator(const char* temp_directory)
{
    reset_fault_injection();
    char* path = create_hosts_fixture(temp_directory, "missing-newline-hosts", "127.0.0.1 localhost");
    if (!path) {
        return;
    }

    const char* domains[] = { "example.test" };
    check_true(update_hosts(path, domains, 1) == EXIT_SUCCESS, "missing trailing newline update succeeds");
    check_file_equals(path, "127.0.0.1 localhost\n127.0.0.1\texample.test\n", "separator newline is inserted before new mapping");
    free(path);
}

static void test_existing_trailing_newline_is_preserved(const char* temp_directory)
{
    reset_fault_injection();
    char* path = create_hosts_fixture(temp_directory, "existing-newline-hosts", "127.0.0.1 localhost\n");
    if (!path) {
        return;
    }

    const char* domains[] = { "example.test" };
    check_true(update_hosts(path, domains, 1) == EXIT_SUCCESS, "existing trailing newline update succeeds");
    check_file_equals(path, "127.0.0.1 localhost\n127.0.0.1\texample.test\n", "existing trailing newline does not create blank separator line");
    free(path);
}

static void test_existing_crlf_trailing_newline_is_preserved(const char* temp_directory)
{
    reset_fault_injection();
    char* path = create_hosts_fixture(temp_directory, "existing-crlf-newline-hosts", "127.0.0.1 localhost\r\n");
    if (!path) {
        return;
    }

    const char* domains[] = { "example.test" };
    check_true(update_hosts(path, domains, 1) == EXIT_SUCCESS, "existing CRLF trailing newline update succeeds");
    check_file_equals(path, "127.0.0.1 localhost\r\n127.0.0.1\texample.test\n", "existing CRLF trailing newline does not create blank separator line");
    free(path);
}

static void test_empty_file_has_no_leading_separator(const char* temp_directory)
{
    reset_fault_injection();
    char* path = create_hosts_fixture(temp_directory, "empty-hosts", "");
    if (!path) {
        return;
    }

    const char* domains[] = { "empty.test" };
    check_true(update_hosts(path, domains, 1) == EXIT_SUCCESS, "empty hosts update succeeds");
    check_file_equals(path, "127.0.0.1\tempty.test\n", "empty hosts file receives only the requested mapping");
    free(path);
}

static void test_multiple_domains_are_appended_in_order(const char* temp_directory)
{
    reset_fault_injection();
    char* path = create_hosts_fixture(temp_directory, "multiple-domain-hosts", "127.0.0.1 localhost\n");
    if (!path) {
        return;
    }

    const char* domains[] = { "one.test", "two.test" };
    check_true(update_hosts(path, domains, 2) == EXIT_SUCCESS, "multiple domain update succeeds");
    check_file_equals(path, "127.0.0.1 localhost\n127.0.0.1\tone.test\n127.0.0.1\ttwo.test\n", "multiple domains are appended in request order");
    free(path);
}

static void test_existing_loopback_mapping_is_not_duplicated(const char* temp_directory)
{
    reset_fault_injection();
    char* path = create_hosts_fixture(temp_directory, "existing-loopback-hosts", "127.0.0.1 example.test");
    if (!path) {
        return;
    }

    const char* domains[] = { "example.test" };
    check_true(update_hosts(path, domains, 1) == EXIT_SUCCESS, "existing loopback mapping update succeeds");
    check_file_equals(path, "127.0.0.1 example.test", "existing loopback mapping is not duplicated or given a separator");
    free(path);
}

static void test_crlf_loopback_mapping_is_not_duplicated(const char* temp_directory)
{
    reset_fault_injection();
    char* path = create_hosts_fixture(temp_directory, "crlf-loopback-hosts", "127.0.0.1 example.test\r\n");
    if (!path) {
        return;
    }

    const char* domains[] = { "example.test" };
    check_true(update_hosts(path, domains, 1) == EXIT_SUCCESS, "CRLF loopback mapping update succeeds");
    check_file_equals(path, "127.0.0.1 example.test\r\n", "CRLF loopback mapping is not duplicated");
    free(path);
}

static void test_multiple_hostnames_on_loopback_line_are_recognized(const char* temp_directory)
{
    reset_fault_injection();
    char* path = create_hosts_fixture(
        temp_directory,
        "multiple-hostnames-loopback-hosts",
        "\n# comment-only line\n127.0.0.1 localhost example.test other.test # ignored.test\n"
    );
    if (!path) {
        return;
    }

    const char* domains[] = { "example.test", "other.test" };
    check_true(update_hosts(path, domains, 2) == EXIT_SUCCESS, "multiple hostnames loopback update succeeds");
    check_file_equals(
        path,
        "\n# comment-only line\n127.0.0.1 localhost example.test other.test # ignored.test\n",
        "multiple hostnames on one loopback line are not duplicated"
    );
    free(path);
}

static void test_comments_do_not_count_as_existing_mappings(const char* temp_directory)
{
    reset_fault_injection();
    char* path = create_hosts_fixture(
        temp_directory,
        "commented-hosts",
        "# 127.0.0.1 comment.test\n127.0.0.1 localhost # inline.test\n\n"
    );
    if (!path) {
        return;
    }

    const char* domains[] = { "comment.test", "inline.test" };
    check_true(update_hosts(path, domains, 2) == EXIT_SUCCESS, "commented hostname update succeeds");
    check_file_equals(
        path,
        "# 127.0.0.1 comment.test\n127.0.0.1 localhost # inline.test\n\n127.0.0.1\tcomment.test\n127.0.0.1\tinline.test\n",
        "commented hostnames are ignored and missing domains are appended"
    );
    free(path);
}

static void test_existing_mapping_match_is_case_insensitive(const char* temp_directory)
{
    reset_fault_injection();
    char* path = create_hosts_fixture(temp_directory, "case-insensitive-hosts", "127.0.0.1 Example.Test\n");
    if (!path) {
        return;
    }

    const char* domains[] = { "example.test" };
    check_true(update_hosts(path, domains, 1) == EXIT_SUCCESS, "case-insensitive existing mapping update succeeds");
    check_file_equals(path, "127.0.0.1 Example.Test\n", "existing mapping is matched case-insensitively");
    free(path);
}

static void test_duplicate_requested_domains_are_appended_once(const char* temp_directory)
{
    reset_fault_injection();
    char* path = create_hosts_fixture(temp_directory, "duplicate-request-hosts", "");
    if (!path) {
        return;
    }

    const char* domains[] = { "dupe.test", "DUPE.test" };
    check_true(update_hosts(path, domains, 2) == EXIT_SUCCESS, "duplicate requested domain update succeeds");
    check_file_equals(path, "127.0.0.1\tdupe.test\n", "duplicate requested domains are appended once with first spelling");
    free(path);
}

static void test_ipv6_loopback_mapping_is_not_duplicated(const char* temp_directory)
{
    reset_fault_injection();
    char* path = create_hosts_fixture(temp_directory, "ipv6-loopback-hosts", "::1 ipv6.test\n");
    if (!path) {
        return;
    }

    const char* domains[] = { "ipv6.test" };
    check_true(update_hosts(path, domains, 1) == EXIT_SUCCESS, "IPv6 loopback mapping update succeeds");
    check_file_equals(path, "::1 ipv6.test\n", "IPv6 loopback mapping is treated as already present");
    free(path);
}

static void test_crlf_ipv6_loopback_mapping_is_not_duplicated(const char* temp_directory)
{
    reset_fault_injection();
    char* path = create_hosts_fixture(temp_directory, "crlf-ipv6-loopback-hosts", "::1 ipv6.test\r\n");
    if (!path) {
        return;
    }

    const char* domains[] = { "ipv6.test" };
    check_true(update_hosts(path, domains, 1) == EXIT_SUCCESS, "CRLF IPv6 loopback mapping update succeeds");
    check_file_equals(path, "::1 ipv6.test\r\n", "CRLF IPv6 loopback mapping is treated as already present");
    free(path);
}

static void test_non_loopback_conflict_reports_and_leaves_unchanged(const char* temp_directory)
{
    reset_fault_injection();
    char* path = create_hosts_fixture(temp_directory, "non-loopback-conflict-hosts", "192.0.2.10 example.test\n");
    if (!path) {
        return;
    }

    const char* domains[] = { "example.test" };
    char* captured_stderr = NULL;
    check_true(
        update_hosts_capturing_stderr(path, domains, 1, temp_directory, "non-loopback-conflict-stderr", &captured_stderr) == EXIT_FAILURE,
        "non-loopback conflict returns failure"
    );
    check_file_equals(path, "192.0.2.10 example.test\n", "non-loopback conflict leaves hosts file unchanged");
    check_contains(captured_stderr, "already maps example.test to non-loopback address 192.0.2.10", "non-loopback conflict is reported");
    free(captured_stderr);
    free(path);
}

static void test_crlf_non_loopback_conflict_blocks_missing_domain(const char* temp_directory)
{
    reset_fault_injection();
    char* path = create_hosts_fixture(temp_directory, "crlf-non-loopback-conflict-hosts", "192.0.2.10 conflict.test\r\n");
    if (!path) {
        return;
    }

    const char* domains[] = { "conflict.test", "missing.test" };
    char* captured_stderr = NULL;
    check_true(
        update_hosts_capturing_stderr(path, domains, 2, temp_directory, "crlf-non-loopback-conflict-stderr", &captured_stderr) == EXIT_FAILURE,
        "CRLF conflict with missing domain returns failure"
    );
    check_file_equals(path, "192.0.2.10 conflict.test\r\n", "CRLF conflict blocks missing domain append and leaves hosts file unchanged");
    check_contains(captured_stderr, "already maps conflict.test to non-loopback address 192.0.2.10", "CRLF non-loopback conflict is reported");
    free(captured_stderr);
    free(path);
}

static void test_mixed_existing_and_missing_domains_append_only_missing(const char* temp_directory)
{
    reset_fault_injection();
    char* path = create_hosts_fixture(temp_directory, "mixed-existing-missing-hosts", "127.0.0.1 existing.test\n");
    if (!path) {
        return;
    }

    const char* domains[] = { "existing.test", "missing.test" };
    check_true(update_hosts(path, domains, 2) == EXIT_SUCCESS, "mixed existing and missing domain update succeeds");
    check_file_equals(path, "127.0.0.1 existing.test\n127.0.0.1\tmissing.test\n", "only missing domains are appended");
    free(path);
}

static void test_address_only_crlf_line_allows_append(const char* temp_directory)
{
    reset_fault_injection();
    char* path = create_hosts_fixture(temp_directory, "address-only-crlf-hosts", "127.0.0.1\r\n");
    if (!path) {
        return;
    }

    const char* domains[] = { "missing.test" };
    check_true(update_hosts(path, domains, 1) == EXIT_SUCCESS, "address-only CRLF line update succeeds");
    check_file_equals(path, "127.0.0.1\r\n127.0.0.1\tmissing.test\n", "address-only CRLF line is preserved before append");
    free(path);
}

static void test_conflict_blocks_all_appends(const char* temp_directory)
{
    reset_fault_injection();
    char* path = create_hosts_fixture(
        temp_directory,
        "conflict-all-or-nothing-hosts",
        "192.0.2.10 conflict.test\n192.0.2.11 other-conflict.test\n"
    );
    if (!path) {
        return;
    }

    const char* domains[] = { "conflict.test", "missing.test", "other-conflict.test" };
    char* captured_stderr = NULL;
    check_true(
        update_hosts_capturing_stderr(path, domains, 3, temp_directory, "conflict-all-or-nothing-stderr", &captured_stderr) == EXIT_FAILURE,
        "conflict with missing domain returns failure"
    );
    check_file_equals(
        path,
        "192.0.2.10 conflict.test\n192.0.2.11 other-conflict.test\n",
        "conflict blocks all appends and leaves hosts file unchanged"
    );
    check_contains(captured_stderr, "already maps conflict.test to non-loopback address 192.0.2.10", "all-or-nothing conflict is reported");
    check_contains(captured_stderr, "already maps other-conflict.test to non-loopback address 192.0.2.11", "second conflict is reported");
    free(captured_stderr);
    free(path);
}

static void test_write_failure_after_prefix_reports_failure(const char* temp_directory)
{
    reset_fault_injection();
    char* path = create_hosts_fixture(temp_directory, "partial-write-hosts", "");
    if (!path) {
        return;
    }

    const char* domains[] = { "one.test", "two.test", "three.test" };
    fail_hosts_entry_write_number = 2;
    check_true(update_hosts(path, domains, 3) == EXIT_FAILURE, "write failure after prefix returns failure");
    check_true(hosts_entry_write_count == 2, "write failure is injected after one successful host entry");
    check_file_equals(path, "127.0.0.1\tone.test\n", "partial prefix remains observable after write failure");
    free(path);
}

static void test_first_entry_write_failure_reports_attempt(const char* temp_directory)
{
    reset_fault_injection();
    char* path = create_hosts_fixture(temp_directory, "first-entry-write-failure-hosts", "");
    if (!path) {
        return;
    }

    const char* domains[] = { "one.test" };
    char* captured_stderr = NULL;
    fail_hosts_entry_write_number = 1;
    check_true(
        update_hosts_capturing_stderr(path, domains, 1, temp_directory, "first-entry-write-failure-stderr", &captured_stderr) == EXIT_FAILURE,
        "first entry write failure returns failure"
    );
    check_file_equals(path, "", "first entry write failure leaves no complete entry");
    check_contains(captured_stderr, "accepting 0 of 1 requested entries", "first entry write failure reports zero accepted entries");
    check_contains(captured_stderr, "additional entry write was attempted", "first entry write failure reports attempted mutation");
    free(captured_stderr);
    free(path);
}

static void test_separator_only_mutation_reports_failure(const char* temp_directory)
{
    reset_fault_injection();
    char* path = create_hosts_fixture(temp_directory, "separator-only-failure-hosts", "127.0.0.1 localhost");
    if (!path) {
        return;
    }

    const char* domains[] = { "separator-only.test" };
    char* captured_stderr = NULL;
    fail_hosts_entry_write_number = 1;
    check_true(
        update_hosts_capturing_stderr(path, domains, 1, temp_directory, "separator-only-failure-stderr", &captured_stderr) == EXIT_FAILURE,
        "separator-only mutation failure returns failure"
    );
    check_file_equals(path, "127.0.0.1 localhost\n", "separator-only mutation remains observable");
    check_contains(captured_stderr, "accepting 0 of 1 requested entries", "separator-only mutation reports zero accepted entries");
    check_contains(captured_stderr, "separator write was accepted", "separator-only mutation reports accepted separator");
    check_contains(captured_stderr, "hosts file may have been modified", "separator-only mutation reports possible modification");
    free(captured_stderr);
    free(path);
}

static void test_open_failure_returns_failure(const char* temp_directory)
{
    reset_fault_injection();
    char* path = join_path(temp_directory, "missing-parent/hosts");
    if (!path) {
        check_true(false, "set up missing parent path");
        return;
    }

    const char* domains[] = { "open-fail.test" };
    check_true(update_hosts(path, domains, 1) == EXIT_FAILURE, "open failure returns failure");
    free(path);
}

static void test_lock_failure_returns_failure(const char* temp_directory)
{
    reset_fault_injection();
    char* path = create_hosts_fixture(temp_directory, "lock-failure-hosts", "");
    if (!path) {
        return;
    }

    const char* domains[] = { "lock-fail.test" };
    fail_lock_once = true;
    check_true(update_hosts(path, domains, 1) == EXIT_FAILURE, "lock failure returns failure");
    check_file_equals(path, "", "lock failure leaves hosts file unchanged");
    free(path);
}

static void test_fflush_failure_returns_failure(const char* temp_directory)
{
    reset_fault_injection();
    char* path = create_hosts_fixture(temp_directory, "flush-failure-hosts", "");
    if (!path) {
        return;
    }

    const char* domains[] = { "flush-fail.test" };
    char* captured_stderr = NULL;
    fail_fflush_once = true;
    check_true(
        update_hosts_capturing_stderr(path, domains, 1, temp_directory, "flush-failure-stderr", &captured_stderr) == EXIT_FAILURE,
        "fflush failure returns failure"
    );
    check_contains(captured_stderr, "stdio accepted 1 of 1 requested entries", "fflush failure reports stdio-accepted entries");
    check_contains(captured_stderr, "durability/persistence is uncertain", "fflush failure reports uncertain durability");
    free(captured_stderr);
    free(path);
}

static void test_fsync_failure_returns_failure(const char* temp_directory)
{
    reset_fault_injection();
    char* path = create_hosts_fixture(temp_directory, "sync-failure-hosts", "");
    if (!path) {
        return;
    }

    const char* domains[] = { "sync-fail.test" };
    char* captured_stderr = NULL;
    fail_fsync_once = true;
    check_true(
        update_hosts_capturing_stderr(path, domains, 1, temp_directory, "sync-failure-stderr", &captured_stderr) == EXIT_FAILURE,
        "fsync failure returns failure"
    );
    check_file_equals(path, "127.0.0.1\tsync-fail.test\n", "fsync failure leaves attempted entry observable");
    check_contains(captured_stderr, "stdio accepted 1 of 1 requested entries", "fsync failure reports stdio-accepted entries");
    check_contains(captured_stderr, "durability/persistence is uncertain", "fsync failure reports uncertain durability");
    free(captured_stderr);
    free(path);
}

static void test_fclose_failure_returns_failure(const char* temp_directory)
{
    reset_fault_injection();
    char* path = create_hosts_fixture(temp_directory, "close-failure-hosts", "");
    if (!path) {
        return;
    }

    const char* domains[] = { "close-fail.test" };
    char* captured_stderr = NULL;
    fail_fclose_once = true;
    check_true(
        update_hosts_capturing_stderr(path, domains, 1, temp_directory, "close-failure-stderr", &captured_stderr) == EXIT_FAILURE,
        "fclose failure returns failure"
    );
    check_contains(captured_stderr, "stdio accepted 1 of 1 requested entries", "fclose failure reports stdio-accepted entries");
    check_contains(captured_stderr, "durability/persistence is uncertain", "fclose failure reports uncertain durability");
    free(captured_stderr);
    free(path);
}

static void test_concurrent_update_waits_for_lock(const char* temp_directory)
{
#if defined(__linux__) || defined(__APPLE__)
    reset_fault_injection();
    char* path = create_hosts_fixture(temp_directory, "locked-hosts", "");
    if (!path) {
        return;
    }

    int file_fd = open(path, O_RDWR);
    if (file_fd == -1) {
        fprintf(stderr, "Error opening lock fixture %s: %s\n", path, strerror(errno));
        check_true(false, "set up existing hosts lock");
        free(path);
        return;
    }

    struct flock lock;
    memset(&lock, 0, sizeof(lock));
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    if (fcntl(file_fd, F_SETLK, &lock) != 0) {
        fprintf(stderr, "Error locking fixture %s: %s\n", path, strerror(errno));
        close(file_fd);
        free(path);
        skip_check("concurrent lock assertion skipped because fixture lock could not be acquired");
        return;
    }

    int lock_attempt_pipe[2];
    if (pipe(lock_attempt_pipe) != 0) {
        fprintf(stderr, "Error creating lock-attempt marker pipe: %s\n", strerror(errno));
        lock.l_type = F_UNLCK;
        (void)fcntl(file_fd, F_SETLK, &lock);
        close(file_fd);
        free(path);
        check_true(false, "set up lock marker pipe");
        return;
    }

    int write_pipe[2];
    if (pipe(write_pipe) != 0) {
        fprintf(stderr, "Error creating write marker pipe: %s\n", strerror(errno));
        close(lock_attempt_pipe[0]);
        close(lock_attempt_pipe[1]);
        lock.l_type = F_UNLCK;
        (void)fcntl(file_fd, F_SETLK, &lock);
        close(file_fd);
        free(path);
        check_true(false, "set up write marker pipe");
        return;
    }

    pid_t child = fork();
    if (child == -1) {
        fprintf(stderr, "Error forking lock test child: %s\n", strerror(errno));
        close(lock_attempt_pipe[0]);
        close(lock_attempt_pipe[1]);
        close(write_pipe[0]);
        close(write_pipe[1]);
        lock.l_type = F_UNLCK;
        (void)fcntl(file_fd, F_SETLK, &lock);
        close(file_fd);
        free(path);
        check_true(false, "start concurrent update child");
        return;
    }

    if (child == 0) {
        close(lock_attempt_pipe[0]);
        close(write_pipe[0]);
        lock_attempt_marker_fd = lock_attempt_pipe[1];
        write_marker_fd = write_pipe[1];
        const char* domains[] = { "locked.test" };
        int result = update_hosts(path, domains, 1);
        close(lock_attempt_pipe[1]);
        close(write_pipe[1]);
        _exit(result == EXIT_SUCCESS ? 0 : 1);
    }

    close(lock_attempt_pipe[1]);
    close(write_pipe[1]);

    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(lock_attempt_pipe[0], &read_fds);
    struct timeval lock_attempt_timeout;
    lock_attempt_timeout.tv_sec = 2;
    lock_attempt_timeout.tv_usec = 0;
    int ready = select(lock_attempt_pipe[0] + 1, &read_fds, NULL, NULL, &lock_attempt_timeout);
    check_true(ready == 1, "concurrent update attempts blocking lock while existing lock is held");
    if (ready == 1) {
        char marker;
        check_true(read(lock_attempt_pipe[0], &marker, sizeof(marker)) == (ssize_t)sizeof(marker), "concurrent lock-attempt marker is read");
    }
    close(lock_attempt_pipe[0]);

    FD_ZERO(&read_fds);
    FD_SET(write_pipe[0], &read_fds);
    struct timeval short_timeout;
    short_timeout.tv_sec = 0;
    short_timeout.tv_usec = 200000;
    ready = select(write_pipe[0] + 1, &read_fds, NULL, NULL, &short_timeout);
    check_true(ready == 0, "concurrent update does not write while hosts lock is held");

    lock.l_type = F_UNLCK;
    check_true(fcntl(file_fd, F_SETLK, &lock) == 0, "existing hosts lock is released");
    close(file_fd);

    FD_ZERO(&read_fds);
    FD_SET(write_pipe[0], &read_fds);
    struct timeval long_timeout;
    long_timeout.tv_sec = 2;
    long_timeout.tv_usec = 0;
    ready = select(write_pipe[0] + 1, &read_fds, NULL, NULL, &long_timeout);
    check_true(ready == 1, "concurrent update proceeds after hosts lock is released");
    if (ready == 1) {
        char marker;
        check_true(read(write_pipe[0], &marker, sizeof(marker)) == (ssize_t)sizeof(marker), "concurrent update marker is read");
    }
    close(write_pipe[0]);

    int child_status = 0;
    check_true(waitpid(child, &child_status, 0) == child, "concurrent update child exits");
    check_true(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0, "concurrent update child succeeds");
    check_file_equals(path, "127.0.0.1\tlocked.test\n", "concurrent update writes after serialization");
    free(path);
#else
    (void)temp_directory;
    skip_check("concurrent lock assertion skipped because POSIX locking is not available");
#endif
}

int main(int argc, char** argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <temp-directory>\n", argv[0]);
        return EXIT_FAILURE;
    }

    test_missing_trailing_newline_gets_separator(argv[1]);
    test_existing_trailing_newline_is_preserved(argv[1]);
    test_existing_crlf_trailing_newline_is_preserved(argv[1]);
    test_empty_file_has_no_leading_separator(argv[1]);
    test_multiple_domains_are_appended_in_order(argv[1]);
    test_existing_loopback_mapping_is_not_duplicated(argv[1]);
    test_crlf_loopback_mapping_is_not_duplicated(argv[1]);
    test_multiple_hostnames_on_loopback_line_are_recognized(argv[1]);
    test_comments_do_not_count_as_existing_mappings(argv[1]);
    test_existing_mapping_match_is_case_insensitive(argv[1]);
    test_duplicate_requested_domains_are_appended_once(argv[1]);
    test_ipv6_loopback_mapping_is_not_duplicated(argv[1]);
    test_crlf_ipv6_loopback_mapping_is_not_duplicated(argv[1]);
    test_non_loopback_conflict_reports_and_leaves_unchanged(argv[1]);
    test_crlf_non_loopback_conflict_blocks_missing_domain(argv[1]);
    test_mixed_existing_and_missing_domains_append_only_missing(argv[1]);
    test_address_only_crlf_line_allows_append(argv[1]);
    test_conflict_blocks_all_appends(argv[1]);
    test_write_failure_after_prefix_reports_failure(argv[1]);
    test_first_entry_write_failure_reports_attempt(argv[1]);
    test_separator_only_mutation_reports_failure(argv[1]);
    test_open_failure_returns_failure(argv[1]);
    test_lock_failure_returns_failure(argv[1]);
    test_fflush_failure_returns_failure(argv[1]);
    test_fsync_failure_returns_failure(argv[1]);
    test_fclose_failure_returns_failure(argv[1]);
    test_concurrent_update_waits_for_lock(argv[1]);

    printf("summary - %d failure(s), %d skip(s)\n", failures, skips);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}