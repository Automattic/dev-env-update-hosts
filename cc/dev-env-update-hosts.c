#if defined(__linux__) || defined(__APPLE__)
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#endif // defined(__linux__) || defined(__APPLE__)

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#include <sys/acl.h>
#include <sys/types.h>
#endif // defined(__APPLE__)

#if defined(_WIN32)
#include <io.h>
#include <windows.h>
#endif // defined(_WIN32)

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    bool separator_write_attempted;
    bool separator_written;
    size_t entries_attempted;
    size_t entries_accepted;
    bool durability_failed;
} hosts_update_progress;

#if defined(_WIN32)
static bool get_windows_hosts_handle(FILE* hosts, HANDLE* handle)
{
    int fd = _fileno(hosts);
    if (fd == -1) {
        perror("Error getting hosts file descriptor");
        return false;
    }

    intptr_t os_handle = _get_osfhandle(fd);
    if (os_handle == -1) {
        perror("Error getting hosts file handle");
        return false;
    }

    *handle = (HANDLE)os_handle;
    return true;
}

static void print_windows_error(const char* message)
{
    fprintf(stderr, "%s: Windows error %lu\n", message, (unsigned long)GetLastError());
}
#endif // defined(_WIN32)

static bool lock_hosts_file(FILE* hosts)
{
#if defined(__linux__) || defined(__APPLE__)
    int fd = fileno(hosts);
    if (fd == -1) {
        perror("Error getting hosts file descriptor");
        return false;
    }

    struct flock lock;
    memset(&lock, 0, sizeof(lock));
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;

    for (;;) {
        if (fcntl(fd, F_SETLKW, &lock) == 0) {
            return true;
        }

        if (errno != EINTR) {
            perror("Error locking hosts file");
            return false;
        }
    }
#elif defined(_WIN32)
    HANDLE handle;
    if (!get_windows_hosts_handle(hosts, &handle)) {
        return false;
    }

    OVERLAPPED overlapped;
    memset(&overlapped, 0, sizeof(overlapped));
    if (!LockFileEx(handle, LOCKFILE_EXCLUSIVE_LOCK, 0, MAXDWORD, MAXDWORD, &overlapped)) {
        print_windows_error("Error locking hosts file");
        return false;
    }

    return true;
#else
    (void)hosts;
    fputs("Error locking hosts file: unsupported platform\n", stderr);
    return false;
#endif
}

static bool append_hosts_separator_if_needed(FILE* hosts, hosts_update_progress* progress)
{
    if (fseek(hosts, 0, SEEK_END) == -1) {
        perror("Error seeking to end of hosts file");
        return false;
    }

    long hosts_size = ftell(hosts);
    if (hosts_size == -1) {
        perror("Error determining hosts file size");
        return false;
    }

    if (hosts_size == 0) {
        return true;
    }

    if (fseek(hosts, -1, SEEK_END) == -1) {
        perror("Error seeking to end of hosts file");
        return false;
    }

    int last_char = fgetc(hosts);
    if (last_char == EOF) {
        if (ferror(hosts)) {
            perror("Error reading hosts file");
        }
        else {
            fputs("Error reading hosts file: unexpected end of file\n", stderr);
        }
        return false;
    }

    if (fseek(hosts, 0, SEEK_END) == -1) {
        perror("Error seeking to end of hosts file");
        return false;
    }

    if (last_char != '\n') {
        progress->separator_write_attempted = true;
        if (fputc('\n', hosts) == EOF) {
            perror("Error writing newline separator to hosts file");
            return false;
        }

        progress->separator_written = true;
    }

    return true;
}

static bool sync_hosts_file(FILE* hosts)
{
#if defined(__linux__) || defined(__APPLE__)
    int fd = fileno(hosts);
    if (fd == -1) {
        perror("Error getting hosts file descriptor");
        return false;
    }

    for (;;) {
        if (fsync(fd) == 0) {
            return true;
        }

        if (errno != EINTR) {
            perror("Error syncing hosts file");
            return false;
        }
    }
#elif defined(_WIN32)
    HANDLE handle;
    if (!get_windows_hosts_handle(hosts, &handle)) {
        return false;
    }

    if (!FlushFileBuffers(handle)) {
        print_windows_error("Error syncing hosts file");
        return false;
    }

    return true;
#else
    (void)hosts;
    fputs("Error syncing hosts file: unsupported platform\n", stderr);
    return false;
#endif
}

static void report_hosts_update_failure(const hosts_update_progress* progress, size_t ndomains)
{
    if (!progress->separator_write_attempted && progress->entries_attempted == 0) {
        return;
    }

    if (progress->durability_failed) {
        fprintf(stderr, "Error: hosts update failed after stdio accepted %zu of %zu requested entries", progress->entries_accepted, ndomains);
    }
    else {
        fprintf(stderr, "Error: hosts update failed after accepting %zu of %zu requested entries", progress->entries_accepted, ndomains);
    }

    if (progress->separator_written) {
        fputs("; separator write was accepted", stderr);
    }
    else if (progress->separator_write_attempted) {
        fputs("; separator write was attempted", stderr);
    }

    if (progress->entries_attempted > progress->entries_accepted) {
        fputs("; an additional entry write was attempted", stderr);
    }

    if (progress->durability_failed) {
        fputs("; hosts file may have been modified and durability/persistence is uncertain; no rollback attempted\n", stderr);
    }
    else {
        fputs("; hosts file may have been modified; no rollback attempted\n", stderr);
    }
}

static int update_hosts(const char* fname, const char** domain, size_t ndomains)
{
    FILE* hosts = fopen(fname, "r+b");
    if (!hosts) {
        perror("Error opening hosts file");
        return EXIT_FAILURE;
    }

    if (!lock_hosts_file(hosts)) {
        if (fclose(hosts) != 0) {
            perror("Error closing hosts file");
        }
        return EXIT_FAILURE;
    }

    int status = EXIT_SUCCESS;
    hosts_update_progress progress;
    memset(&progress, 0, sizeof(progress));

    if (!append_hosts_separator_if_needed(hosts, &progress)) {
        status = EXIT_FAILURE;
    }

    for (size_t i = 0; status == EXIT_SUCCESS && i < ndomains; ++i) {
        ++progress.entries_attempted;
        if (fprintf(hosts, "127.0.0.1\t%s\n", domain[i]) < 0) {
            perror("Error writing hosts entry");
            status = EXIT_FAILURE;
            break;
        }

        ++progress.entries_accepted;
    }

    if (status == EXIT_SUCCESS && fflush(hosts) != 0) {
        perror("Error flushing hosts file");
        progress.durability_failed = true;
        status = EXIT_FAILURE;
    }

    if (status == EXIT_SUCCESS && !sync_hosts_file(hosts)) {
        progress.durability_failed = true;
        status = EXIT_FAILURE;
    }

    if (0 != fclose(hosts)) {
        perror("Error closing hosts file");
        progress.durability_failed = true;
        status = EXIT_FAILURE;
    }

    if (status != EXIT_SUCCESS) {
        report_hosts_update_failure(&progress, ndomains);
    }

    return status;
}

static char* my_strdup(const char* s)
{
    if (s == NULL) {
        return NULL;
    }

    size_t len = strlen(s) + 1;
    char* p = malloc(len);
    if (p) {
        memcpy(p, s, len);
    }

    return p;
}

#if defined(__linux__) || defined(__APPLE__)

static bool has_dbus()
{
#if defined(__APPLE__)
    return false;
#else
    const char* bus_address = getenv("DBUS_SESSION_BUS_ADDRESS");
    return bus_address && *bus_address;
#endif // defined(__APPLE__)
}

static bool is_wsl()
{
#if defined(__APPLE__)
    return false;
#else
    struct utsname uts;
    if (uname(&uts) == -1) {
        perror("Error getting system information");
        return false;
    }

    return
        strstr(uts.release, "-WSL2") != NULL ||
        strstr(uts.release, "microsoft-standard") != NULL ||
        strstr(uts.release, "Microsoft") != NULL || strstr(uts.release, "microsoft") != NULL
    ;
#endif // defined(__APPLE__)
}

static bool is_absolute_path(const char* path)
{
    return path != NULL && path[0] == '/';
}

#if defined(__APPLE__)
static bool has_no_extended_acl(const char* path)
{
    errno = 0;
    acl_t acl = acl_get_file(path, ACL_TYPE_EXTENDED);
    if (!acl) {
        if (errno != ENOENT) {
            return false;
        }

        // Darwin reports ENOENT when a path has no extended ACL.
        struct stat st;
        return stat(path, &st) == 0;
    }

    if (acl_free(acl) != 0) {
        return false;
    }

    return false;
}
#endif // defined(__APPLE__)

static bool is_trusted_directory(const char* path)
{
    struct stat st;
    if (stat(path, &st) != 0) {
        return false;
    }

    if (!S_ISDIR(st.st_mode)) {
        return false;
    }

    if (st.st_uid != 0) {
        return false;
    }

#if defined(__APPLE__)
    if (!has_no_extended_acl(path)) {
        return false;
    }
#endif // defined(__APPLE__)

    return (st.st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

static bool has_trusted_parent_directories(const char* path)
{
    if (!is_absolute_path(path)) {
        return false;
    }

    char* parent = my_strdup(path);
    if (!parent) {
        perror("Error allocating memory");
        return false;
    }

    char* slash = strrchr(parent, '/');
    if (!slash) {
        free(parent);
        return false;
    }

    if (slash == parent) {
        parent[1] = '\0';
    }
    else {
        *slash = '\0';
    }

    for (;;) {
        if (!is_trusted_directory(parent)) {
            free(parent);
            return false;
        }

        if (strcmp(parent, "/") == 0) {
            free(parent);
            return true;
        }

        slash = strrchr(parent, '/');
        if (!slash) {
            free(parent);
            return false;
        }

        if (slash == parent) {
            parent[1] = '\0';
        }
        else {
            *slash = '\0';
        }
    }
}

static bool is_trusted_executable(const char* path)
{
    struct stat st;
    if (!is_absolute_path(path) || stat(path, &st) != 0) {
        return false;
    }

    if (!S_ISREG(st.st_mode)) {
        return false;
    }

    if (st.st_uid != 0) {
        return false;
    }

    if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        return false;
    }

#if defined(__APPLE__)
    if (!has_no_extended_acl(path)) {
        return false;
    }
#endif // defined(__APPLE__)

    if (access(path, X_OK) != 0) {
        return false;
    }

    return has_trusted_parent_directories(path);
}

static char* resolve_trusted_helper_candidate(const char* path)
{
    if (!is_absolute_path(path) || !has_trusted_parent_directories(path)) {
        return NULL;
    }

    char* resolved_path = realpath(path, NULL);
    if (!resolved_path) {
        return NULL;
    }

    if (!is_trusted_executable(resolved_path)) {
        free(resolved_path);
        return NULL;
    }

    return resolved_path;
}

static char* find_trusted_helper(const char* const* candidates, size_t ncandidates)
{
    for (size_t i = 0; i < ncandidates; ++i) {
        char* resolved_path = resolve_trusted_helper_candidate(candidates[i]);
        if (resolved_path) {
            return resolved_path;
        }
    }

    return NULL;
}

#if defined(__linux__)
static char* get_self_path()
{
    size_t path_len = 1024;

    for (;;) {
        char* path = malloc(path_len);
        if (!path) {
            perror("Error allocating memory");
            return NULL;
        }

        ssize_t bytes_read = readlink("/proc/self/exe", path, path_len - 1);
        if (bytes_read < 0) {
            perror("Error resolving executable path");
            free(path);
            return NULL;
        }

        if ((size_t)bytes_read < path_len - 1) {
            path[bytes_read] = '\0';
            return path;
        }

        free(path);
        if (path_len > 1024 * 1024) {
            fputs("Error resolving executable path: path too long\n", stderr);
            return NULL;
        }
        path_len *= 2;
    }
}
#elif defined(__APPLE__)
static char* get_self_path()
{
    uint32_t path_len = 1024;
    char* path = NULL;

    for (;;) {
        path = malloc(path_len);
        if (!path) {
            perror("Error allocating memory");
            return NULL;
        }

        uint32_t required_len = path_len;
        if (_NSGetExecutablePath(path, &required_len) == 0) {
            char* resolved_path = realpath(path, NULL);
            free(path);
            if (!resolved_path) {
                perror("Error resolving executable path");
                return NULL;
            }
            return resolved_path;
        }

        free(path);
        if (required_len <= path_len) {
            fputs("Error resolving executable path\n", stderr);
            return NULL;
        }
        path_len = required_len;
    }
}
#endif // defined(__linux__)

#endif // defined(__linux__) || defined(__APPLE__)

static bool is_ascii_alnum(unsigned char c)
{
    return (c >= '0' && c <= '9') ||
           (c >= 'A' && c <= 'Z') ||
           (c >= 'a' && c <= 'z');
}

static unsigned char ascii_lower(unsigned char c)
{
    if (c >= 'A' && c <= 'Z') {
        return (unsigned char)(c + ('a' - 'A'));
    }

    return c;
}

static bool is_valid_label(const char* label, size_t len)
{
    if (len == 0 || len > 63 || label[0] == '-' || label[len - 1] == '-') {
        return false;
    }

    for (size_t i = 0; i < len; ++i) {
        if (!is_ascii_alnum((unsigned char)label[i]) && label[i] != '-') {
            return false;
        }
    }

    return true;
}

static const size_t MAX_DOMAIN_LEN = 255;

static bool is_valid_domain(const char* s)
{
    if (s == NULL || strnlen(s, MAX_DOMAIN_LEN + 1) > MAX_DOMAIN_LEN) {
        return false;
    }

    const char* label_start = s;

    for (const char* p = s; ; ++p) {
        if (*p == '.' || *p == '\0') {
            if (!is_valid_label(label_start, (size_t)(p - label_start))) {
                return false;
            }

            if (*p == '\0') {
                return true;
            }

            label_start = p + 1;
        }
    }
}

static bool domain_equals_ignore_case(const char* a, const char* b)
{
    while (*a != '\0' && *b != '\0') {
        if (ascii_lower((unsigned char)*a) != ascii_lower((unsigned char)*b)) {
            return false;
        }

        ++a;
        ++b;
    }

    return *a == *b;
}

static bool domain_was_seen(const char** domains, size_t ndomains, const char* domain)
{
    for (size_t i = 0; i < ndomains; ++i) {
        if (domain_equals_ignore_case(domains[i], domain)) {
            return true;
        }
    }

    return false;
}

#if defined(_WIN32) || defined(DEV_ENV_UPDATE_HOSTS_TESTING)
static const char WINDOWS_HOSTS_PATH_SUFFIX[] = "\\drivers\\etc\\hosts";
static const char WINDOWS_SYSNATIVE_SUFFIX[] = "\\Sysnative";

#if defined(_WIN32)
typedef UINT (WINAPI *windows_directory_api)(LPSTR, UINT);
typedef UINT windows_directory_api_length;
#define WINDOWS_DIRECTORY_INITIAL_CAPACITY MAX_PATH
#else
typedef unsigned int (*windows_directory_api)(char*, unsigned int);
typedef unsigned int windows_directory_api_length;
#define WINDOWS_DIRECTORY_INITIAL_CAPACITY 260
#endif

enum windows_wow64_status {
    WINDOWS_WOW64_STATUS_ERROR,
    WINDOWS_WOW64_STATUS_NOT_WOW64,
    WINDOWS_WOW64_STATUS_WOW64,
};

typedef char* (*windows_directory_resolver)(void* context);
typedef enum windows_wow64_status (*windows_wow64_status_resolver)(void* context);

struct windows_native_system_directory_resolver {
    void* context;
    windows_directory_resolver get_native_system_directory;
    windows_wow64_status_resolver get_wow64_status;
    windows_directory_resolver get_windows_directory;
    windows_directory_resolver get_system_directory;
};

static char* make_windows_path_with_suffix(const char* base_path, size_t base_path_length, const char* suffix, size_t suffix_size)
{
    if (base_path == NULL || suffix == NULL || suffix_size == 0 || base_path_length > SIZE_MAX - suffix_size) {
        return NULL;
    }

    size_t path_length = base_path_length + suffix_size;
    char* path = (char*)malloc(path_length);
    if (path == NULL) {
        perror("Memory allocation error");
        return NULL;
    }

    memcpy(path, base_path, base_path_length);
    memcpy(path + base_path_length, suffix, suffix_size);
    return path;
}

static char* make_windows_hosts_file_path_from_system_dir(const char* system_dir, size_t system_dir_length)
{
    return make_windows_path_with_suffix(system_dir, system_dir_length, WINDOWS_HOSTS_PATH_SUFFIX, sizeof(WINDOWS_HOSTS_PATH_SUFFIX));
}

static char* get_windows_directory_from_api(windows_directory_api get_directory, const char* api_name)
{
    if (get_directory == NULL) {
        return NULL;
    }

    size_t directory_capacity = WINDOWS_DIRECTORY_INITIAL_CAPACITY;
    char* directory = (char*)malloc(directory_capacity);
    if (directory == NULL) {
        perror("Memory allocation error");
        return NULL;
    }

    windows_directory_api_length directory_length = 0;
    for (;;) {
        if (directory_capacity > UINT_MAX) {
            fprintf(stderr, "Error resolving Windows directory with %s: required buffer size exceeds Windows API limit\n", api_name);
            free(directory);
            return NULL;
        }

        directory_length = get_directory(directory, (windows_directory_api_length)directory_capacity);
        if (directory_length == 0) {
#if defined(_WIN32)
            fprintf(stderr, "Error resolving Windows directory with %s: Windows error %lu\n", api_name, (unsigned long)GetLastError());
#else
            fprintf(stderr, "Error resolving Windows directory with %s\n", api_name);
#endif
            free(directory);
            return NULL;
        }

        if ((size_t)directory_length < directory_capacity) {
            return directory;
        }

        if (directory_length == UINT_MAX) {
            fprintf(stderr, "Error resolving Windows directory with %s: required buffer size exceeds Windows API limit\n", api_name);
            free(directory);
            return NULL;
        }

        size_t required_capacity = (size_t)directory_length + 1;
        char* resized_directory = (char*)realloc(directory, required_capacity);
        if (resized_directory == NULL) {
            perror("Memory allocation error");
            free(directory);
            return NULL;
        }

        directory = resized_directory;
        directory_capacity = required_capacity;
    }
}

static char* resolve_windows_native_system_directory_with_resolver(const struct windows_native_system_directory_resolver* resolver)
{
    if (resolver == NULL || resolver->get_wow64_status == NULL || resolver->get_windows_directory == NULL || resolver->get_system_directory == NULL) {
        return NULL;
    }

    if (resolver->get_native_system_directory != NULL) {
        return resolver->get_native_system_directory(resolver->context);
    }

    enum windows_wow64_status wow64_status = resolver->get_wow64_status(resolver->context);
    if (wow64_status == WINDOWS_WOW64_STATUS_ERROR) {
        return NULL;
    }

    if (wow64_status == WINDOWS_WOW64_STATUS_WOW64) {
        char* windows_directory = resolver->get_windows_directory(resolver->context);
        if (windows_directory == NULL) {
            return NULL;
        }

        char* sysnative_directory = make_windows_path_with_suffix(windows_directory, strlen(windows_directory), WINDOWS_SYSNATIVE_SUFFIX, sizeof(WINDOWS_SYSNATIVE_SUFFIX));
        if (sysnative_directory == NULL) {
            fprintf(stderr, "Error constructing Windows native system directory from Windows directory result\n");
        }
        free(windows_directory);

        return sysnative_directory;
    }

    return resolver->get_system_directory(resolver->context);
}
#endif // defined(_WIN32) || defined(DEV_ENV_UPDATE_HOSTS_TESTING)

#if defined(_WIN32)
typedef BOOL (WINAPI *is_wow64_process_api)(HANDLE, PBOOL);

struct windows_api_resolver_context {
    HMODULE kernel32;
    windows_directory_api get_native_system_directory_api;
};

static enum windows_wow64_status get_windows_wow64_status(HMODULE kernel32)
{
    is_wow64_process_api is_wow64_process = (is_wow64_process_api)GetProcAddress(kernel32, "IsWow64Process");
    if (is_wow64_process == NULL) {
        return WINDOWS_WOW64_STATUS_NOT_WOW64;
    }

    BOOL is_wow64 = FALSE;
    if (!is_wow64_process(GetCurrentProcess(), &is_wow64)) {
        fprintf(stderr, "Error determining Windows WOW64 status with IsWow64Process: Windows error %lu\n", (unsigned long)GetLastError());
        return WINDOWS_WOW64_STATUS_ERROR;
    }

    return is_wow64 ? WINDOWS_WOW64_STATUS_WOW64 : WINDOWS_WOW64_STATUS_NOT_WOW64;
}

static char* get_native_system_directory_from_context(void* context)
{
    struct windows_api_resolver_context* resolver_context = (struct windows_api_resolver_context*)context;
    return get_windows_directory_from_api(resolver_context->get_native_system_directory_api, "GetNativeSystemDirectoryA");
}

static enum windows_wow64_status get_wow64_status_from_context(void* context)
{
    struct windows_api_resolver_context* resolver_context = (struct windows_api_resolver_context*)context;
    return get_windows_wow64_status(resolver_context->kernel32);
}

static char* get_windows_directory_from_context(void* context)
{
    (void)context;
    return get_windows_directory_from_api(GetWindowsDirectoryA, "GetWindowsDirectoryA");
}

static char* get_system_directory_from_context(void* context)
{
    (void)context;
    return get_windows_directory_from_api(GetSystemDirectoryA, "GetSystemDirectoryA");
}

static char* get_windows_native_system_directory(void)
{
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    if (kernel32 == NULL) {
        fprintf(stderr, "Error resolving Windows native system directory with GetModuleHandleA: Windows error %lu\n", (unsigned long)GetLastError());
        return NULL;
    }

    struct windows_api_resolver_context context = {
        kernel32,
        (windows_directory_api)GetProcAddress(kernel32, "GetNativeSystemDirectoryA")
    };
    struct windows_native_system_directory_resolver resolver = {
        &context,
        context.get_native_system_directory_api != NULL ? get_native_system_directory_from_context : NULL,
        get_wow64_status_from_context,
        get_windows_directory_from_context,
        get_system_directory_from_context,
    };

    return resolve_windows_native_system_directory_with_resolver(&resolver);
}

static char* get_windows_hosts_file_path()
{
    char* system_dir = get_windows_native_system_directory();
    if (system_dir == NULL) {
        return NULL;
    }

    char* hosts_path = make_windows_hosts_file_path_from_system_dir(system_dir, strlen(system_dir));
    if (hosts_path == NULL) {
        fprintf(stderr, "Error constructing hosts file path from Windows native system directory result\n");
    }
    free(system_dir);

    return hosts_path;
}
#endif // defined(_WIN32)

static char* get_hosts_file_path()
{
#if defined(_WIN32)
    return get_windows_hosts_file_path();
#else
    return my_strdup("/etc/hosts");
#endif
}

static const char* get_program_name(const char* argv0)
{
    const char* prog = (argv0 && argv0[0]) ? argv0 : "dev-env-update-hosts";
    const char* unix_slash = strrchr(prog, '/');
    const char* win_slash  = strrchr(prog, '\\');
    const char* slash      = NULL;

    if (unix_slash && win_slash) {
        slash = (unix_slash > win_slash) ? unix_slash : win_slash;
    }
    else if (unix_slash) {
        slash = unix_slash;
    }
    else {
        slash = win_slash;
    }

    return (slash && slash[1] != '\0') ? slash + 1 : prog;
}

static int escalate_privilege(int argc, char** argv) {
#if defined(__linux__) || defined(__APPLE__)
    if (geteuid() != 0) {
        const char* pkexec_candidates[] = { "/usr/bin/pkexec" };
        const char* sudo_candidates[] = { "/usr/bin/sudo", "/bin/sudo" };

        char* elevator = NULL;
        if (has_dbus() && !is_wsl()) {
            elevator = find_trusted_helper(pkexec_candidates, sizeof(pkexec_candidates) / sizeof(pkexec_candidates[0]));
        }

        if (!elevator) {
            elevator = find_trusted_helper(sudo_candidates, sizeof(sudo_candidates) / sizeof(sudo_candidates[0]));
        }

        if (!elevator) {
            fputs("Error: No suitable privilege escalation tool found\n", stderr);
            return EXIT_FAILURE;
        }

        char* self_path = get_self_path();
        if (!self_path) {
            free(elevator);
            return EXIT_FAILURE;
        }

        if (!is_trusted_executable(self_path)) {
            fprintf(stderr, "Error: Refusing to elevate untrusted executable path: %s\n", self_path);
            free(elevator);
            free(self_path);
            return EXIT_FAILURE;
        }

        char* new_argv[argc + 2];
        new_argv[0] = (char*)elevator;
        new_argv[1] = self_path;
        for (int i = 1; i < argc; ++i) {
            new_argv[i + 1] = argv[i];
        }
        new_argv[argc + 1] = NULL;

        execv(elevator, new_argv);
        perror("Error executing privilege escalation tool");
        free(elevator);
        free(self_path);
        return EXIT_FAILURE;
    }
#endif
    return EXIT_SUCCESS;
}

int main(int argc, char** argv)
{
    if (argc < 2) {
        const char* prog = get_program_name((argc > 0 && argv != NULL) ? argv[0] : NULL);

        fprintf(stderr, "Usage: %s <domain1> [<domain2> ...]\n", prog);
        return EXIT_FAILURE;
    }

    const char* domains[argc - 1];
    size_t ndomains = 0;
    bool has_invalid_domain = false;

    for (int i = 1; i < argc; ++i) {
        if (!is_valid_domain(argv[i])) {
            fprintf(stderr, "Error: Invalid domain argument: %s\n", argv[i]);
            has_invalid_domain = true;
        }
        else if (!domain_was_seen(domains, ndomains, argv[i])) {
            domains[ndomains++] = argv[i];
        }
    }

    if (has_invalid_domain) {
        return EXIT_FAILURE;
    }

    if (ndomains == 0) {
        fputs("Error: No valid domains provided\n", stderr);
        return EXIT_FAILURE;
    }

    if (escalate_privilege(argc, argv) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    char* hosts = get_hosts_file_path();
    if (!hosts) {
        fputs("Error: Unable to determine hosts file path\n", stderr);
        return EXIT_FAILURE;
    }

    int code = update_hosts(hosts, domains, ndomains);
    free(hosts);
    return code;
}
