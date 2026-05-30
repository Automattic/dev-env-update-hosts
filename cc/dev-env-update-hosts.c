#if defined(__linux__) || defined(__APPLE__)
#include <unistd.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#endif // defined(__linux__) || defined(__APPLE__)

#if defined(__APPLE__)
#include <errno.h>
#include <mach-o/dyld.h>
#include <sys/acl.h>
#include <sys/types.h>
#endif // defined(__APPLE__)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

static int update_hosts(const char* fname, const char** domain, size_t ndomains)
{
    FILE* hosts = fopen(fname, "r+");
    if (!hosts) {
        perror("Error opening hosts file");
        return EXIT_FAILURE;
    }

    if (-1 == fseek(hosts, 0, SEEK_END)) {
        perror("Error seeking to end of hosts file");
        fclose(hosts);
        return EXIT_FAILURE;
    }

    int status = EXIT_SUCCESS;
    for (size_t i = 0; i < ndomains; ++i) {
        if (fprintf(hosts, "127.0.0.1\t%s\n", domain[i]) < 0) {
            perror("Error writing to hosts file");
            status = EXIT_FAILURE;
            break;
        }
    }

    if (0 != fclose(hosts)) {
        perror("Error closing hosts file");
        status = EXIT_FAILURE;
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

static char* get_hosts_file_path()
{
#if defined(_WIN32)
    char* system_root = getenv("SystemRoot");
    if (!system_root || !*system_root) {
        perror("Error getting SystemRoot environment variable");
        return NULL;
    }

    const size_t max_path_length = 1024;
    char* hosts_path = (char*)malloc(max_path_length * sizeof(char));
    if (hosts_path == NULL) {
        perror("Memory allocation error");
        return NULL;
    }

    int n = snprintf(hosts_path, max_path_length, "%s\\System32\\drivers\\etc\\hosts", system_root);
    if (n < 0 || n >= (int) max_path_length) {
        if (n < 0) {
            fprintf(stderr, "Error constructing hosts file path: encoding error\n");
        }
        else {
            fprintf(stderr, "Error constructing hosts file path: path truncated (required %d bytes, buffer size %zu)\n", n + 1, max_path_length);
        }
        free(hosts_path);
        return NULL;
    }

    return hosts_path;
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
