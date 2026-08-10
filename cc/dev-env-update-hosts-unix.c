#include "dev-env-update-hosts.h"

#if defined(__linux__) || defined(__APPLE__)
#include <errno.h>
#include <string.h>

bool has_dbus(void)
{
#if defined(__APPLE__)
    return false;
#else
    const char* bus_address = getenv("DBUS_SESSION_BUS_ADDRESS");
    return bus_address && *bus_address;
#endif
}

bool is_wsl(void)
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
#endif
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

        struct stat st;
        return stat(path, &st) == 0;
    }

    if (acl_free(acl) != 0) {
        return false;
    }

    return false;
}
#endif

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
#endif

    return (st.st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

bool has_trusted_parent_directories(const char* path)
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

bool is_trusted_executable(const char* path)
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
#endif

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

char* find_trusted_helper(const char* const* candidates, size_t ncandidates)
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
char* get_self_path(void)
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
char* get_self_path(void)
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
#endif

#endif
