#include "dev-env-update-hosts.h"

#include <limits.h>
#include <string.h>

#if defined(_WIN32) || defined(DEV_ENV_UPDATE_HOSTS_TESTING)
const char WINDOWS_HOSTS_PATH_SUFFIX[] = "\\drivers\\etc\\hosts";
const char WINDOWS_SYSNATIVE_SUFFIX[] = "\\Sysnative";

static char* make_windows_path_with_suffix_impl(const char* base_path, size_t base_path_length, const char* suffix, size_t suffix_size)
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

char* make_windows_path_with_suffix(const char* base_path, size_t base_path_length, const char* suffix, size_t suffix_size)
{
    return make_windows_path_with_suffix_impl(base_path, base_path_length, suffix, suffix_size);
}

char* make_windows_hosts_file_path_from_system_dir(const char* system_dir, size_t system_dir_length)
{
    if (system_dir == NULL || system_dir_length == 0) {
        fprintf(stderr, "Error constructing hosts file path: empty Windows system directory\n");
        return NULL;
    }

    return make_windows_path_with_suffix(system_dir, system_dir_length, WINDOWS_HOSTS_PATH_SUFFIX, sizeof(WINDOWS_HOSTS_PATH_SUFFIX));
}

char* get_windows_directory_from_api(windows_directory_api get_directory, const char* api_name)
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

char* resolve_windows_native_system_directory_with_resolver(const struct windows_native_system_directory_resolver* resolver)
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

        size_t windows_directory_length = strlen(windows_directory);
        if (windows_directory_length > 0 && windows_directory[windows_directory_length - 1] == '\\') {
            --windows_directory_length;
        }

        char* sysnative_directory = make_windows_path_with_suffix(windows_directory, windows_directory_length, WINDOWS_SYSNATIVE_SUFFIX, sizeof(WINDOWS_SYSNATIVE_SUFFIX));
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

char* get_windows_hosts_file_path(void)
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
