#ifndef DEV_ENV_UPDATE_HOSTS_H
#define DEV_ENV_UPDATE_HOSTS_H

#if defined(__linux__) || defined(__APPLE__)
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#endif

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#include <sys/acl.h>
#include <sys/types.h>
#endif

#if defined(_WIN32)
#include <io.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct hosts_update_progress {
    bool separator_write_attempted;
    bool separator_written;
    size_t entries_attempted;
    size_t entries_accepted;
    bool durability_failed;
};
typedef struct hosts_update_progress hosts_update_progress;

typedef struct {
    bool mapped_to_loopback;
    bool mapped_to_non_loopback;
    const char* conflict_address;
} hosts_domain_state;

char* my_strdup(const char* value);
bool domain_equals_ignore_case(const char* a, const char* b);
bool domain_was_seen(const char** domains, size_t ndomains, const char* domain);
bool is_valid_domain(const char* value);

int update_hosts(const char* filename, const char** domains, size_t ndomains);

#if defined(__linux__) || defined(__APPLE__)
bool has_dbus(void);
bool is_wsl(void);
bool has_trusted_parent_directories(const char* path);
bool is_trusted_executable(const char* path);
char* find_trusted_helper(const char* const* candidates, size_t ncandidates);
char* get_self_path(void);
#endif

#if defined(_WIN32) || defined(DEV_ENV_UPDATE_HOSTS_TESTING)
extern const char WINDOWS_HOSTS_PATH_SUFFIX[];
extern const char WINDOWS_SYSNATIVE_SUFFIX[];

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

char* make_windows_path_with_suffix(const char* base_path, size_t base_path_length, const char* suffix, size_t suffix_size);
char* make_windows_hosts_file_path_from_system_dir(const char* system_dir, size_t system_dir_length);
char* get_windows_directory_from_api(windows_directory_api get_directory, const char* api_name);
char* resolve_windows_native_system_directory_with_resolver(const struct windows_native_system_directory_resolver* resolver);
char* get_windows_hosts_file_path(void);
#endif

#endif
