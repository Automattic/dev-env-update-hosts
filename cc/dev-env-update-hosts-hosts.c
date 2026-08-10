#include "dev-env-update-hosts.h"

#include <errno.h>
#include <string.h>

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

static bool initialize_windows_sockets(void)
{
    WSADATA data;
    int result = WSAStartup(MAKEWORD(2, 2), &data);
    if (result != 0) {
        fprintf(stderr, "Error initializing Windows sockets: Windows error %d\n", result);
        return false;
    }

    return true;
}
#endif

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
    if (fseek(hosts, 0, SEEK_END) != 0) {
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

    if (fseek(hosts, -1, SEEK_END) != 0) {
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

    if (fseek(hosts, 0, SEEK_END) != 0) {
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

static bool is_hosts_space(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f';
}

static char* skip_hosts_spaces(char* cursor)
{
    while (is_hosts_space(*cursor)) {
        ++cursor;
    }

    return cursor;
}

static bool is_accepted_loopback_address(const char* address)
{
    return strcmp(address, "127.0.0.1") == 0 || strcmp(address, "::1") == 0;
}

static bool is_valid_hosts_address(const char* address)
{
#if defined(_WIN32)
    struct in_addr ipv4_address;
    struct in6_addr ipv6_address;
    return InetPtonA(AF_INET, address, &ipv4_address) == 1 ||
           InetPtonA(AF_INET6, address, &ipv6_address) == 1;
#elif defined(__linux__) || defined(__APPLE__)
    struct in_addr ipv4_address;
    struct in6_addr ipv6_address;
    return inet_pton(AF_INET, address, &ipv4_address) == 1 ||
           inet_pton(AF_INET6, address, &ipv6_address) == 1;
#else
    (void)address;
    return false;
#endif
}

static bool load_hosts_contents(FILE* hosts, char** contents)
{
    *contents = NULL;

    if (fseek(hosts, 0, SEEK_END) != 0) {
        perror("Error seeking to end of hosts file");
        return false;
    }

    long hosts_size = ftell(hosts);
    if (hosts_size == -1) {
        perror("Error determining hosts file size");
        return false;
    }

    if (fseek(hosts, 0, SEEK_SET) != 0) {
        perror("Error seeking to beginning of hosts file");
        return false;
    }

    char* buffer = malloc((size_t)hosts_size + 1);
    if (!buffer) {
        perror("Error allocating memory");
        return false;
    }

    size_t bytes_read = fread(buffer, 1, (size_t)hosts_size, hosts);
    if (bytes_read != (size_t)hosts_size) {
        if (ferror(hosts)) {
            perror("Error reading hosts file");
        }
        else {
            fputs("Error reading hosts file: unexpected end of file\n", stderr);
        }
        free(buffer);
        return false;
    }

    buffer[hosts_size] = '\0';
    *contents = buffer;
    return true;
}

static void record_hosts_mapping(
    const char* address,
    const char* hostname,
    bool is_loopback,
    const char** domains,
    size_t ndomains,
    hosts_domain_state* states
)
{
    for (size_t i = 0; i < ndomains; ++i) {
        if (!domain_equals_ignore_case(hostname, domains[i])) {
            continue;
        }

        if (is_loopback) {
            states[i].mapped_to_loopback = true;
        }
        else {
            states[i].mapped_to_non_loopback = true;
            if (!states[i].conflict_address) {
                states[i].conflict_address = address;
            }
        }
    }
}

static void parse_hosts_line(char* line, const char** domains, size_t ndomains, hosts_domain_state* states)
{
    char* cursor = skip_hosts_spaces(line);
    if (*cursor == '\0' || *cursor == '#') {
        return;
    }

    char* address = cursor;
    while (*cursor != '\0' && *cursor != '#' && !is_hosts_space(*cursor)) {
        ++cursor;
    }

    if (*cursor == '\0' || *cursor == '#') {
        *cursor = '\0';
        return;
    }

    *cursor = '\0';
    ++cursor;

    if (!is_valid_hosts_address(address)) {
        return;
    }

    bool is_loopback = is_accepted_loopback_address(address);
    for (;;) {
        cursor = skip_hosts_spaces(cursor);
        if (*cursor == '\0' || *cursor == '#') {
            return;
        }

        char* hostname = cursor;
        while (*cursor != '\0' && *cursor != '#' && !is_hosts_space(*cursor)) {
            ++cursor;
        }

        char delimiter = *cursor;
        *cursor = '\0';
        record_hosts_mapping(address, hostname, is_loopback, domains, ndomains, states);

        if (delimiter == '\0' || delimiter == '#') {
            return;
        }

        ++cursor;
    }
}

static bool requested_domain_was_seen_before(const char** domains, size_t domain_index)
{
    for (size_t i = 0; i < domain_index; ++i) {
        if (domain_equals_ignore_case(domains[i], domains[domain_index])) {
            return true;
        }
    }

    return false;
}

static void report_hosts_conflicts(const char** domains, size_t ndomains, const hosts_domain_state* states)
{
    for (size_t i = 0; i < ndomains; ++i) {
        if (!states[i].mapped_to_non_loopback || requested_domain_was_seen_before(domains, i)) {
            continue;
        }

        fprintf(
            stderr,
            "Error: Hosts file already maps %s to non-loopback address %s; leaving hosts file unchanged\n",
            domains[i],
            states[i].conflict_address ? states[i].conflict_address : "unknown"
        );
    }
}

static bool inspect_existing_hosts(
    FILE* hosts,
    const char** domains,
    size_t ndomains,
    hosts_domain_state* states,
    bool* has_conflicts
)
{
    *has_conflicts = false;

    char* contents = NULL;
    if (!load_hosts_contents(hosts, &contents)) {
        return false;
    }

    char* line = contents;
    while (*line != '\0') {
        char* line_end = strchr(line, '\n');
        if (line_end) {
            *line_end = '\0';
        }

        parse_hosts_line(line, domains, ndomains, states);

        if (!line_end) {
            break;
        }

        line = line_end + 1;
    }

    for (size_t i = 0; i < ndomains; ++i) {
        if (states[i].mapped_to_non_loopback) {
            *has_conflicts = true;
            break;
        }
    }

    if (*has_conflicts) {
        report_hosts_conflicts(domains, ndomains, states);
    }

    free(contents);
    return true;
}

static bool should_append_domain(const char** domains, size_t domain_index, const hosts_domain_state* states)
{
    return !requested_domain_was_seen_before(domains, domain_index) &&
           !states[domain_index].mapped_to_loopback &&
           !states[domain_index].mapped_to_non_loopback;
}

static size_t count_domains_to_append(const char** domains, size_t ndomains, const hosts_domain_state* states)
{
    size_t count = 0;
    for (size_t i = 0; i < ndomains; ++i) {
        if (should_append_domain(domains, i, states)) {
            ++count;
        }
    }

    return count;
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

int update_hosts(const char* filename, const char** domains, size_t ndomains)
{
#if defined(_WIN32)
    if (!initialize_windows_sockets()) {
        return EXIT_FAILURE;
    }
#endif

    FILE* hosts = fopen(filename, "r+b");
    if (!hosts) {
        perror("Error opening hosts file");
#if defined(_WIN32)
        WSACleanup();
#endif
        return EXIT_FAILURE;
    }

    if (!lock_hosts_file(hosts)) {
        if (fclose(hosts) != 0) {
            perror("Error closing hosts file");
        }
#if defined(_WIN32)
        WSACleanup();
#endif
        return EXIT_FAILURE;
    }

    int status = EXIT_SUCCESS;
    hosts_update_progress progress;
    memset(&progress, 0, sizeof(progress));

    hosts_domain_state* states = calloc(ndomains, sizeof(*states));
    if (!states) {
        perror("Error allocating memory");
        status = EXIT_FAILURE;
    }

    bool has_conflicts = false;
    if (status == EXIT_SUCCESS && !inspect_existing_hosts(hosts, domains, ndomains, states, &has_conflicts)) {
        status = EXIT_FAILURE;
    }

    size_t domains_to_append = 0;
    if (status == EXIT_SUCCESS) {
        if (has_conflicts) {
            status = EXIT_FAILURE;
        }
        else {
            domains_to_append = count_domains_to_append(domains, ndomains, states);
        }
    }

    if (status == EXIT_SUCCESS && domains_to_append > 0 && !append_hosts_separator_if_needed(hosts, &progress)) {
        status = EXIT_FAILURE;
    }

    for (size_t i = 0; status == EXIT_SUCCESS && i < ndomains; ++i) {
        if (!should_append_domain(domains, i, states)) {
            continue;
        }

        ++progress.entries_attempted;
        if (fprintf(hosts, "127.0.0.1\t%s\n", domains[i]) < 0) {
            perror("Error writing hosts entry");
            status = EXIT_FAILURE;
            break;
        }

        ++progress.entries_accepted;
    }

    if (status == EXIT_SUCCESS && domains_to_append > 0 && fflush(hosts) != 0) {
        perror("Error flushing hosts file");
        progress.durability_failed = true;
        status = EXIT_FAILURE;
    }

    if (status == EXIT_SUCCESS && domains_to_append > 0 && !sync_hosts_file(hosts)) {
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

    free(states);
#if defined(_WIN32)
    WSACleanup();
#endif
    return status;
}
