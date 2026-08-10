#include "dev-env-update-hosts.h"

#include <string.h>

#if defined(_WIN32)
static char* get_hosts_file_path(void)
{
    return get_windows_hosts_file_path();
}
#else
static char* get_hosts_file_path(void)
{
    return my_strdup("/etc/hosts");
}
#endif

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

static int escalate_privilege(int argc, char** argv)
{
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
