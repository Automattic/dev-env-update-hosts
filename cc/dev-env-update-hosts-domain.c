#include "dev-env-update-hosts.h"

#include <string.h>

char* my_strdup(const char* value)
{
    if (value == NULL) {
        return NULL;
    }

    size_t length = strlen(value) + 1;
    char* copy = malloc(length);
    if (copy) {
        memcpy(copy, value, length);
    }

    return copy;
}

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

bool is_valid_domain(const char* value)
{
    if (value == NULL || strnlen(value, MAX_DOMAIN_LEN + 1) > MAX_DOMAIN_LEN) {
        return false;
    }

    const char* label_start = value;

    for (const char* cursor = value; ; ++cursor) {
        if (*cursor == '.' || *cursor == '\0') {
            if (!is_valid_label(label_start, (size_t)(cursor - label_start))) {
                return false;
            }

            if (*cursor == '\0') {
                return true;
            }

            label_start = cursor + 1;
        }
    }
}

bool domain_equals_ignore_case(const char* a, const char* b)
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

bool domain_was_seen(const char** domains, size_t ndomains, const char* domain)
{
    for (size_t i = 0; i < ndomains; ++i) {
        if (domain_equals_ignore_case(domains[i], domain)) {
            return true;
        }
    }

    return false;
}
