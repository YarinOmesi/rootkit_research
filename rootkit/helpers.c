#include "helpers.h"
#include <linux/string.h>


int ends_with(const char *str, const char *suffix) {
    size_t str_len = strlen(str);
    size_t suffix_len = strlen(suffix);

    return (str_len >= suffix_len) &&
           (strncmp(str + str_len - suffix_len, suffix, suffix_len) == 0);
}