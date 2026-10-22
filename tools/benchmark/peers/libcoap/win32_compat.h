#ifndef COAPTIC_BENCH_WIN32_COMPAT_H
#define COAPTIC_BENCH_WIN32_COMPAT_H

#ifdef _MSC_VER
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Match POSIX's bounded scan and the caller's ordinary CRT free(). */
static __inline char *coaptic_bench_strndup(const char *source, size_t limit) {
    size_t length = 0;
    char *copy;
    if (source == NULL) return NULL;
    while (length < limit && source[length] != '\0') ++length;
    if (length == SIZE_MAX) return NULL;
    copy = (char *)malloc(length + 1);
    if (copy == NULL) return NULL;
    if (length != 0) memcpy(copy, source, length);
    copy[length] = '\0';
    return copy;
}

#ifndef strndup
#define strndup coaptic_bench_strndup
#endif
#endif

#endif
