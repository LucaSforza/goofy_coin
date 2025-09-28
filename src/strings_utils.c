#include "strings_utils.h"

#include <sys/errno.h>

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#define return_defer(value) do { result = (value); goto defer; } while(0)

int sb_read_entire_file(const char *path, String_Builder *sb) {
    int result = 0;

    FILE *f = fopen(path, "rb");
    size_t new_count = 0;
    long long m = 0;
    if (f == NULL)                 return_defer(1);
    if (fseek(f, 0, SEEK_END) < 0) return_defer(1);
#ifndef _WIN32
    m = ftell(f);
#else
    m = _ftelli64(f);
#endif
    if (m < 0)                     return_defer(1);
    if (fseek(f, 0, SEEK_SET) < 0) return_defer(1);

    new_count = sb->count + m;
    if (new_count > sb->capacity) {
        sb->items = SU_REALLOC(sb->items, new_count);
        SU_ASSERT(sb->items != NULL && "Buy more RAM lool!!");
        sb->capacity = new_count;
    }

    fread(sb->items + sb->count, m, 1, f);
    if (ferror(f)) {
        // TODO: Afaik, ferror does not set errno. So the error reporting in defer is not correct in this case.
        return_defer(1);
    }
    sb->count = new_count;

defer:
    if (result) fprintf(stderr, "Could not read file %s: %s", path, strerror(errno));
    if (f) fclose(f);
    return result;
}

int sb_appendf(String_Builder *sb, const char *fmt, ...) {
    va_list args;

    va_start(args, fmt);
    int n = vsnprintf(NULL, 0, fmt, args);
    va_end(args);

    // NOTE: the new_capacity needs to be +1 because of the null terminator.
    // However, further below we increase sb->count by n, not n + 1.
    // This is because we don't want the sb to include the null terminator. The user can always sb_append_null() if they want it
    da_reserve(sb, sb->count + n + 1);
    char *dest = sb->items + sb->count;
    va_start(args, fmt);
    vsnprintf(dest, n+1, fmt, args);
    va_end(args);

    sb->count += n;

    return n;
}

String_View sv_chop_by_delim(String_View *sv, char delim) {
    size_t i = 0;
    while (i < sv->count && sv->data[i] != delim) {
        i += 1;
    }

    String_View result = sv_from_parts(sv->data, i);

    if (i < sv->count) {
        sv->count -= i + 1;
        sv->data  += i + 1;
    } else {
        sv->count -= i;
        sv->data  += i;
    }

    return result;
}

String_View sv_chop_by_spaces(String_View *sv) {
    size_t i = 0;
    while (i < sv->count && !isspace(sv->data[i])) {
        i += 1;
    }

    String_View result = sv_from_parts(sv->data, i);

    if (i < sv->count) {
        sv->count -= i + 1;
        sv->data  += i + 1;
    } else {
        sv->count -= i;
        sv->data  += i;
    }
    i = 0;
    while (i < sv->count && isspace(sv->data[i])) {
        i += 1;
    }
    sv->count -= i;
    sv->data += i;

    return result;
}

String_View sv_chop_left(String_View *sv, size_t n) {
    if (n > sv->count) {
        n = sv->count;
    }

    String_View result = sv_from_parts(sv->data, n);

    sv->data  += n;
    sv->count -= n;

    return result;
}

String_View sv_trim(String_View sv) {
    return sv_trim_left(sv_trim_right(sv));
}

String_View sv_trim_left(String_View sv) {
    size_t i = 0;
    while (i < sv.count && isspace(sv.data[i])) {
        i += 1;
    }

    return sv_from_parts(sv.data + i, sv.count - i);
}

String_View sv_trim_right(String_View sv) {
    size_t i = 0;
    while (i < sv.count && isspace(sv.data[sv.count - 1 - i])) {
        i += 1;
    }

    return sv_from_parts(sv.data, sv.count - i);
}

int sv_eq(String_View a, String_View b) {
    if (a.count != b.count) {
        return 0;
    } else {
        return memcmp(a.data, b.data, a.count) == 0;
    }
}

int sv_end_with(String_View sv, const char *cstr) {
    size_t cstr_count = strlen(cstr);
    if (sv.count >= cstr_count) {
        size_t ending_start = sv.count - cstr_count;
        String_View sv_ending = sv_from_parts(sv.data + ending_start, cstr_count);
        return sv_eq(sv_ending, sv_from_cstr(cstr));
    }
    return 0;
}

int sv_starts_with(String_View sv, String_View expected_prefix) {
    if (expected_prefix.count <= sv.count) {
        String_View actual_prefix = sv_from_parts(sv.data, expected_prefix.count);
        return sv_eq(expected_prefix, actual_prefix);
    }

    return 0;
}

String_View sv_from_cstr(const char *cstr) {
    return (String_View){ .count = strlen(cstr), .data = cstr };
}

String_View sv_from_parts(const char *data, size_t count) {
    return (String_View){ .count = count, .data = data };
}

int sv_save_to_file(String_View sv, const char *file_name) {
    FILE *file = fopen(file_name, "wb"); // binario
    if (!file) {
        perror("fopen");
        return -1;
    }

    size_t written = fwrite(sv.data, 1, sv.count, file);
    if (written != sv.count) {
        perror("fwrite");
        fclose(file);
        return -1;
    }

    if (fclose(file) != 0) {
        perror("fclose");
        return -1;
    }

    return 0;
}

void sb_append_buf(String_Builder *sb, const void *buf, size_t size) {
    da_append_many(sb, buf, size);
}

void sb_append_null(String_Builder *sb) {
    sb_append_buf(sb, "", 1);
    sb->count--;
}

void sb_append_cstr(String_Builder *sb, const char *cstr) {
    const char *s = (cstr);
    size_t n = strlen(s);
    sb_append_buf(sb, s, n);
}

String_View sb_to_sv(String_Builder sb) {
    return sv_from_parts(sb.items, sb.count);
}

String_Builder sv_to_sb(String_View sv) {
    String_Builder result = {0};
    da_reserve(&result, sv.count);
    memcpy(result.items, sv.data, sv.count);
    result.count = sv.count;
    return result;
}

String_Builder sv_to_sb_null(String_View sv) {
    String_Builder result = {0};
    da_reserve(&result, sv.count + 1);
    memcpy(result.items, sv.data, sv.count);
    result.count = sv.count;
    result.items[result.count] = '\0';
    return result;
}