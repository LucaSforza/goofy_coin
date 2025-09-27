// Adapted from: https://github.com/tsoding/nob.h
#ifndef STRINGS_UTILS_H_
#define STRINGS_UTILS_H_

#ifndef SUDEF
#define SUDEF inline
#endif // SUDEF

#ifndef SU_REALLOC
#include <stdlib.h>
#define SU_REALLOC realloc
#endif // SU_REALLOC

#ifndef SU_ASSERT
#include <assert.h>
#define SU_ASSERT assert
#endif // SU_REALLOC

#ifndef SU_FREE
#include <stdlib.h>
#define SU_FREE free
#endif // SU_FREE

#if defined(__GNUC__) || defined(__clang__)
//   https://gcc.gnu.org/onlinedocs/gcc-4.7.2/gcc/Function-Attributes.html
#    ifdef __MINGW_PRINTF_FORMAT
#        define SU_PRINTF_FORMAT(STRING_INDEX, FIRST_TO_CHECK) __attribute__ ((format (__MINGW_PRINTF_FORMAT, STRING_INDEX, FIRST_TO_CHECK)))
#    else
#        define SU_PRINTF_FORMAT(STRING_INDEX, FIRST_TO_CHECK) __attribute__ ((format (printf, STRING_INDEX, FIRST_TO_CHECK)))
#    endif // __MINGW_PRINTF_FORMAT
#else
//   TODO: implement SU_PRINTF_FORMAT for MSVC
#    define SU_PRINTF_FORMAT(STRING_INDEX, FIRST_TO_CHECK)
#endif

typedef struct {
    char *items;
    size_t count;
    size_t capacity;
} String_Builder;

#ifndef DA_INIT_CAP
#define DA_INIT_CAP 32
#endif // DA_INIT_CAP

#define da_reserve(da, expected_capacity)                                              \
    do {                                                                                   \
        if ((expected_capacity) > (da)->capacity) {                                        \
            if ((da)->capacity == 0) {                                                     \
                (da)->capacity = DA_INIT_CAP;                                          \
            }                                                                              \
            while ((expected_capacity) > (da)->capacity) {                                 \
                (da)->capacity *= 2;                                                       \
            }                                                                              \
            (da)->items = SU_REALLOC((da)->items, (da)->capacity * sizeof(*(da)->items)); \
            SU_ASSERT((da)->items != NULL && "Buy more RAM lol");                         \
        }                                                                                  \
    } while (0)

// Append several items to a dynamic array
#define da_append_many(da, new_items, new_items_count)                                      \
    do {                                                                                        \
        da_reserve((da), (da)->count + (new_items_count));                                  \
        memcpy((da)->items + (da)->count, (new_items), (new_items_count)*sizeof(*(da)->items)); \
        (da)->count += (new_items_count);                                                       \
    } while (0)

SUDEF int sb_read_entire_file(const char *path, String_Builder *sb);
SUDEF int sb_appendf(String_Builder *sb, const char *fmt, ...) SU_PRINTF_FORMAT(2, 3);
/**
 * @param sb string builder where append null at the end
 * @note This function will not change the length of the String Builder
 */
SUDEF void sb_append_null(String_Builder *sb);
// Append a NULL-terminated string to a string builder
SUDEF void sb_append_cstr(String_Builder *sb, const char *cstr);
// Append a sized buffer to a string builder
SUDEF void sb_append_buf(String_Builder *sb, void *buf, size_t size);

typedef struct {
    size_t count;
    const char *data;
} String_View;

SUDEF String_View sv_chop_by_delim(String_View *sv, char delim);
SUDEF String_View sv_chop_left(String_View *sv, size_t n);
SUDEF String_View sv_trim(String_View sv);
SUDEF String_View sv_trim_left(String_View sv);
SUDEF String_View sv_trim_right(String_View sv);
SUDEF int sv_eq(String_View a, String_View b);
SUDEF int sv_end_with(String_View sv, const char *cstr);
SUDEF int sv_starts_with(String_View sv, String_View expected_prefix);
SUDEF String_View sv_from_cstr(const char *cstr);
SUDEF String_View sv_from_parts(const char *data, size_t count);
SUDEF int sv_save_to_file(String_View view, const char *file_name);
// sb_to_sv() enables you to just view String_Builder as String_View
SUDEF String_View sb_to_sv(String_Builder sb);
#define sb_free(sb) SU_FREE(sb.items)

#endif // STRINGS_UTILS_H_