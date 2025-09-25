#ifndef DIGITAL_SIGNATURE
#define DIGITAL_SIGNATURE

#include <stdbool.h>
#include <stddef.h>

typedef struct {
    size_t length;
    char data[];
} String_View;


int ds_generate_Keys(size_t keysize, String_View **privateKey, String_View **publicKey);
int ds_signature(const String_View *secret, const char *message, String_View **sign);

/**
 * @return 0 false, 1 true, -1 error
 */
int ds_isValid(const String_View *publicKey,const char *message,const String_View *sign);
int ds_init(void);
int ds_deinit(void);

#endif // DIGITAL_SIGNATURE