#ifndef DIGITAL_SIGNATURE_H_
#define DIGITAL_SIGNATURE_H_

#include <stdbool.h>
#include <stddef.h>

#ifndef DSDEF
#define DSDEF
#endif // DSDEF

#include "strings_utils.h"

/**
 * @param keysize size of the keys, eg: 2048
 * @param privateKey one result of the operation, a private key (must be secret)
 * @param publicKey one result of the operation, the public key.
 *
 * @return 0 if no error occured, 1 otherwise
 */
DSDEF int ds_generate_Keys(size_t keysize, String_Builder *privateKey,
                           String_Builder *publicKey);

/**
 * @param secret the private key
 * @param message the message to sign
 * @param sign result of the operation, the String of a signature
 *
 * @return 0 if no error occured, 1 otherwise
 */
DSDEF int ds_signature(String_View secret, String_View message,
                       String_Builder *sign);

/**
 *
 * @param publicKey the public key used for verify the signature and the message
 * @param message the message signed
 * @param sign signature
 * @return 0 false, 1 true, -1 error
 */
DSDEF int ds_isValid(String_View publicKey, String_View message,
                     String_View sign);

/**
 * Used for init the library
 *
 * @return 0 if no error occured, 1 otherwise
 */
DSDEF int ds_init(void);

/**
 * Used for deallocate garbage of the library
 *
 * @note all strings view returned by functions of this library must be
 * deallocated by hand
 *
 * @return 0 if no error occured, 1 otherwise
 */
DSDEF int ds_deinit(void);

DSDEF int ds_hash(void *object, size_t count, String_Builder *hash);

DSDEF int ds_base64(const unsigned char *in, size_t in_size,
                    String_Builder *out);
#endif // DIGITAL_SIGNATURE_H_
