#include <math.h>
#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>

#include "digital_signature.h"
#include "strings_utils.h"
//
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// helper to print error + OpenSSL error queue
static void print_openssl_error(const char *msg, const char *file, int line) {
  fprintf(stderr, "[ERROR] %s %s:%d\n", msg, file, line);
  ERR_print_errors_fp(stderr);
}

// --- init / deinit ---
int ds_init(void) {
  if (OPENSSL_init_ssl(0, NULL) == 0) {
    print_openssl_error("OPENSSL_init_ssl failed", __FILE__, __LINE__);
    return 1;
  }
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
  return 0;
}

int ds_deinit(void) {
  EVP_cleanup();
  ERR_free_strings();
  return 0;
}

// --- generate keys ---
// OpenSSL 3.x

EVP_PKEY *gen_rsa_key(unsigned bits) {
  EVP_PKEY *pkey = NULL;
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
  if (!ctx)
    return NULL;

  if (EVP_PKEY_keygen_init(ctx) <= 0)
    goto err;

  // Only specify the size
  OSSL_PARAM params[] = {OSSL_PARAM_construct_uint("bits", &bits),
                         OSSL_PARAM_END};
  if (EVP_PKEY_CTX_set_params(ctx, params) <= 0)
    goto err;

  if (EVP_PKEY_generate(ctx, &pkey) <= 0)
    goto err;

  EVP_PKEY_CTX_free(ctx);
  return pkey;

err:
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return NULL;
}

int ds_generate_Keys(size_t keysize, String_Builder *privateKey,
                     String_Builder *publicKey) {
  if (!privateKey || !publicKey) {
    print_openssl_error("arguments are NULL", __FILE__, __LINE__);
    return 1;
  }

  int rc = 1;
  EVP_PKEY *pkey = gen_rsa_key(keysize);
  BIO *bio_priv = NULL;
  BIO *bio_pub = NULL;
  char *priv_buf = NULL;
  char *pub_buf = NULL;
  size_t prev_priv_count = privateKey->count;
  size_t prev_pub_count = publicKey->count;

  bio_priv = BIO_new(BIO_s_mem());
  bio_pub = BIO_new(BIO_s_mem());

  if (!bio_priv || !bio_pub) {
    print_openssl_error("BIO_new failed", __FILE__, __LINE__);
    goto cleanup;
  }

  if (!PEM_write_bio_PrivateKey(bio_priv, pkey, NULL, NULL, 0, NULL, NULL)) {
    print_openssl_error("PEM_write_bio_PrivateKey failed", __FILE__, __LINE__);
    goto cleanup;
  }
  if (!PEM_write_bio_PUBKEY(bio_pub, pkey)) {
    print_openssl_error("PEM_write_bio_PUBKEY failed", __FILE__, __LINE__);
    goto cleanup;
  }

  long priv_len = BIO_get_mem_data(bio_priv, &priv_buf);
  long pub_len = BIO_get_mem_data(bio_pub, &pub_buf);

  if (priv_len <= 0 || pub_len <= 0) {
    print_openssl_error("BIO_get_mem_data failed", __FILE__, __LINE__);
    goto cleanup;
  }

  // append raw bytes and a terminating null so the builder can be used as a
  // C-string if needed
  sb_append_buf(privateKey, priv_buf, (size_t)priv_len);
  // sb_append_null(privateKey);

  sb_append_buf(publicKey, pub_buf, (size_t)pub_len);
  // sb_append_null(publicKey);

  rc = 0;

cleanup:
  if (rc != 0) {
    // rollback counts (we don't attempt to free/reduce capacity)
    privateKey->count = prev_priv_count;
    publicKey->count = prev_pub_count;
  }

  if (pkey)
    EVP_PKEY_free(pkey);
  if (bio_priv)
    BIO_free(bio_priv);
  if (bio_pub)
    BIO_free(bio_pub);

  return rc;
}

// --- signature ---
int ds_signature(String_View secret, String_View message,
                 String_Builder *sign) {
  if (!secret.data || !message.data || !sign) {
    print_openssl_error("arguments are NULL", __FILE__, __LINE__);
    return 1;
  }
  int rc = 1;

  BIO *bio = BIO_new_mem_buf((void *)secret.data, (int)secret.count);
  if (!bio) {
    print_openssl_error("BIO_new_mem_buf failed", __FILE__, __LINE__);
    return 1;
  }

  EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
  BIO_free(bio);
  if (!pkey) {
    print_openssl_error("PEM_read_bio_PrivateKey failed", __FILE__, __LINE__);
    return 1;
  }

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) {
    print_openssl_error("EVP_MD_CTX_new failed", __FILE__, __LINE__);
    EVP_PKEY_free(pkey);
    return 1;
  }

  if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
    print_openssl_error("EVP_DigestSignInit failed", __FILE__, __LINE__);
    goto cleanup;
  }

  if (EVP_DigestSignUpdate(ctx, message.data, message.count) <= 0) {
    print_openssl_error("EVP_DigestSignUpdate failed", __FILE__, __LINE__);
    goto cleanup;
  }

  size_t siglen = 0;
  if (EVP_DigestSignFinal(ctx, NULL, &siglen) <= 0) {
    print_openssl_error("EVP_DigestSignFinal (size) failed", __FILE__,
                        __LINE__);
    goto cleanup;
  }

  unsigned char *sig_buf = malloc(siglen);
  if (!sig_buf) {
    print_openssl_error("malloc failed for signature buffer", __FILE__,
                        __LINE__);
    goto cleanup;
  }

  if (EVP_DigestSignFinal(ctx, sig_buf, &siglen) <= 0) {
    print_openssl_error("EVP_DigestSignFinal (data) failed", __FILE__,
                        __LINE__);
    free(sig_buf);
    goto cleanup;
  }

  sb_append_buf(sign, sig_buf, siglen);
  // sb_append_null(sign);

  free(sig_buf);
  rc = 0;

cleanup:
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return rc;
}

// --- verify ---
int ds_isValid(String_View publicKey, String_View message, String_View sign) {
  if (!publicKey.data || !message.data || !sign.data) {
    print_openssl_error("arguments are NULL", __FILE__, __LINE__);
    return -1;
  }
  int rc = -1;

  BIO *bio = BIO_new_mem_buf((void *)publicKey.data, (int)publicKey.count);
  if (!bio) {
    print_openssl_error("BIO_new_mem_buf failed", __FILE__, __LINE__);
    return -1;
  }

  EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
  BIO_free(bio);
  if (!pkey) {
    print_openssl_error("PEM_read_bio_PUBKEY failed", __FILE__, __LINE__);
    return -1;
  }

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) {
    EVP_PKEY_free(pkey);
    print_openssl_error("EVP_MD_CTX_new failed", __FILE__, __LINE__);
    return -1;
  }

  if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
    print_openssl_error("EVP_DigestVerifyInit failed", __FILE__, __LINE__);
    goto cleanup;
  }
  if (EVP_DigestVerifyUpdate(ctx, message.data, message.count) <= 0) {
    print_openssl_error("EVP_DigestVerifyUpdate failed", __FILE__, __LINE__);
    goto cleanup;
  }

  int v =
      EVP_DigestVerifyFinal(ctx, (const unsigned char *)sign.data, sign.count);
  if (v == 1)
    rc = 1;
  else if (v == 0)
    rc = 0;
  else {
    print_openssl_error("EVP_DigestVerifyFinal error", __FILE__, __LINE__);
    rc = -1;
  }

cleanup:
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return rc;
}

int sha256_bytes(const unsigned char *in, size_t inlen,
                 unsigned char out[EVP_MAX_MD_SIZE]) {
  int ok = 1;
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx)
    return ok;

  // Prefer provider-based fetch (3.x). Fallback to EVP_sha256() for 1.1.1.
  EVP_MD *md = EVP_MD_fetch(NULL, "SHA256", NULL);
  const EVP_MD *md_fallback = md ? md : EVP_sha256();

  if (EVP_DigestInit_ex(ctx, md_fallback, NULL) <= 0)
    goto done;
  if (EVP_DigestUpdate(ctx, in, inlen) <= 0)
    goto done;
  if (EVP_DigestFinal_ex(ctx, out, NULL) <= 0)
    goto done;

  ok = 0;
done:
  EVP_MD_CTX_free(ctx);
  if (md)
    EVP_MD_free(md);
  return ok;
}
int ds_hash(void *object, size_t count, String_Builder *hash) {
  unsigned char hash_result[EVP_MAX_MD_SIZE] = {0};
  if (sha256_bytes(object, count, hash_result)) {
    print_openssl_error("sha256_bytes Error.", __FILE__, __LINE__);
    return 1;
  }
  sb_append_buf(hash, hash_result, EVP_MAX_MD_SIZE);
  return 0;
}

int ds_base64(const unsigned char *in, size_t in_size, String_Builder *out)
/* Returns number of Base64 chars written (excluding NUL) on success, 0 on
   failure. */
{

  // Base64 length = 4 * ceil(n/3). Need +1 for '\0'.
  size_t need = 4 * (size_t)ceil((double)in_size / 3) + 1;
  if (out->capacity < need) {
    da_reserve(out, need);
  }

  out->count = need - 1;
  int written = EVP_EncodeBlock((unsigned char *)out->items, in, in_size);

  if (written <= 0)
    return 1;

  out->items[need] = '\0';
  return 0;
}

/*
int decobase64(const void *b64_out, size_t b64_out_size,String_Builder* out)
 Returns number of Base64 chars written (excluding NUL) on success, 0 on
   failure.
{

  // Base64 length = 4 * ceil(n/3). Need +1 for '\0'.
  size_t need = 4 * ((dlen + 2) / 3) + 1;
  if (b64_out_size < need)
    return 1;

  int written = EVP_EncodeBlock((unsigned char *)b64_out, digest, (int)dlen);
  if (written <= 0)
    return 1;

  b64_out[written] = '\0';

  return 0;
}*/
