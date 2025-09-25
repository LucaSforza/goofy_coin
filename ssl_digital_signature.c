#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "digital_signature.h"
#include <stdio.h>

// helper to print error + OpenSSL error queue
static void print_openssl_error(const char *msg, const char *file, int line) {
    fprintf(stderr, "[ERROR] %s %s:%d\n", msg, file, line);
    ERR_print_errors_fp(stderr);
}

// --- init / deinit ---
int ds_init(void) {
    if (OPENSSL_init_ssl(0, NULL) == 0) {
        print_openssl_error("OPENSSL_init_ssl failed", __FILE__, __LINE__);
        return -1;
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

// --- helper: alloc String_View ---
static String_View *sv_alloc(size_t len) {
    String_View *sv = malloc(sizeof(String_View) + len);
    if (!sv) {
        print_openssl_error("malloc failed in sv_alloc", __FILE__, __LINE__);
        return NULL;
    }
    sv->length = len;
    return sv;
}

// --- generate keys ---
int ds_generate_Keys(size_t keysize, String_View **privateKey, String_View **publicKey) {
    if (!privateKey || !publicKey) {
        print_openssl_error("arguments are NULL", __FILE__, __LINE__);
        return -1;
    } 
    int rc = -1;

    EVP_PKEY *pkey = NULL;
    RSA *rsa = NULL;
    BIGNUM *bn = NULL;
    BIO *bio_priv = NULL, *bio_pub = NULL;
    char *priv_buf = NULL, *pub_buf = NULL;

    pkey = EVP_PKEY_new();
    rsa = RSA_new();
    bn = BN_new();
    if (!pkey || !rsa || !bn) {
        print_openssl_error("pkey rsa bn are NULL", __FILE__, __LINE__);
        goto cleanup;
    }

    if (!BN_set_word(bn, RSA_F4)) {
        print_openssl_error("BN_set_word failed", __FILE__, __LINE__);
        goto cleanup;
    } 
    if (!RSA_generate_key_ex(rsa, (int)keysize, bn, NULL)) {
        print_openssl_error("RSA_generate_key_ex failed", __FILE__, __LINE__);
        goto cleanup;
    }
    if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
        print_openssl_error("EVP_PKEY_assign_RSA failed", __FILE__, __LINE__);
        goto cleanup;
    }
    rsa = NULL; // ora posseduto da pkey

    bio_priv = BIO_new(BIO_s_mem());
    bio_pub  = BIO_new(BIO_s_mem());
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
    long pub_len  = BIO_get_mem_data(bio_pub, &pub_buf);
    if (priv_len <= 0 || pub_len <= 0) {
        print_openssl_error("BIO_get_mem_data failed", __FILE__, __LINE__);
        goto cleanup;
    }

    *privateKey = sv_alloc((size_t)priv_len);
    *publicKey  = sv_alloc((size_t)pub_len);
    if (!*privateKey || !*publicKey) {
        print_openssl_error("sv_alloc failed", __FILE__, __LINE__);
        goto cleanup;
    }

    memcpy((*privateKey)->data, priv_buf, priv_len);
    memcpy((*publicKey)->data, pub_buf, pub_len);

    rc = 0;

cleanup:
    if (bn) BN_free(bn);
    if (rsa) RSA_free(rsa);
    if (pkey) EVP_PKEY_free(pkey);
    if (bio_priv) BIO_free(bio_priv);
    if (bio_pub) BIO_free(bio_pub);
    if (rc != 0) {
        free(*privateKey); free(*publicKey);
    }
    return rc;
}

// --- signature ---
int ds_signature(const String_View *secret, const char *message, String_View **sign) {
    if (!secret || !message || !sign) {
        print_openssl_error("arguments are NULL", __FILE__, __LINE__);
        return -1;
    }
    int rc = -1;
    BIO *bio = BIO_new_mem_buf(secret->data, (int)secret->length);
    if (!bio) {
        print_openssl_error("BIO_new_mem_buf failed", __FILE__, __LINE__);
        return -1;
    }

    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!pkey) {
        print_openssl_error("PEM_read_bio_PrivateKey failed", __FILE__, __LINE__);
        return -1;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        print_openssl_error("EVP_MD_CTX_new failed", __FILE__, __LINE__);
        EVP_PKEY_free(pkey);
        return -1;
    }

    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        print_openssl_error("EVP_DigestSignInit failed", __FILE__, __LINE__);
        goto cleanup;
    }

    if (EVP_DigestSignUpdate(ctx, message, strlen(message)) <= 0) {
        print_openssl_error("EVP_DigestSignUpdate failed", __FILE__, __LINE__);
        goto cleanup;
    }

    size_t siglen = 0;
    if (EVP_DigestSignFinal(ctx, NULL, &siglen) <= 0) {
        print_openssl_error("EVP_DigestSignFinal (size) failed", __FILE__, __LINE__);
        goto cleanup;
    }

    *sign = sv_alloc(siglen);
    if (!*sign) {
        print_openssl_error("sv_alloc failed", __FILE__, __LINE__);
        goto cleanup;
    }

    if (EVP_DigestSignFinal(ctx, (unsigned char *)(*sign)->data, &siglen) <= 0) {
        print_openssl_error("EVP_DigestSignFinal (data) failed", __FILE__, __LINE__);
        free(*sign); *sign = NULL; goto cleanup;
    }

    (*sign)->length = siglen;
    rc = 0;

cleanup:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return rc;
}

// --- verify ---
int ds_isValid(const String_View *publicKey, const char *message, const String_View *sign) {
    if (!publicKey || !message || !sign) {
        print_openssl_error("arguments are NULL", __FILE__, __LINE__);
        return -1;
    }
    int rc = -1;

    BIO *bio = BIO_new_mem_buf(publicKey->data, (int)publicKey->length);
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
    if (!ctx) { EVP_PKEY_free(pkey); print_openssl_error("EVP_MD_CTX_new failed", __FILE__, __LINE__); return -1; }

    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        print_openssl_error("EVP_DigestVerifyInit failed", __FILE__, __LINE__);
        goto cleanup;
    }
    if (EVP_DigestVerifyUpdate(ctx, message, strlen(message)) <= 0) {
        print_openssl_error("EVP_DigestVerifyUpdate failed", __FILE__, __LINE__);
        goto cleanup;
    }

    int v = EVP_DigestVerifyFinal(ctx, (const unsigned char *)sign->data, sign->length);
    if (v == 1) rc = 1;
    else if (v == 0) rc = 0;
    else {
        print_openssl_error("EVP_DigestVerifyFinal error", __FILE__, __LINE__);
        rc = -1;
    }

cleanup:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return rc;
}