#include <stdio.h>
#include <stdlib.h>
#include "digital_signature.h"

#include <string.h>

int save_to_file(String_View *view, const char *file_name) {
    FILE *file = fopen(file_name, "w");
    size_t value = fwrite(view->data, 1, view->length, file);
    return value;
}

String_View *from_file(const char *file_name) {
    FILE *file = fopen(file_name, "rb");
    if (!file) return NULL;

    fseek(file, 0, SEEK_END);
    size_t length = ftell(file);
    rewind(file);

    String_View *view = malloc(sizeof(String_View) + length + 1);
    if (!view) {
        fclose(file);
        return NULL;
    }
    view->length = length;
    fread(view->data, 1, length, file);
    view->data[length] = '\0';
    fclose(file);

    return view;
}

String_View *concatenate(String_View* firts, String_View *second) {
    size_t total_length = firts->length + second->length;
    String_View *result = malloc(sizeof(String_View) + total_length + 1);
    if (!result) return NULL;
    result->length = total_length;
    memcpy(result->data, firts->data, firts->length);
    memcpy(result->data + firts->length, second->data, second->length);
    result->data[total_length] = '\0';
    return result;
}

String_View *from_cstr(const char *cstr) {
    size_t len = strlen(cstr);
    String_View *view = malloc(sizeof(String_View) + len + 1);
    if (!view) return NULL;
    view->length = len;
    memcpy(view->data, cstr, len);
    view->data[len] = '\0';
    return view;
}

#define eprintf(...) fprintf(stderr, __VA_ARGS__)

#define control(bool_exp) \
    do {\
        if((bool_exp) == -1) {\
            eprintf("[FATAL ERROR] %s:%d "#bool_exp"\n", __FILE__, __LINE__);\
            exit(1);\
        }\
    }while(0)\
    
#include <assert.h>

#define shift(xs, xs_sz) (assert((xs_sz) > 0), (xs_sz)--, *(xs)++)

int main(int argc, char **argv) {
    const char *program_name = shift(argv, argc);
    const char *subcommand = shift(argv, argc);

    control(ds_init());

    if(strcmp(subcommand, "createUser") == 0) {
        const char *private_path = shift(argv, argc);
        const char *public_path = shift(argv, argc);

        String_View *priv = NULL;
        String_View *pub  = NULL;

        // Genera coppia di chiavi RSA 2048
        control(ds_generate_Keys(2048, &priv, &pub));

        save_to_file(priv, private_path);
        save_to_file(pub, public_path);

        free(priv);
        free(pub);

    } else if (strcmp(subcommand, "sign") == 0) {
        const char *file_to_sign = shift(argv, argc);
        const char *private_key = shift(argv, argc);

        String_View *sv_file_to_sign = from_file(file_to_sign);
        String_View *sv_private_key = from_file(private_key);
        
        String_View *sv_sign = NULL;
        control(ds_signature(sv_private_key, sv_file_to_sign->data, &sv_sign));
        const char *to_save = shift(argv, argc);
        save_to_file(sv_sign, to_save);

        free(sv_file_to_sign);
        free(sv_private_key);
        free(sv_sign);

    } else if (strcmp(subcommand, "createCoin") == 0) {
        const char *private_key = shift(argv, argc);
        const char *coin_id = shift(argv, argc);

        String_View *sv_private_key = from_file(private_key);

        String_View *base = from_cstr("CreateCoin ");
        String_View *sv_coin_id = from_cstr(coin_id);
        String_View *sv_coin = concatenate(base, sv_coin_id);
        free(base);
        free(sv_coin_id);

        String_View *sv_sign = NULL;

        control(ds_signature(sv_private_key, sv_coin->data, &sv_sign));


        const char *signature_file_path = shift(argv, argc);

        save_to_file(sv_sign, signature_file_path);
        save_to_file(sv_coin, coin_id);


        free(sv_private_key);
        free(sv_coin);

    } else if (strcmp(subcommand, "verify") == 0){
        const char *public_key_path = shift(argv, argc);
        const char *signature_path = shift(argv, argc);
        const char *message_path = shift(argv, argc);

        String_View *sv_public_key = from_file(public_key_path);
        String_View *sv_signature = from_file(signature_path);
        String_View *sv_message = from_file(message_path);

        int value = ds_isValid(sv_public_key, sv_message->data, sv_signature);
        printf("[INFO] is valid: %d\n", value);

        free(sv_public_key);
        free(sv_signature);
        free(sv_message);

    } else {
        eprintf("[FATAL ERROR] subcomand not recognised: %s\n", subcommand);
        return(1);
    }

    ds_deinit();

    return(0);
}

int main2(void) {
    control(ds_init());

    String_View *priv = NULL;
    String_View *pub  = NULL;

    // Genera coppia di chiavi RSA 2048
    control(ds_generate_Keys(2048, &priv, &pub));

    const char *message = "hello world";
    String_View *sig = NULL;

    // Firma il messaggio
    control(ds_signature(priv, message, &sig));

    // Verifica
    int ok = ds_isValid(pub, message, sig);
    printf("Verification result: %d\n", ok);  // 1 = OK, 0 = FAIL, -1 = ERROR

    // Libera memoria
    free(priv);
    free(pub);
    free(sig);

    ds_deinit();
    return 0;
}