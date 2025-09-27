#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "digital_signature.h"

#define eprintf(...) fprintf(stderr, __VA_ARGS__)

#define control(bool_exp) \
    do {\
        if((bool_exp) == -1) {\
            eprintf("[FATAL ERROR] %s:%d "#bool_exp"\n", __FILE__, __LINE__);\
            exit(1);\
        }\
    }while(0)\
    

#define shift(xs, xs_sz) (assert((xs_sz) > 0), (xs_sz)--, *(xs)++)

int main(int argc, char **argv) {
    const char *program_name = shift(argv, argc);
    (void)program_name;
    const char *subcommand = shift(argv, argc);

    control(ds_init());

    if(strcmp(subcommand, "createUser") == 0) {
        const char *private_path = shift(argv, argc);
        const char *public_path = shift(argv, argc);

        String_Builder priv = {0};
        String_Builder pub  = {0};

        // Genera coppia di chiavi RSA 2048
        control(ds_generate_Keys(2048, &priv, &pub));

        sv_save_to_file(sb_to_sv(priv), private_path);
        sv_save_to_file(sb_to_sv(pub), public_path);

        sb_free(priv);
        sb_free(pub);

    } else if (strcmp(subcommand, "sign") == 0) {
        const char *file_to_sign = shift(argv, argc);
        const char *private_key = shift(argv, argc);

        String_Builder sb_file_to_sign = {0};
        sb_read_entire_file(file_to_sign, &sb_file_to_sign);
    
        String_Builder sb_private_key = {0};
        sb_read_entire_file(private_key, &sb_private_key);
        
        String_Builder sb_sign = {0};
        control(ds_signature(sb_to_sv(sb_private_key), sb_to_sv(sb_file_to_sign), &sb_sign));
        const char *to_save = shift(argv, argc);
        sv_save_to_file(sb_to_sv(sb_sign), to_save);

        sb_free(sb_file_to_sign);
        sb_free(sb_private_key);
        sb_free(sb_sign);

    } else if (strcmp(subcommand, "createCoin") == 0) {
        const char *private_key = shift(argv, argc);
        const char *coin_id = shift(argv, argc);

        String_Builder sb_private_key = {0};
        sb_read_entire_file(private_key, &sb_private_key);

        String_Builder sb_coin = {0};
        sb_append_cstr(&sb_coin, "CreateCoin ");
        sb_append_cstr(&sb_coin, coin_id);

        String_Builder sb_sign = {0};

        control(ds_signature(sb_to_sv(sb_private_key), sb_to_sv(sb_coin), &sb_sign));

        const char *signature_file_path = shift(argv, argc);

        sv_save_to_file(sb_to_sv(sb_sign), signature_file_path);
        sv_save_to_file(sb_to_sv(sb_coin), coin_id);


        sb_free(sb_private_key);
        sb_free(sb_coin);
        sb_free(sb_sign);

    } else if (strcmp(subcommand, "verify") == 0){
        const char *public_key_path = shift(argv, argc);
        const char *signature_path = shift(argv, argc);
        const char *message_path = shift(argv, argc);

        String_Builder sb_public_key = {0};
        sb_read_entire_file(public_key_path, &sb_public_key);
        String_Builder sb_signature = {0};
        sb_read_entire_file(signature_path, &sb_signature);
        String_Builder sb_message = {0};
        sb_read_entire_file(message_path, &sb_message);

        int value = ds_isValid(sb_to_sv(sb_public_key), sb_to_sv(sb_message), sb_to_sv(sb_signature));
        printf("[INFO] is valid: %d\n", value);

        sb_free(sb_public_key);
        sb_free(sb_signature);
        sb_free(sb_message);

    } else {
        eprintf("[FATAL ERROR] subcomand not recognised: %s\n", subcommand);
        return(1);
    }

    ds_deinit();

    return(0);
}