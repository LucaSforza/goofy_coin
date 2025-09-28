#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <signal.h>

#include <readline/readline.h>
#include <readline/history.h>

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

void sigint_handler(int signo) {
    // Cancella la riga corrente e mostra un nuovo prompt
    (void)signo; // evita warning unused parameter
    printf("\n");              // va a capo come bash
    rl_replace_line("", 0);    // svuota linea
    rl_on_new_line();         // va a nuova linea
    rl_redisplay();           // ridisegna il prompt
}

void execute_command(String_View sv_command, String_View sv_input) {

    if(sv_eq(sv_command, sv_from_cstr("createUser"))) {
        String_Builder sb_private_path = sv_to_sb_null(sv_chop_by_spaces(&sv_input));
        if(sb_private_path.count == 0) {
            printf("[ERROR] please provide the path to the private key\n");
            return;
        }
        String_Builder sb_public_path = sv_to_sb_null(sv_chop_by_spaces(&sv_input));
        if(sb_public_path.count == 0) {
            printf("[ERROR] please provide the path to the public key\n");
            sb_free(sb_private_path);
            return;
        }
        String_Builder priv = {0};
        String_Builder pub  = {0};

        // Genera coppia di chiavi RSA 2048
        control(ds_generate_Keys(2048, &priv, &pub));

        sv_save_to_file(sb_to_sv(priv), sb_private_path.items);
        sv_save_to_file(sb_to_sv(pub), sb_public_path.items);

        sb_free(priv);
        sb_free(pub);
        sb_free(sb_private_path);
        sb_free(sb_public_path);

    } else if (sv_eq(sv_command, sv_from_cstr("sign"))) {
        String_Builder sb_file_to_sign_path = sv_to_sb_null(sv_chop_by_spaces(&sv_input));
        if(sb_file_to_sign_path.count == 0) {
            printf("[ERROR] please provide the path to the file to sign\n");
            return;
        }
        String_Builder sb_private_path = sv_to_sb_null(sv_chop_by_spaces(&sv_input));
        if(sb_private_path.count == 0) {
            printf("[ERROR] please provide the path to the private key\n");
            sb_free(sb_file_to_sign_path);
            return;
        }
        String_Builder sb_output_path = sv_to_sb_null(sv_chop_by_spaces(&sv_input));
        if(sb_output_path.count == 0) {
            printf("[ERROR] please provide the output signature path\n");
            sb_free(sb_file_to_sign_path);
            sb_free(sb_private_path);
            return;
        }

        String_Builder sb_file_to_sign = {0};
        sb_read_entire_file(sb_file_to_sign_path.items, &sb_file_to_sign);

        String_Builder sb_private_key = {0};
        sb_read_entire_file(sb_private_path.items, &sb_private_key);
        
        String_Builder sb_sign = {0};
        control(ds_signature(sb_to_sv(sb_private_key), sb_to_sv(sb_file_to_sign), &sb_sign));
        sv_save_to_file(sb_to_sv(sb_sign), sb_output_path.items);

        sb_free(sb_file_to_sign);
        sb_free(sb_private_key);
        sb_free(sb_sign);
        sb_free(sb_file_to_sign_path);
        sb_free(sb_private_path);
        sb_free(sb_output_path);

    } else if (sv_eq(sv_command, sv_from_cstr("createCoin"))) {
        String_Builder sb_private_path = sv_to_sb_null(sv_chop_by_spaces(&sv_input));
        if(sb_private_path.count == 0) {
            printf("[ERROR] please provide the path to the private key\n");
            return;
        }
        String_Builder sb_coin_id = sv_to_sb_null(sv_chop_by_spaces(&sv_input));
        if(sb_coin_id.count == 0) {
            printf("[ERROR] please provide the coin id\n");
            sb_free(sb_private_path);
            return;
        }
        String_Builder sb_signature_path = sv_to_sb_null(sv_chop_by_spaces(&sv_input));
        if(sb_signature_path.count == 0) {
            printf("[ERROR] please provide the signature output path\n");
            sb_free(sb_private_path);
            sb_free(sb_coin_id);
            return;
        }

        String_Builder sb_private_key = {0};
        sb_read_entire_file(sb_private_path.items, &sb_private_key);

        String_Builder sb_coin = {0};
        sb_append_cstr(&sb_coin, "CreateCoin ");
        sb_append_cstr(&sb_coin, sb_coin_id.items);

        String_Builder sb_sign = {0};
        control(ds_signature(sb_to_sv(sb_private_key), sb_to_sv(sb_coin), &sb_sign));

        sv_save_to_file(sb_to_sv(sb_sign), sb_signature_path.items);
        sv_save_to_file(sb_to_sv(sb_coin), sb_coin_id.items);

        sb_free(sb_private_key);
        sb_free(sb_coin);
        sb_free(sb_sign);
        sb_free(sb_private_path);
        sb_free(sb_coin_id);
        sb_free(sb_signature_path);

    } else if (sv_eq(sv_command, sv_from_cstr("verify"))) {
        String_Builder sb_public_key_path = sv_to_sb_null(sv_chop_by_spaces(&sv_input));
        if(sb_public_key_path.count == 0) {
            printf("[ERROR] please provide the path to the public key\n");
            return;
        }
        String_Builder sb_signature_path = sv_to_sb_null(sv_chop_by_spaces(&sv_input));
        if(sb_signature_path.count == 0) {
            printf("[ERROR] please provide the path to the signature\n");
            sb_free(sb_public_key_path);
            return;
        }
        String_Builder sb_message_path = sv_to_sb_null(sv_chop_by_spaces(&sv_input));
        if(sb_message_path.count == 0) {
            printf("[ERROR] please provide the path to the message\n");
            sb_free(sb_public_key_path);
            sb_free(sb_signature_path);
            return;
        }

        String_Builder sb_public_key = {0};
        sb_read_entire_file(sb_public_key_path.items, &sb_public_key);
        String_Builder sb_signature = {0};
        sb_read_entire_file(sb_signature_path.items, &sb_signature);
        String_Builder sb_message = {0};
        sb_read_entire_file(sb_message_path.items, &sb_message);

        int value = ds_isValid(sb_to_sv(sb_public_key), sb_to_sv(sb_message), sb_to_sv(sb_signature));
        printf("[INFO] is valid: %d\n", value);

        sb_free(sb_public_key);
        sb_free(sb_signature);
        sb_free(sb_message);
        sb_free(sb_public_key_path);
        sb_free(sb_signature_path);
        sb_free(sb_message_path);

    } else {
        String_Builder sb_cmd = sv_to_sb_null(sv_command);
        printf("[ERROR] command not recognised: %s\n", sb_cmd.items);
        sb_free(sb_cmd);
    }
}

int main(void) {
    char *input = NULL;

    // Disabilita handler di default di Readline
    rl_catch_signals = 0;
    // Imposta handler personalizzato
    signal(SIGINT, sigint_handler);

    control(ds_init());

    while((input = readline("> ")) != NULL) {
        if(*input) {
            add_history(input);
        }

        if (strcmp(input, "exit") == 0) {
            ds_deinit();
            return 0;
        }

        String_View sv_input   = sv_from_cstr(input);
        String_View sv_command = sv_chop_by_spaces(&sv_input);

        execute_command(sv_command, sv_input);
        
        free(input);
    }
    ds_deinit();
    return 0;
}