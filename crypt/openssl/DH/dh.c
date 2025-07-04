#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <stdio.h>
#include "derive_aes_dh.c"

// Choose desired group
#define DH_GROUP "ffdhe2048"
#define OPENSSL_API_COMPAT 0x30500010

static void handle_errors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}


int main(void) {
    EVP_PKEY_CTX *pctx = NULL, *kctx = NULL, *dctx = NULL;
    EVP_PKEY *params = NULL, *my_key = NULL, *peer_key = NULL;
    unsigned char *secret = NULL;
    size_t slen;

    // Create context for parameter generation
    pctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
    if (!pctx || EVP_PKEY_paramgen_init(pctx) <= 0) handle_errors();

    // Specify the named group via OSSL_PARAM
    OSSL_PARAM params_arr[2];
    params_arr[0] = OSSL_PARAM_construct_utf8_string(
        "group", DH_GROUP, 0);//stack
    params_arr[1] = OSSL_PARAM_construct_end();
    if (EVP_PKEY_CTX_set_params(pctx, params_arr) <= 0)
        handle_errors();

    // Generate parameters
    if (EVP_PKEY_paramgen(pctx, &params) <= 0) handle_errors();

    // Generate our own key
    kctx = EVP_PKEY_CTX_new(params, NULL);                        //
    if (!kctx || EVP_PKEY_keygen_init(kctx) <= 0) handle_errors();//TO ZASTĄPIĆ CZYTANIEM KLUCZY Z PLIKU??
    if (EVP_PKEY_keygen(kctx, &my_key) <= 0) handle_errors();     //

    // Simulate peer keygen
    EVP_PKEY_keygen_init(kctx);                                //
    if (EVP_PKEY_keygen(kctx, &peer_key) <= 0) handle_errors();//TO ZASTĄPIĆ KLUCZEM PUBLICZNYM?

    // Perform key derivation
    dctx = EVP_PKEY_CTX_new(my_key, NULL);
    if (!dctx || EVP_PKEY_derive_init(dctx) <= 0) handle_errors();
    if (EVP_PKEY_derive_set_peer(dctx, peer_key) <= 0) handle_errors();

    // Determine secret length and derive
    EVP_PKEY_derive(dctx, NULL, &slen);
    secret = OPENSSL_malloc(slen);
    if (!secret || EVP_PKEY_derive(dctx, secret, &slen) <= 0)
        handle_errors();

    printf("Shared secret (%zu bytes):\n", slen);
    for (size_t i = 0; i < slen; i++) printf("%02x", secret[i]);
    printf("\n");





    size_t key_len = 32; // 256-bit AES key
    unsigned char salt[16] = {0}; // You can randomize this
    unsigned char info[] = "aes-gcm key derivation";

    RAND_bytes(salt, sizeof(salt));

    // `shared_secret` and `shared_secret_len` come from EVP_PKEY_derive()
    unsigned char *aes_key = derive_aes_key_from_dh_secret(
        secret, slen,
        salt, sizeof(salt),
        info, sizeof(info) - 1,
        key_len
    );
    printf("aes key:\n");
    for(int i = 0; i < key_len; i++){
        printf("%02x", aes_key[i]);
    }
    printf("\n");

    printf("key salt:\n");
    for(int i = 0; i < sizeof(salt); i++){
        printf("%02x", salt[i]);
    }
    printf("\n");



    EVP_PKEY_free(params);
    EVP_PKEY_free(my_key);
    EVP_PKEY_free(peer_key);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_CTX_free(dctx);
    OPENSSL_free(secret);

    return 0;
}
