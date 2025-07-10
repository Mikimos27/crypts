#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stddef.h>


int KeyGenRSA(const char* pubfile, const char* privfile, size_t keylen){
    
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey = NULL;
    int unfinished = 1;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx)
        goto error;
    if (EVP_PKEY_keygen_init(ctx) <= 0)
        goto error;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keylen) <= 0)
        goto error;

    /* Generate key */
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        goto error;

    FILE* fpr = fopen(privfile, "w");
    FILE* fpu = fopen(pubfile, "w");
    if(fpr == NULL || fpu == NULL) goto error;
    

    PEM_write_PUBKEY(fpu, pkey);
    PEM_write_PrivateKey(fpr, pkey, NULL, NULL, 0, NULL, NULL);


    unfinished = 0;
error:
    fclose(fpr);
    fclose(fpu);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return unfinished;
}

int LoadKeyPriv(const char* filename, EVP_PKEY** pkey){
    FILE* fp = fopen(filename, "r");
    int ret = 1;
    if(fp == NULL) goto cleanuppriv;

    PEM_read_PrivateKey(fp, pkey, NULL, NULL);

    //i2d_PrivateKey_fp(stdout, pkey);
    ret = 0;
cleanuppriv:
    fclose(fp);
    return ret;
}

int LoadKeyPub(const char* filename, EVP_PKEY** pkey){
    FILE* fp = fopen(filename, "r");
    int ret = 1;
    if(fp == NULL) goto cleanuppub;
    PEM_read_PUBKEY(fp, pkey, NULL, NULL);

     
    ret = 0;
cleanuppub:
    fclose(fp);
    return ret;
}

int main(int argc, char** argv){
    if(argc < 2){
        fprintf(stderr, "No size given\n");
        return 1;
    }
    int keysize = atoi(argv[1]);
    if(keysize == 0){
        fprintf(stderr, "Bad size given\n");
        return 1;
    }
    KeyGenRSA("public.pem", "private.pem", keysize);
    EVP_PKEY* privatekey = EVP_PKEY_new();
    EVP_PKEY* publickey = EVP_PKEY_new();

    LoadKeyPriv("private.pem", &privatekey);
    LoadKeyPub("public.pem", &publickey);


    //PEM_write_PrivateKey(stdout, privatekey, NULL, NULL, 0, NULL, NULL);
    //PEM_write_PUBKEY(stdout, publickey);


    EVP_PKEY_free(privatekey);
    EVP_PKEY_free(publickey);
    return 0;
}
