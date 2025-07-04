#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define AES_KEYLEN 32  // 128 bits

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

// Encrypts plaintext and outputs ciphertext
int encrypt(unsigned char *plaintext, int plaintext_len,
            unsigned char *key, unsigned char *iv,
            unsigned char *ciphertext) {
    
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

// Decrypts ciphertext and outputs plaintext
int decrypt(unsigned char *ciphertext, int ciphertext_len,
            unsigned char *key, unsigned char *iv,
            unsigned char *plaintext) {
    
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();

    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    
    plaintext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

int main() {
    // Generate random key and IV
    unsigned char key[AES_KEYLEN];
    unsigned char iv[AES_KEYLEN];

    if (!RAND_bytes(key, sizeof(key))) handleErrors();
    if (!RAND_bytes(iv, sizeof(iv))) handleErrors();

    // Message to encrypt
    unsigned char *plaintext = (unsigned char *)"This is a top secret message!";
    unsigned char ciphertext[128];
    unsigned char decryptedtext[128];

    int ciphertext_len = encrypt(plaintext, strlen((char *)plaintext), key, iv, ciphertext);
    int decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);
    decryptedtext[decryptedtext_len] = '\0';

    printf("Plaintext: %s\n", plaintext);
    printf("Key (hex):\n");
    for (int i = 0; i < AES_KEYLEN; i++)
        printf("%02x", key[i]);
    printf("\nIV (hex):\n");
    for (int i = 0; i < AES_KEYLEN; i++)
        printf("%02x", iv[i]);
    printf("\nCiphertext (hex):\n");
    for (int i = 0; i < ciphertext_len; i++)
        printf("%02x", ciphertext[i]);
    printf("\nDecrypted text: %s\n", decryptedtext);

    return 0;
}
