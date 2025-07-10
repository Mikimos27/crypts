#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define AES_KEYLEN 32  // AES-256
#define AES_IVLEN 12   // Recommended IV size for GCM
#define TAG_LEN   16   // GCM tag size

// Helper to print bytes as hex
void print_hex(const char *label, const unsigned char *data, int len) {
    printf("%s", label);
    for (int i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

// AES-GCM encryption
int aes_gcm_encrypt(const unsigned char *plaintext, int plaintext_len,
                    const unsigned char *aad, int aad_len,
                    const unsigned char *key,
                    const unsigned char *iv,
                    unsigned char *ciphertext,
                    unsigned char *tag) {
    EVP_CIPHER_CTX *ctx;
    int len, ciphertext_len;

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_IVLEN, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    if (aad && aad_len > 0)
        EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len);

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag);
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

// AES-GCM decryption
int aes_gcm_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                    const unsigned char *aad, int aad_len,
                    const unsigned char *tag,
                    const unsigned char *key,
                    const unsigned char *iv,
                    unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len, plaintext_len, ret;

    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_IVLEN, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);

    if (aad && aad_len > 0)
        EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len);

    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void *)tag);

    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        plaintext_len += len;
        return plaintext_len;
    } else {
        return -1; // authentication failed
    }
}

int main() {
    // Setup
    unsigned char key[AES_KEYLEN];
    unsigned char iv[AES_IVLEN];
    unsigned char tag[TAG_LEN];
    unsigned char aad[] = "header-data";
    unsigned char *plaintext = (unsigned char *)"This is a secret file message.";
    unsigned char ciphertext[1024], decrypted[1024];

    // Generate random key and IV
    RAND_bytes(key, sizeof(key));
    RAND_bytes(iv, sizeof(iv));

    // Encrypt
    int ct_len = aes_gcm_encrypt(plaintext, strlen((char *)plaintext),
                                 aad, sizeof(aad)-1,
                                 key, iv, ciphertext, tag);

    // Output
    print_hex("Key:       ", key, AES_KEYLEN);
    print_hex("IV:        ", iv, AES_IVLEN);
    print_hex("Tag:       ", tag, TAG_LEN);
    print_hex("Ciphertext:", ciphertext, ct_len);

    // Decrypt
    int pt_len = aes_gcm_decrypt(ciphertext, ct_len,
                                 aad, sizeof(aad)-1,
                                 tag, key, iv, decrypted);

    if (pt_len >= 0) {
        decrypted[pt_len] = '\0'; // Null-terminate for display
        printf("Decrypted: %s\n", decrypted);
    } else {
        printf("Decryption failed: Authentication failed!\n");
    }
    printf("Plaintext size = %d\nCiphertext size = %d\n", pt_len, ct_len);

    return 0;
}

