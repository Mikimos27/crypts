#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>

#define AES_KEY_SIZE 16  // 256 bits = 32 bytes
#define AES_BLOCK_SIZE 16   // CBC mode block size

int main() {
    unsigned char key[AES_KEY_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];

    // Generate random AES-256 key
    if (RAND_bytes(key, sizeof(key)) != 1) {
        fprintf(stderr, "Failed to generate AES key.\n");
        return 1;
    }

    // Generate random IV
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        fprintf(stderr, "Failed to generate IV.\n");
        return 1;
    }

    // Print key and IV in hex
    printf("AES Key: ");
    for (int i = 0; i < AES_KEY_SIZE; i++) {
        printf("%02x", key[i]);
    }
    printf("\n");

    printf("IV: ");
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        printf("%02x", iv[i]);
    }
    printf("\n");

    return 0;
}
