#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gcrypt.h>

void initialize_libgcrypt() {
    if (!gcry_check_version(NULL)) {
        fprintf(stderr, "libgcrypt version mismatch\n");
        exit(1);
    }
    gcry_control(GCRYCTL_SET_THREAD_CBS, NULL);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
}

// Helper function to load keys from a file
gcry_sexp_t load_key(const char *filename) {
    FILE *key_file = fopen(filename, "r");
    if (!key_file) {
        fprintf(stderr, "Failed to open key file: %s\n", filename);
        exit(1);
    }

    fseek(key_file, 0, SEEK_END);
    long len = ftell(key_file);
    fseek(key_file, 0, SEEK_SET);

    char *key_data = (char *)malloc(len);
    fread(key_data, 1, len, key_file);
    fclose(key_file);

    gcry_sexp_t key_sexp;
    if (gcry_sexp_new(&key_sexp, key_data, len, 1)) {
        fprintf(stderr, "Failed to load key data\n");
        exit(1);
    }

    free(key_data);
    return key_sexp;
}

int main(){
    gcry_sexp_t pub_key = load_key("public_key.pem");
    gcry_sexp_t prv_key = load_key("private_key.pem");

    gcry_sexp_release(pub_key);
    return 0;
}
