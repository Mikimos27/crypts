#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gcrypt.h>

#define RSA_KEY_SIZE 4096
#define NEED_LIBGCRYPT_VERSION "1.0.0"
#define MAX_BUFF 8192

int init(){
    if (!gcry_check_version (NEED_LIBGCRYPT_VERSION))
    {
        fprintf (stderr, "libgcrypt is too old (need %s, have %s)\n",
                 NEED_LIBGCRYPT_VERSION, gcry_check_version (NULL));
        exit (2);
    }

    gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
    gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);
    gcry_control (GCRYCTL_RESUME_SECMEM_WARN);

    /* ... If required, other initialization goes here.  */

    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
}
gcry_sexp_t generate_rsa_key_pair(int key_size) {
    gcry_sexp_t rsa_keypair;
    gcry_sexp_t rsa_params;
    
    // Create RSA parameters                    v---- tu dać key_size
    const char *params = "(genkey (rsa (nbits 4:4096)))"; // You can adjust the key size here
    
    // Convert to sexp (s-expression) format for RSA generation
    gcry_sexp_new(&rsa_params, params, strlen(params), 0);
    
    // Generate the RSA keypair
    if (gcry_pk_genkey(&rsa_keypair, rsa_params)) {
        fprintf(stderr, "Error generating RSA key pair\n");
        exit(1);
    }

    gcry_sexp_release(rsa_params); // Release the parameter sexp after key generation
    return rsa_keypair;
}

void export_key(gcry_sexp_t rsa_keypair) {
    char buff[MAX_BUFF] = {0};
    gcry_sexp_t public_key = gcry_sexp_find_token(rsa_keypair, "public-key", 0);
    gcry_sexp_t private_key = gcry_sexp_find_token(rsa_keypair, "private-key", 0);

        // Export private key (for example, to PEM)
    FILE *private_key_file = fopen("private_key.pem", "w");
    if (private_key_file) {
        int len = gcry_sexp_sprint(private_key, 0, buff, MAX_BUFF);
        fwrite(buff, 1, len, private_key_file);
        fclose(private_key_file);
    } else {
        fprintf(stderr, "Error opening file for private key export\n");
    }

    // Export public key (for example, to PEM)
    FILE *public_key_file = fopen("public_key.pem", "w");
    if (public_key_file) {
        int len = gcry_sexp_sprint(public_key, 0, buff, MAX_BUFF);
        fwrite(buff, 1, len, public_key_file);
        fclose(public_key_file);
    } else {
        fprintf(stderr, "Error opening file for public key export\n");
    }
    
    gcry_sexp_release(public_key);
    gcry_sexp_release(private_key);
}


int main(){
    init();
    if (!gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P))
    {
        fputs ("libgcrypt has not been initialized\n", stderr);
        return 2;
    }
    gcry_sexp_t rsa_keypair = generate_rsa_key_pair(RSA_KEY_SIZE);
    export_key(rsa_keypair);
    gcry_sexp_release(rsa_keypair);
    return 0;
}
