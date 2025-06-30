#include <gcrypt.h>
#define NEED_LIBGCRYPT_VERSION "1.0.0"

int init(){
    /* Version check should be the very first call because it
     makes sure that important subsystems are initialized.
     #define NEED_LIBGCRYPT_VERSION to the minimum required version. */
    if (!gcry_check_version (NEED_LIBGCRYPT_VERSION))
    {
        fprintf (stderr, "libgcrypt is too old (need %s, have %s)\n",
                 NEED_LIBGCRYPT_VERSION, gcry_check_version (NULL));
        exit (2);
    }

    /* We don't want to see any warnings, e.g. because we have not yet
     parsed program options which might be used to suppress such
     warnings. */
    gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);

    /* ... If required, other initialization goes here.  Note that the
     process might still be running with increased privileges and that
     the secure memory has not been initialized.  */

    /* Allocate a pool of 16k secure memory.  This makes the secure memory
     available and also drops privileges where needed.  Note that by
     using functions like gcry_xmalloc_secure and gcry_mpi_snew Libgcrypt
     may expand the secure memory pool with memory which lacks the
     property of not being swapped out to disk.   */
    gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);

    /* It is now okay to let Libgcrypt complain when there was/is
     a problem with the secure memory. */
    gcry_control (GCRYCTL_RESUME_SECMEM_WARN);

    /* ... If required, other initialization goes here.  */

    /* Tell Libgcrypt that initialization has completed. */
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
}

int main(){
    init();
    if (!gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P))
    {
        fputs ("libgcrypt has not been initialized\n", stderr);
        return 2;
    }
    char* s = "Some text";
    gcry_md_hd_t h;
    gcry_md_open(&h, GCRY_MD_SHA256, GCRY_MD_FLAG_SECURE); /* initialise the hash context */
    gcry_md_write(h, s, strlen(s)); /* hash some text */
    unsigned char* x = gcry_md_read(h, GCRY_MD_SHA256); /* get the result */

    for (int i = 0; i < strlen(x); i++)
    {
        printf("%02x", x[i]); /* print the result */
    }
    printf("\n");
    return 0;




    printf("%s\n", "HALLO!");
    return 0;
}
