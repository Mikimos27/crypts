#include <openssl/kdf.h>
#include <openssl/evp.h>
#include <string.h>

unsigned char *derive_aes_key_from_dh_secret(const unsigned char *secret, size_t secret_len,
                                             const unsigned char *salt, size_t salt_len,
                                             const unsigned char *info, size_t info_len,
                                             size_t aes_key_len)
{
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    unsigned char *aes_key = NULL;

    // Allocate space for output key
    aes_key = OPENSSL_malloc(aes_key_len);
    if (!aes_key)
        return NULL;

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf)
        goto err;

    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx)
        goto err;

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_construct_octet_string("salt", (void *)salt, salt_len),
        OSSL_PARAM_construct_octet_string("key", (void *)secret, secret_len),
        OSSL_PARAM_construct_octet_string("info", (void *)info, info_len),
        OSSL_PARAM_construct_end()
    };

    if (EVP_KDF_derive(kctx, aes_key, aes_key_len, params) <= 0)
        goto err;

    EVP_KDF_CTX_free(kctx);
    return aes_key;

err:
    EVP_KDF_CTX_free(kctx);
    OPENSSL_free(aes_key);
    return NULL;
}
