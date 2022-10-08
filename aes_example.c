#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/fips_names.h>
#include <assert.h>

#define MIN( a,b ) ( ( ( a )<( b ) )?( a ):( b ) )
#define MAX( a,b ) ( ( ( a )>( b ) )?( a ):( b ) )
#define TRUE 1
#define FALSE 0

/* key and initial vector */
static char key[16] =
    "\xaa\xbb\x45\xd4\xaa\xbb\x45\xd4"
    "\xaa\xbb\x45\xd4\xaa\xbb\x45\xd4";
static char ivec[16] =
    "\xaa\xbb\x45\xd4\xaa\xbb\x45\xd4"
    "\xaa\xbb\x45\xd4\xaa\xbb\x45\xd4";

static void
usage(int exit_code) __attribute__((noreturn));

static void
usage(int exit_code)
{
    printf("Usage: %s in out\n", getprogname());
    exit(exit_code);
}


int
main(int argc, char **argv)
{
    int encryptp = 1;
    const char *ifn = NULL, *ofn = NULL;
    FILE *in, *out;
    void *ibuf, *obuf;
    int ilen, olen;
    size_t block_size = 0;
    const EVP_CIPHER *c = EVP_aes_128_cbc();
    EVP_CIPHER_CTX *ctx;
    int ret;

    setprogname(argv[0]);

    if (argc == 2) {
        if (strcmp(argv[1], "--version") == 0) {
            printf("version");
            exit(0);
        }
        if (strcmp(argv[1], "--help") == 0)
            usage(0);
        usage(1);
    } else if (argc == 4) {
        block_size = atoi(argv[1]);
        if (block_size == 0)
            printf("Invalid blocksize %s", argv[1]);
        ifn = argv[2];
        ofn = argv[3];
    } else
        usage(1);

    in = fopen(ifn, "r");
    if (in == NULL)
        printf("Failed to open input file\n");
    out = fopen(ofn, "w+");
    if (out == NULL)
        printf("Failed to open output file\n");

    /* Check that key and ivec are long enough */
    assert(EVP_CIPHER_key_length(c) <= sizeof(key));
    assert(EVP_CIPHER_iv_length(c) <= sizeof(ivec));

    /*
     * Allocate buffer, the output buffer is at least
     * EVP_CIPHER_block_size() longer
     */
    ibuf = malloc(block_size);
    obuf = malloc(block_size + EVP_CIPHER_block_size(c));

    /*
     * Init the memory used for EVP_CIPHER_CTX and set the key and
     * ivec.
     */
    EVP_CIPHER_CTX_init(ctx);
    EVP_CipherInit_ex(ctx, c, NULL, key, ivec, encryptp);

    /* read in buffer */
    while ((ilen = fread(ibuf, 1, block_size, in)) > 0) {
        /* encrypto/decrypt */
        ret = EVP_CipherUpdate(ctx, obuf, &olen, ibuf, ilen);
        if (ret != 1) {
            EVP_CIPHER_CTX_cleanup(ctx);
            printf("EVP_CipherUpdate failed\n");
        }
        /* write out to output file */
        fwrite(obuf, 1, olen, out);
    }
    /* done reading */
    fclose(in);

    /* clear up any last bytes left in the output buffer */
    ret = EVP_CipherFinal_ex(ctx, obuf, &olen);
    EVP_CIPHER_CTX_cleanup(ctx);
    if (ret != 1)
        printf("EVP_CipherFinal_ex failed\n");

    /* write the last bytes out and close */
    fwrite(obuf, 1, olen, out);
    fclose(out);

    return 0;
}