#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

int main( int argc, char * argv[] )
{

  EVP_MD_CTX *ctx = NULL;
  EVP_MD *sha256 = NULL;

  unsigned int length = 0;

  /* Create a context for the digest operation */
  ctx = EVP_MD_CTX_new();
  if (ctx == NULL)
  {
    /* Clean up all the resources we allocated */
    OPENSSL_free(outdigest);
    EVP_MD_free(sha256);
    EVP_MD_CTX_free(ctx);
    if (ret != 0)
    {
      ERR_print_errors_fp(stderr);
    }
  }



  return 0;
}