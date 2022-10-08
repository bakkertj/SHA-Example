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

  /*
   * Fetch the SHA256 algorithm implementation for doing the digest. We're
   * using the "default" library context here (first NULL parameter), and
   * we're not supplying any particular search criteria for our SHA256
   * implementation (second NULL parameter). Any SHA256 implementation will
   * do.
   */
  sha256 = EVP_MD_fetch(NULL, "SHA256", NULL);
  if (sha256 == NULL)
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

  /* Initialise the digest operation */
  if (!EVP_DigestInit_ex(ctx, sha256, NULL))
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