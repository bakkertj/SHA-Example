#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <assert.h>
#include <string.h>

/* key and initial vector */
static char key[17] =
    "\xaa\xbb\x45\xd4\xaa\xbb\x45\xd4\xaa\xbb\x45\xd4\xaa\xbb\x45\xd4\x0" ;
static char ivec[17] =
    "\xaa\xbb\x45\xd4\xaa\xbb\x45\xd4\xaa\xbb\x45\xd4\xaa\xbb\x45\xd4\x0" ;

char *encrypt( const char *data, const char *key, const char *iv, int *length )
{
  int key_length, iv_length, data_length ;

  key_length = strlen( key ) ;
  iv_length = strlen( iv ) ;
  data_length = strlen( data ) ;

  const EVP_CIPHER *cipher ;
  int cipher_key_length, cipher_iv_length ;

  cipher            = EVP_aes_128_cbc(  ) ;
  cipher_key_length = EVP_CIPHER_key_length( cipher ) ;
  cipher_iv_length  = EVP_CIPHER_iv_length( cipher ) ;

  if ( key_length != cipher_key_length || iv_length != cipher_iv_length ) 
  {
    *length = 0 ;
    return NULL ;
  }

  EVP_CIPHER_CTX ctx ;
  int i, cipher_length, final_length ;
  unsigned char *ciphertext ;

  EVP_CIPHER_CTX_init( &ctx ) ;
  EVP_EncryptInit_ex( &ctx, cipher, NULL, ( unsigned char * )key, ( unsigned char * )iv ) ;

  cipher_length = data_length + EVP_MAX_BLOCK_LENGTH ;
  ciphertext    = ( unsigned char * )malloc( cipher_length ) ;

  EVP_EncryptUpdate( &ctx, ciphertext, &cipher_length, ( unsigned char * )data, data_length ) ;
  EVP_EncryptFinal_ex( &ctx, ciphertext + cipher_length, &final_length ) ;

  EVP_CIPHER_CTX_cleanup( &ctx ) ;

  *length = cipher_length + final_length ;

  return ciphertext ;
}

char *decrypt( const char *data, int data_length, const char *key, const char *iv )
{
  int key_length, iv_length ;

  key_length = strlen( key ) ;
  iv_length  = strlen( iv ) ;

  const EVP_CIPHER *cipher ;
  int cipher_key_length, cipher_iv_length ;

  cipher            = EVP_aes_128_cbc(  ) ;
  cipher_key_length = EVP_CIPHER_key_length( cipher ) ;
  cipher_iv_length  = EVP_CIPHER_iv_length( cipher ) ;

  if ( key_length != cipher_key_length || iv_length != cipher_iv_length ) 
  {
    return NULL ;
  }

  const char *p ;
  char *datax ;
  int i, datax_length ;

  datax = ( char * )malloc( data_length ) ;
  memcpy( datax, data, data_length ) ;
  datax_length = data_length ;

  EVP_CIPHER_CTX ctx ;

  EVP_CIPHER_CTX_init( &ctx ) ;
  EVP_DecryptInit_ex( &ctx, cipher, NULL, ( unsigned char * )key, ( unsigned char * )iv ) ;

  int plain_length, final_length ;
  unsigned char *plaintext ;

  plain_length = datax_length ;
  plaintext = ( unsigned char * )malloc( plain_length + 1 ) ;

  EVP_DecryptUpdate( &ctx, plaintext, &plain_length, ( unsigned char * )datax, datax_length ) ;
  EVP_DecryptFinal_ex( &ctx, plaintext + plain_length, &final_length ) ;

  plaintext[plain_length + final_length] = '\0' ;

  free( datax ) ;

  EVP_CIPHER_CTX_cleanup( &ctx ) ;

  return plaintext ;
}


int main( int argc, const char* argv[] )
{
  if ( argc != 2 ) 
  {
    fprintf( stderr, "Usage: %s <data>\n", argv[0] ) ;
    exit( EXIT_FAILURE ) ;
  }

  const char *data ;
  char *encrypted, *decrypted ;
  int enc_length, i ;

  data = argv[1] ;

  encrypted = encrypt( data, key, ivec, &enc_length ) ;
  for ( i = 0 ; i < enc_length ; i++ )
    printf( "%02x", ( unsigned char )encrypted[i] ) ;
  printf( "\n" ) ;

  decrypted = decrypt( encrypted, enc_length, key, ivec ) ;
  printf( "%s\n", decrypted ) ;

  free( encrypted ) ;
  free( decrypted ) ;

  return 0 ;
}