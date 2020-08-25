#include <stdint.h>
#include "nxflat.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/fcntl.h>

#include <getopt.h>
#include <unistd.h>

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

static char *private_key = NULL;
static char *hash_type_opt = "md4";
int hash_type;

char* program_name;
char* key_file;
char* signature_type;

static void show_usage (void)
{
  fprintf(stderr, "Usage: %s -k <private key file> -s <signature type> <nxflat>\n\n", program_name);

  fprintf(stderr, "  -s md4,md5,sha1\n     signature type used for signing\n");

  fprintf(stderr, "\n");
  exit(2);
}
   
          
int sign_rsa(int fd, char* keyfile, const EVP_MD* digest) {
  FILE *file;
  EVP_PKEY *pkey;
  EVP_MD_CTX *mdctx = NULL;
  int ret = 0;
  size_t slen;
  unsigned char* sigbuf;

  file        = fopen(keyfile, "r");
  if(!file) {
      perror("Failed to open key file");
      return -1;
  }

  pkey = PEM_read_PrivateKey(
      file,     /* use the FILE* that was opened */
      NULL, /* pointer to EVP_PKEY structure */
      NULL,  /* password callback - can be NULL */
      NULL   /* parameter passed to callback or password if callback is NULL */
  );

  /* Create the Message Digest Context */
  if (!(mdctx = EVP_MD_CTX_create())) {
      ERR_print_errors_fp(stderr);
    return -1;
  }

  if (1 != EVP_DigestSignInit (mdctx, NULL, digest, NULL, pkey)) {
      ERR_print_errors_fp(stderr);
      return -1;
  }

  uint8_t buf[256];
  lseek(fd, offsetof(struct nxflat_hdr_s, h_signature), SEEK_SET);
  
  
  lseek(fd, offsetof(struct nxflat_hdr_s, h_entry), SEEK_SET);
  for(;;) {
      ret = read(fd, buf, sizeof buf);
      if(ret == 0) 
        break;
      EVP_DigestSignUpdate(mdctx, buf, ret);
  }

  /* Finalise the DigestSign operation */
  /* First call EVP_DigestSignFinal with a NULL sig parameter to obtain the length of the
   * signature. Length is returned in slen */
  if ( EVP_DigestSignFinal (mdctx, NULL, &slen) != 1) {
      ERR_print_errors_fp(stderr);
      return -1;
  }

  /* Allocate memory for the signature based on size in slen */
  sigbuf = OPENSSL_malloc(slen);

  /* Obtain the signature */
  if (EVP_DigestSignFinal (mdctx, sigbuf, &slen) != 1) {
    ERR_print_errors_fp(stderr);
    return -1;
  }

  int pos = lseek(fd, 0, SEEK_END);
  uint32_t siginfo =  NXFLAT_SIGNATURE_OFFSET(pos) |
      NXFLAT_SIGNATURE_TYPE(hash_type);

  pwrite(fd, (uint8_t*)&siginfo, sizeof(siginfo), 4);

  write(fd, sigbuf, slen);

  OPENSSL_free(sigbuf);

  if (mdctx) {
    EVP_MD_CTX_destroy(mdctx);
  }

  return 0;
}


int main(int argc, char** argv) {
  program_name = argv[0];
  
  int opt;
  while ((opt = getopt(argc, argv, "hk:s:")) != -1)
    {
      switch (opt)
        {
        case 'k':
          private_key = strdup(optarg);
          break;
        case 's':
          hash_type_opt = strdup(optarg);
          break;

        case 'h':
          show_usage();
          break;

        default:
        
          fprintf(stderr, "%s Unknown option\n\n", argv[0]);
          
          show_usage();
          exit(0);
        }
    }    
    
  const char* nxf_filename = argv[argc - 1];

  if(private_key) {
      const EVP_MD * evp;
      if (strcmp(hash_type_opt, "md4") == 0)
        {
          evp = EVP_md4();
          hash_type = NXFLAT_SIGNATURE_TYPE_RSA_MD4;
        }
      else if (strcmp(hash_type_opt, "md5") == 0)
        {
          evp = EVP_md5();
          hash_type = NXFLAT_SIGNATURE_TYPE_RSA_MD5;
        }
      else if (strcmp(hash_type_opt, "sha1") == 0)
        {
          hash_type = NXFLAT_SIGNATURE_TYPE_RSA_SHA1;
          evp = EVP_sha1();
        } else {
            evp = EVP_md4();
            hash_type = NXFLAT_SIGNATURE_TYPE_RSA_MD4;
        }

      fprintf(stderr, "Signing using RSA key: %s\n", private_key);
      fprintf(stderr, "Using digest: %s\n", EVP_MD_name(evp));
      
      int fd = open(nxf_filename, O_RDWR);
      char magic[4];
      read(fd, magic, 4);
      if(memcmp(magic, NXFLAT_MAGIC, 4) != 0) {
        fprintf(stderr, "Not a NxFLAT file\n");
        exit(1);
      }
      

      if(sign_rsa(fd, private_key, evp) < 0) {
          fprintf (stderr, "Sign failed\n");
          exit(1);
      }
    }
  }
