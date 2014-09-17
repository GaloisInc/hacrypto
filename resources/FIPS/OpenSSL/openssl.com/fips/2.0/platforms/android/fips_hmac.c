/* 
   Sample application using FIPS mode OpenSSL.

   This application will qualify as FIPS 140-2 validated when built,
   installed, and utilized as described in the "OpenSSL FIPS 140-2
   Security Policy" manual.

   This command calculates a HMAC-SHA-1 digest of files or input data
   stream using the same arbitrary hard-coded key as the FIPS 140-2
   source file build-time integrity checks and runtime executable
   file integrity check.
*/

#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/hmac.h>

static char label[] = "@(#)FIPS approved SHA1 HMAC";

static void doUsage(const char* prog)
{
  printf("Usage: %s [-c|-v] <filename>\n", prog);
  puts("  Options:");
  puts("\t-c\tUse non-FIPS mode");
  puts("\t-v\tVerbose output");
}

static void doFile(FILE *fp)
{
  HMAC_CTX ctx;
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int i = 0, dlen = (unsigned int)sizeof(digest);
  size_t rd = 0;
  const char key[] = "etaonrishdlcupfm";
  unsigned char buf[4096];

  /* Initialise context */
  HMAC_CTX_init(&ctx);
  /* Set digest type and key in context */
  HMAC_Init_ex(&ctx, key, strlen(key), EVP_sha1(), NULL);
  /* Process input stream */
  do {
    rd = fread(buf,sizeof(char),sizeof(buf),fp);
    if(ferror(fp) || ((rd < sizeof(buf)) && !feof(fp))) exit(3);
    if(!HMAC_Update(&ctx, buf, (unsigned int)rd)) exit(4);
  } while(!feof(fp));

  /* Generate digest */
  if(!HMAC_Final(&ctx, digest, &dlen)) exit(5);
  HMAC_CTX_cleanup(&ctx);

  /* Display digest in hex */
  for(i = 0; i < dlen; i++) printf("%02x", digest[i]);
  printf("\n");
  return;
}

int main(int argc, char *argv[])
{
  char *opt = NULL;
  int verbose = 0, fipsmode = 1, i = 0;
  FILE *fp = NULL;

  /* Process command line arguments */ 
  i = 0;
  while(++i < argc) {
    opt = argv[i];
    if (0 /*match*/ == strcmp(opt,"-v")) verbose = 1;
    else if (0 /*match*/ == strcmp(opt,"-c")) fipsmode = 0;
    else if ('-' == opt[0]) {
      doUsage(argv[0]);
      exit(1);
    }
    else break;
  }
 
  /* Enter FIPS mode by default */
  if (fipsmode) {
    if(verbose) {
      printf("Attempting FIPS mode...\n");
    }
    if(FIPS_mode_set(1)) {
      if(verbose) {
	printf("FIPS mode enabled\n");
      }
    }
    else {
      ERR_load_crypto_strings();
      ERR_print_errors_fp(stderr);
      exit(2);
    }
  }

  /* If no file arguments, process stdin */
  if (i >= argc) {
    doFile(stdin);
  }
  else {
    while((i < argc) && (opt = argv[i++])) {
      if ((fp = fopen(opt,"rb")) == NULL) {
	fprintf(stderr,"Unable to open file \"%s\"\n", opt);
	exit(1);
      }
      if(verbose) {
	printf("%s: ", opt);
      }
      doFile(fp);
      fclose(fp), fp = NULL;
    }
  }

  return 0;
}
