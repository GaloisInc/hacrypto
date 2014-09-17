/* 
   Sample application using FIPS mode OpenSSL.

   This application will qualify as FIPS 140-2 validated when built,
   installed, and utilized as described in the "OpenSSL FIPS 140-2
   Security Policy" manual.

   This command calculates a HMAC-SHA-1 digest of a file or input data
   stream using the same arbitrary hard-coded key as the FIPS 140-2
   source file build-time integrity checks and runtime executable
   file integrity check.
*/

#include <stdio.h>
#include <string.h>
#include <openssl/hmac.h>

static char label[] = "@(#)FIPS approved SHA1 HMAC";

static void dofile(FILE *fp)
    {
    HMAC_CTX ctx;
    unsigned char hmac_value[EVP_MAX_MD_SIZE];
    int hmac_len, i;
    char key[] = "etaonrishdlcupfm";
    char buf[256];

    /* Initialise context */
    HMAC_CTX_init(&ctx);
    /* Set digest type and key in context */ 
    HMAC_Init_ex(&ctx, key, strlen(key), EVP_sha1(), NULL);
    /* Process input stream */
    while(i = fread(buf,sizeof(char),sizeof(buf),fp)) {
        if(!HMAC_Update(&ctx, buf, i)) exit(3);
    }
    /* Generate digest */
    if(!HMAC_Final(&ctx, hmac_value, &hmac_len)) exit(4);
    HMAC_CTX_cleanup(&ctx);

    /* Display digest in hex */ 
    for(i = 0; i < hmac_len; i++) printf("%02x", hmac_value[i]);
        printf("\n");
    return;
}

main(int argc, char *argv[])
    {
    char *opt = NULL;
    int verbose = 0;
    int fipsmode = 1;
    FILE *fp = stdin;
    int i;

    /* Process command line arguments */ 
    i = 0;
    while(++i < argc) {
        opt = argv[i];
        if (!strcmp(opt,"-v")) verbose = 1;
        else if (!strcmp(opt,"-c")) fipsmode = 0;
        else if ('-' == opt[0]) {
            printf("Usage: %s <filename>\n", argv[0]);
            puts("Options:");
            puts("\t-c\tUse non-FIPS mode"); 
            puts("\t-v\tVerbose output"); 
            exit(1);
        }
        else break;
    }
 
    /* Enter FIPS mode by default */
    if (fipsmode) {
        if(FIPS_mode_set(1)) {
            verbose && fputs("FIPS mode enabled\n",stderr);
        }
        else {
            ERR_load_crypto_strings();
            ERR_print_errors_fp(stderr);
            exit(1);
        }
    }

    if (i >= argc) {
        dofile(fp);
    }
    else {
        while(i < argc) { 
            opt = argv[i];
            if ((fp = fopen(opt,"rb")) == NULL) {
                fprintf(stderr,"Unable to open file \"%s\"\n", opt);
                exit(1);
            }
        dofile(fp);
        fclose(fp);
        i++;
        }
    }

    exit(0);
}
