/*
 * Copyright Daniel Silverstone <dsilvers@digital-scurf.org> 2006-2011
 */

#include "config.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "libgfshare.h"

#define DEFAULT_SHARECOUNT 5
#define DEFAULT_THRESHOLD 3
#define BUFFER_SIZE 4096

#ifndef MIN
#define MIN(a,b) ((a)<(b))?(a):(b)
#endif

static void
gfsplit_fill_rand( unsigned char *buffer,
                   unsigned int count )
{
  size_t n;
  FILE *devrandom;

  devrandom = fopen("/dev/urandom", "rb");
  if (!devrandom) {
    perror("Unable to read /dev/urandom");
    abort();
  }
  n = fread(buffer, 1, count, devrandom);
  if (n < count) {
      perror("Short read from /dev/urandom");
      abort();
  }
  fclose(devrandom);
}

static char* progname;

void
usage(FILE* stream)
{
  fprintf( stream, "\
Usage: %s [-n threshold] [-m sharecount] inputfile [outputstem]\n\
  where sharecount is the number of shares to build.\n\
  where threshold is the number of shares needed to recombine.\n\
  where inputfile is the file to split.\n\
  where outputstem is the stem for the output files.\n\
\n\
The sharecount option defaults to %d.\n\
The threshold option defaults to %d.\n\
The outputstem option defaults to the inputfile.\n\
\n\
The program automatically adds \".NNN\" to the output stem for each share.\n\
", progname, DEFAULT_SHARECOUNT, DEFAULT_THRESHOLD );
}

static unsigned int
getlen( FILE* f )
{
  unsigned int len;
  fseek(f, 0, SEEK_END);
  len = ftell(f);
  fseek(f, 0, SEEK_SET);
  return len;
}

static int
do_gfsplit( unsigned int sharecount, 
            unsigned int threshold,
            char *_inputfile,
            char *_outputstem )
{
  FILE *inputfile;
  unsigned char* sharenrs = malloc( sharecount );
  unsigned int i, j;
  FILE **outputfiles = malloc( sizeof(FILE*) * sharecount );
  char **outputfilenames = malloc( sizeof(char*) * sharecount );
  char* outputfilebuffer = malloc( strlen(_outputstem) + 5 );
  unsigned char* buffer = malloc( BUFFER_SIZE );
  gfshare_ctx *G;
  
  if( sharenrs == NULL || outputfiles == NULL || outputfilenames == NULL || outputfilebuffer == NULL || buffer == NULL ) {
    perror( "malloc" );
    return 1;
  }
  
  inputfile = fopen( _inputfile, "rb" );
  if( inputfile == NULL ) {
    perror( _inputfile );
    return 1;
  }
  for( i = 0; i < sharecount; ++i ) {
    unsigned char proposed = (random() & 0xff00) >> 8;
    if( proposed == 0 ) {
      proposed = 1;
    }
    SHARENR_TRY_AGAIN:
    for( j = 0; j < i; ++j ) {
      if( sharenrs[j] == proposed ) {
        proposed++;
        if( proposed == 0 ) proposed = 1;
        goto SHARENR_TRY_AGAIN;
      }
    }
    sharenrs[i] = proposed;
    sprintf( outputfilebuffer, "%s.%03d", _outputstem, proposed );
    outputfiles[i] = fopen( outputfilebuffer, "wb" );
    if( outputfiles[i] == NULL ) {
      perror(outputfilebuffer);
      return 1;
    }
    outputfilenames[i] = strdup(outputfilebuffer);
  }
  /* All open, all ready and raring to go... */
  G = gfshare_ctx_init_enc( sharenrs, sharecount, 
                            threshold, MIN(BUFFER_SIZE, getlen( inputfile )) );
  if( !G ) {
    perror("gfshare_ctx_init_enc");
    return 1;
  }
  while( !feof(inputfile) ) {
    unsigned int bytes_read = fread( buffer, 1, BUFFER_SIZE, inputfile );
    if( bytes_read == 0 ) break;
    gfshare_ctx_enc_setsecret( G, buffer );
    for( i = 0; i < sharecount; ++i ) {
      unsigned int bytes_written;
      gfshare_ctx_enc_getshare( G, i, buffer );
      bytes_written = fwrite( buffer, 1, bytes_read, outputfiles[i] );
      if( bytes_read != bytes_written ) {
        perror(outputfilenames[i]);
        gfshare_ctx_free( G );
        return 1;
      }
    }
  }
  gfshare_ctx_free( G );
  fclose(inputfile);
  for( i = 0; i < sharecount; ++i ) {
    fclose(outputfiles[i]);
  }
  return 0;
}

#define OPTSTRING "n:m:hv"
int
main( int argc, char **argv )
{
  unsigned int sharecount = DEFAULT_SHARECOUNT;
  unsigned int threshold = DEFAULT_THRESHOLD;
  char *inputfile;
  char *outputstem;
  char *endptr;
  int optnr;
  
  progname = argv[0];
  srandom( time(NULL) );

  if (access("/dev/urandom", R_OK) == 0) {
    gfshare_fill_rand = gfsplit_fill_rand;
  } else {
    fprintf(stderr, "\
%s: Cannot access /dev/urandom, so using rand() instead (not secure!)\n\
", progname);
  }
  
  while( (optnr = getopt(argc, argv, OPTSTRING)) != -1 ) {
    switch( optnr ) {
    case 'v':
      fprintf( stdout, "%s", "\
gfsplit (" PACKAGE_STRING ")\n\
Written by Daniel Silverstone.\n\
\n\
Copyright 2006-2011 Daniel Silverstone <dsilvers@digital-scurf.org>\n\
This is free software; see the source for copying conditions.  There is NO\n\
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n\
" );
      return 0;
      break;
    case 'h':
      fprintf( stdout, "%s", "gfsplit (" PACKAGE_STRING ")\n");
      usage( stdout );
      return 0;
      break;
    case 'm':
      sharecount = strtoul( optarg, &endptr, 10 );
      if( *endptr != 0 || *optarg == 0 || 
          sharecount < 2 || sharecount > 255 ) {
        fprintf( stderr, "%s: Invalid argument to option -m\n", progname );
        usage( stderr );
        return 1;
      }
      break;
    case 'n':
      threshold = strtoul( optarg, &endptr, 10 );
      if( *endptr != 0 || *optarg == 0 || 
          threshold < 2 || threshold > sharecount) {
        fprintf( stderr, "%s: Invalid argument to option -n\n", progname );
        usage( stderr );
        return 1;
      }
      break;
    }
  }
  if( optind == argc || optind < (argc - 2) ) {
    fprintf( stderr, "%s: Bad argument count\n", progname );
    usage( stderr );
    return 1;
  }
  inputfile = argv[optind++];
  outputstem = (argc == optind)?inputfile:argv[optind++];
  return do_gfsplit( sharecount, threshold, inputfile, outputstem );
}
