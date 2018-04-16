#include <string.h>
#include <stdlib.h>
#include "freadall.h"

#define MAX 4611686018427387904ULL

/*
 * speedup possibilities:
 * fread() instead of a sequence of getchar()
 * lower-level read(), skipping stdio
 * replace this function with suitable mmap in common file case
 */

unsigned char *freadall(unsigned long long *len,unsigned long long padbefore,unsigned long long padafter,FILE *fi)
{
  unsigned char *buf = 0;
  unsigned char *newbuf;
  unsigned long long bufalloc = 0;
  unsigned long long pos = padbefore;
  int ch;

  if (padbefore >= MAX) goto nomem;
  if (padafter >= MAX) goto nomem;
  if (padbefore + padafter >= MAX) goto nomem;

  for (;;) {
    if (bufalloc <= pos + padafter) {
      while (bufalloc <= pos + padafter) {
        bufalloc = bufalloc * 2 + 1;
        if (bufalloc != (unsigned long long) (size_t) bufalloc) goto nomem;
        if (bufalloc >= MAX) goto nomem;
      }
      newbuf = realloc(buf,bufalloc);
      if (!newbuf) goto nomem;
      buf = newbuf;
    }
    /* buf is allocated, and bufalloc >= pos + padafter */
    ch = getchar();
    if (ch == EOF) {
      if (padbefore) memset(buf,0,padbefore);
      if (bufalloc > pos) memset(buf + pos,0,bufalloc - pos);
      *len = pos - padbefore;
      return buf;
    }
    buf[pos++] = ch;
  }

  nomem:
  free(buf);
  return 0;
}
