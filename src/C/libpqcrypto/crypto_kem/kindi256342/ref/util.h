#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include "randombytes.h"

#include "params.h"

int cmp_llu(const void*, const void*);
unsigned long long median(unsigned long long*, size_t);
unsigned long long average(unsigned long long*, size_t);

void print_timings(double avg_enc, double avg_dec, unsigned long long *t_enc,
	unsigned long long *t_dec, size_t tlen);
void print_results(const char *s, unsigned long long *t, size_t tlen);

void print_parameters();
void print_char_hex(const char *s, const unsigned char *c, int len);

#endif
