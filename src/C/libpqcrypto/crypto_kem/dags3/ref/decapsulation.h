
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdint.h>
#include <assert.h>
#include <libkeccak.a.headers/KangarooTwelve.h>

#include "decoding.h"

#include "fichier.h"
#include "util.h"
#define cus_len 4 // I random pick this number to fullfill parameter

/**
 * @brief Method to perform the decapsulation using secret key
 * @param ss secret shared
 * @param ct
 * @param sk secret key to extract the key
 */
int decapsulation(unsigned char *ss, const unsigned char *ct,
                  const unsigned char *sk);
