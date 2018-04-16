#ifndef LUOV_H
#define LUOV_H

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "parameters.h"
#include "Bitcontainer.h"
#include "LinearAlgebra.h"
#include "randombytes.h"
#include "buffer.h"
#include "keccakrng.h"
#include "apiorig.h"
#include "intermediateValues.h"

typedef struct {
	unsigned char privateseed[32];
	bitcontainer T[VINEGAR_VARS+1];
} SecretKey;

typedef struct {
	unsigned char publicseed[32];
	bitcontainer *Q2;
} PublicKey;

typedef struct {
	FELT s[VARS+1];
} Signature;

void generateKeyPair(PublicKey *pk, SecretKey *sk);
Signature signDocument(SecretKey sk, const unsigned char* document, uint64_t len);
int verify(PublicKey* pk, Signature* signature, unsigned char* document, unsigned long long *len);

void serialize_SecretKey(writer *Buff, SecretKey *sk);
void deserialize_SecretKey(reader *Buff, SecretKey *sk);
void destroy_SecretKey(SecretKey *sk);

void serialize_PublicKey(writer* Buff, PublicKey* pk);
void deserialize_PublicKey(reader* Buff, PublicKey* pk);
void destroy_PublicKey(PublicKey *pk);

void serialize_signature(writer *W, Signature *S);
void deserialize_signature(reader *R, Signature *S);
void destroy_signature(Signature *S);

#endif 
