#include "crypto_sign.h"
#include "LUOV.h"

#ifdef KAT
	#define printIntermediateValue(A) printf(A)
#else
	#define printIntermediateValue(A) 
#endif

/*
	Generates a new keypair

	pk : char array that receives the new public key
	sk : char array that receives the new secret key
*/
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk) 
{
	writer W;
	PublicKey PK;
	SecretKey SK;
	printIntermediateValue("--- Start keygen ---\n");

	// Generate key pair
	generateKeyPair(&PK , &SK);

	// Write secret key to sk
	W = newWriter(sk);
	serialize_SecretKey(&W, &SK);

	// Write public key to pk
	W = newWriter(pk);
	serialize_PublicKey(&W, &PK);

	// Free up memory
	destroy_SecretKey(&SK);
	destroy_PublicKey(&PK);

	printIntermediateValue("--- End keygen ---\n");
	return 0;
}

/*
	Signs a document

	sm : char array that receives the signed message
	smlen : receives the length of the signed message
	m  : char array that contains the original message
	mlen : length of original message
	sk : char array containing the secret key
*/
int crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m, unsigned long long mlen, const unsigned char *sk)
{
	SecretKey skey;
	reader R = newReader(sk);
	writer W = newWriter(sm);
	Signature signature;
	printIntermediateValue("--- Start signing ---\n");

	// Read the secret key
	deserialize_SecretKey(&R, &skey);

	// If not the entire mesage can be recovered from a signature, we copy the first part to sm.
	if( mlen > RECOVERED_PART_MESSAGE ){
		reader DR = newReader(m);
		transcribe(&W,&DR,mlen - RECOVERED_PART_MESSAGE);
	}

	// Produce a signature
	signature = signDocument(skey, m, mlen);

	// Write the signature to sm
	serialize_signature(&W, &signature);
	// Fill the last byte with zeros
	serialize_uint64_t(&W, 0, (8 - W.bitsUsed) % 8);
	*smlen = W.next;

	// Free up memory
	destroy_signature(&signature);
	destroy_SecretKey(&skey);

	printIntermediateValue("--- End signing ---\n");

	return 0;
}

/*
	Verify a signature

	m :  char array that receives the original message
	mlen : receives the length of the original message
	sm : char array that contains the signed message
	smlen : the length of the signed message
	pk : char array containing the public key

	returns : 0 if the signature is accepted, -1 otherwise
*/
int crypto_sign_open(unsigned char *m, unsigned long long *mlen, const unsigned char *sm, unsigned long long smlen, const unsigned char *pk)
{
	int valid;
	reader PKR = newReader(pk);
	reader SMR = newReader(sm);
	writer W   = newWriter(m);
	PublicKey pkey;
	Signature signature;

	printIntermediateValue("--- Start verifying ---\n");

	// Read public key
	deserialize_PublicKey(&PKR, &pkey);

	// Copy the part of the message that cannot be recovered from the signature into m
	transcribe(&W,&SMR,smlen - CRYPTO_BYTES);
	*mlen = smlen - CRYPTO_BYTES;

	// Read signature
	deserialize_signature(&SMR, &signature);

	// Verify signature
	valid = verify(&pkey, &signature, m, mlen);


	// Free up memory
	destroy_signature(&signature);
	destroy_PublicKey(&pkey);

	printIntermediateValue("--- End verifying ---\n");

	return valid;
}
