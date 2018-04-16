#include "crypto_sign.h"

#include <stdlib.h>
#include <string.h>

#include "gui_config.h"
#include "gui.h"

#include "gui_sig.h"
#include "hash_utils.h"

int
crypto_sign_keypair(unsigned char *pk, unsigned char *sk)
{
	gui_genkey( pk, (gui_key *) sk);

	pk[_SALT_PUB_KEY_LEN-1] = _SALT_BYTE;
	sk[_SALT_SEC_KEY_LEN-1] = _SALT_BYTE;

	return 0;
}


int
crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m, unsigned long long mlen, const unsigned char *sk)
{
	unsigned char digest[_HASH_LEN];

	sha2_chain_msg( digest , _HASH_LEN , m , mlen );

	memmove( sm , m , mlen );
	smlen[0] = mlen + _SALT_SIGNATURE_BYTE;

	unsigned r = gui_sign_salt( sm + mlen , sk , digest );

	if( r ) return 0;
	return -1;
}






int
crypto_sign_open(unsigned char *m, unsigned long long *mlen,const unsigned char *sm, unsigned long long smlen,const unsigned char *pk)
{
	unsigned char pkcopy[crypto_sign_PUBLICKEYBYTES];
	memcpy(pkcopy,pk,crypto_sign_PUBLICKEYBYTES);

	if( _SALT_SIGNATURE_BYTE > smlen ) return -1;
	memmove( m , sm , smlen-_SALT_SIGNATURE_BYTE );
	mlen[0] = smlen-_SALT_SIGNATURE_BYTE;

	unsigned char digest[_HASH_LEN];
	sha2_chain_msg( digest , _HASH_LEN , m , *mlen );

	unsigned r = gui_verify_salt( pkcopy , sm + mlen[0] , digest );

	if( r ) return 0;
	return -1;
}

