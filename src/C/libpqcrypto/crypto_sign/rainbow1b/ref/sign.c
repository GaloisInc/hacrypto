#include "crypto_sign.h"

#include <stdlib.h>
#include <string.h>

#include "rainbow_config.h"
#include "rainbow.h"

#include "hash_utils.h"

#include "gf31_convert.h"


int
crypto_sign_keypair(unsigned char *pk, unsigned char *sk)
{
	unsigned char * _pk = (unsigned char *) malloc(_PUB_KEY_LEN);
	if( NULL == _pk ) return -1;
	unsigned char * _sk = (unsigned char *) malloc(_SEC_KEY_LEN);
	if( NULL == _sk ) return -1;

	rainbow_genkey(_pk, (rainbow_key *)_sk);

	gf31_quick_pack( pk , _pk , _PUB_KEY_LEN );
	pk[_SALT_PUB_KEY_LEN-1] = _SALT_BYTE;
	gf31_quick_pack( sk , _sk , _SEC_KEY_LEN );
	sk[_SALT_SEC_KEY_LEN-1] = _SALT_BYTE;

	free( _pk );
	free( _sk );

	return 0;
}


int
crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m, unsigned long long mlen, const unsigned char *sk)
{
	unsigned char digest[_HASH_LEN];

	sha2_chain_msg( digest , _HASH_LEN , m , mlen );

	memmove( sm , m , mlen );
	smlen[0] = mlen + _SALT_SIGNATURE_BYTE;

	unsigned char * _sk = (unsigned char *)malloc(_SEC_KEY_LEN);
	if( NULL == _sk ) return -1;
	gf31_quick_unpack( _sk , sk , _SEC_KEY_LEN );

	int r = rainbow_sign( sm + mlen , (const rainbow_key *)_sk , digest );

	free( _sk );
	return r;
}






int
crypto_sign_open(unsigned char *m, unsigned long long *mlen,const unsigned char *sm, unsigned long long smlen,const unsigned char *pk)
{
	if( _SALT_SIGNATURE_BYTE > smlen ) return -1;

	unsigned char * _pk = (unsigned char *)malloc(_PUB_KEY_LEN);
	if( NULL == _pk ) return -1;
	gf31_quick_unpack( _pk , pk , _PUB_KEY_LEN );

	memmove( m , sm , smlen-_SALT_SIGNATURE_BYTE );
	mlen[0] = smlen-_SALT_SIGNATURE_BYTE;

	unsigned char digest[_HASH_LEN];
	sha2_chain_msg( digest , _HASH_LEN , m , *mlen );

	int r = rainbow_verify( digest , sm + mlen[0] , _pk );

	free( _pk );
	return r;
}

