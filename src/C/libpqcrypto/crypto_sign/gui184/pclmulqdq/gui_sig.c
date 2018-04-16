
#include "gui_config.h"

#include "gui.h"

#include "hash_utils.h"

#include "prng_utils.h"

#include "assert.h"

#include "mpkc.h"


void pack_tails( uint8_t * r , const uint8_t s_tail[_K][_TAIL_BYTE] )
{
	memcpy( r , s_tail[_K-1] , _TAIL_BYTE );
	if( 1 >= _K ) return;
	r += _TAIL_BYTE;
	for(unsigned i=1;i<_K;i++) {
		unsigned remains = ((_TAIL)*i%8);
		if( 0 == remains ) {
			memcpy( r , s_tail[_K-1-i] , _TAIL_BYTE );
			r += _TAIL_BYTE;
			continue;
		}

		uint64_t temp1 = 0;
		uint64_t temp2 = 0;

		memcpy( &temp1 , s_tail[_K-1-i] , _TAIL_BYTE );
		r -= 1;
		temp2 = r[0];
		temp1 <<= remains;
		temp2 |= temp1;

#if 8 <= _TAIL_BYTE
                memcpy( r , &temp2 , _TAIL_BYTE );
#else
                memcpy( r , &temp2 , _TAIL_BYTE + 1 );
#endif
                r += ((_TAIL+remains)+7)/8;
	}
}


void split_tails( uint8_t s_tail[_K][_TAIL_BYTE] , const uint8_t * a )
{
	memcpy( s_tail[_K-1] , a , _TAIL_BYTE );
	if( 1 >= _K ) return;
	a += _TAIL_BYTE;
	for(unsigned i=1;i<_K;i++) {
		unsigned remains = ((_TAIL)*i%8);
		if( 0 == remains ) {
			memcpy( s_tail[_K-1-i] , a , _TAIL_BYTE );
			a += _TAIL_BYTE;
			continue;
		}
		assert( 4 == remains );

		uint64_t temp1 = 0;
		memcpy( &temp1 , a-1 , _TAIL_BYTE );
		a += _TAIL_BYTE-1;
		temp1 >>= remains;
		memcpy( s_tail[_K-1-i] , &temp1 , _TAIL_BYTE );
	}
}


/// algorithm 2
unsigned gui_sign( uint8_t * signature , const uint8_t * sec_key , const uint8_t * digest )
{
	uint8_t sha2_digest[_HASH_LEN] __attribute__((aligned(32)));
	memcpy( sha2_digest , digest , _HASH_LEN );
	unsigned hash_counter = 0;
	uint8_t dd[_PUB_M_BYTE] __attribute__((aligned(32)));
	uint8_t ss[_PUB_N_BYTE] __attribute__((aligned(32))) = {0};
	uint8_t s_tail[_K][ _TAIL_BYTE ];

	unsigned r = 1;
	for(unsigned i=0;i<_K;i++) {
		sha2_chain_byte( dd , _PUB_M_BYTE , &hash_counter , sha2_digest );
		gf256v_add( dd , ss , _PUB_M_BYTE );
		r &= gui_secmap( ss , (const gui_key *) sec_key , dd );

		memcpy( s_tail[i] , ss + _PUB_M_BYTE , _TAIL_BYTE );
	}
	memcpy( signature , ss , _PUB_M_BYTE );
	pack_tails( signature + _PUB_M_BYTE , (const uint8_t (*)[_TAIL_BYTE])s_tail );

	return r;
}


/// algorithm 4
unsigned gui_verify( const uint8_t * pub_key , const uint8_t * signature , const uint8_t * digest )
{
	uint8_t sha2_digest[_HASH_LEN] __attribute__((aligned(32)));
	memcpy( sha2_digest , digest , _HASH_LEN );
	unsigned hash_counter = 0;
	uint8_t dd[_K][((_PUB_M_BYTE+31)/32)*32]  __attribute__((aligned(32)));
	for(unsigned i=0;i<_K;i++) {
		sha2_chain_byte( dd[i] , _PUB_M_BYTE , &hash_counter , sha2_digest );
	}
	uint8_t s_tails[_K][ _TAIL_BYTE ];
	split_tails( s_tails , signature + _PUB_M_BYTE );

	uint8_t temp_sig[_SIGNATURE_BYTE] __attribute__((aligned(32)));
	uint8_t temp_pub[_PUB_M_BYTE] __attribute__((aligned(32)));
	memcpy( temp_sig , signature , _PUB_M_BYTE );
	for(int i=_K-1;i>=0;i--) {
		memcpy( temp_sig + _PUB_M_BYTE , s_tails[i] , _TAIL_BYTE );
		gui_pubmap( temp_pub , pub_key , temp_sig );
		gf256v_add( temp_pub , dd[i] , _PUB_M_BYTE );
		memcpy( temp_sig , temp_pub , _PUB_M_BYTE );
	}
	return gf256v_is_zero( temp_sig , _PUB_M_BYTE );
}



static inline
unsigned _gui_sign_salt_core( uint8_t * signature , const uint8_t * sec_key , const uint8_t * digest , const uint8_t * minus , const uint8_t * vinegar )
{
	uint8_t dd[_PUB_M_BYTE] __attribute__((aligned(32)));
	uint8_t ss[_PUB_N_BYTE] __attribute__((aligned(32))) = {0};
	uint8_t s_tail[_K][ _TAIL_BYTE ];

	unsigned r = 1;
	for(unsigned i=0;i<_K;i++) {
		memcpy( dd , digest , _PUB_M_BYTE );
		digest += _PUB_M_BYTE;
		gf256v_add( dd , ss , _PUB_M_BYTE );

		r = InvHFEv_( ss , (const gui_key *) sec_key , dd , minus , vinegar );
		if( 0 == r ) return 0;

		memcpy( s_tail[i] , ss + _PUB_M_BYTE , _TAIL_BYTE );
	}
	memcpy( signature , ss , _PUB_M_BYTE );
	pack_tails( signature + _PUB_M_BYTE , (const uint8_t (*)[_TAIL_BYTE])s_tail );

	return 1;
}

/// algorithm 6
unsigned gui_sign_salt( uint8_t * signature , const uint8_t * sec_key , const uint8_t * _digest )
{
	uint8_t digest_salt[_HASH_LEN + _SALT_BYTE ] __attribute__((aligned(32))) = {0};
	memcpy( digest_salt , _digest , _HASH_LEN );
	uint8_t * salt = digest_salt + _HASH_LEN;

	uint8_t minus[_MINUS_BYTE] __attribute__((aligned(32)));
	uint8_t vinegar[_VINEGAR_BYTE] __attribute__((aligned(32)));
	prng_bytes( minus , _MINUS_BYTE );
	prng_bytes( vinegar , _VINEGAR_BYTE );


	uint8_t digest[(_PUB_M_BYTE)*_K] __attribute__((aligned(32)));
	unsigned succ = 0;
	unsigned time = 0;
	do {
		prng_bytes( salt , _SALT_BYTE );
		sha2_chain_msg( digest , (_PUB_M_BYTE)*_K , digest_salt , _HASH_LEN + _SALT_BYTE );

		succ = _gui_sign_salt_core( signature , sec_key , digest , minus , vinegar );
		if( 1024 < time ) break;
	} while(! succ );

	memcpy( signature + _SIGNATURE_BYTE , salt , _SALT_BYTE );

	return succ;
}

/// algorithm 8
unsigned gui_verify_salt( const uint8_t * pub_key , const uint8_t * signature , const uint8_t * _digest )
{
	uint8_t digest_salt[_HASH_LEN + _SALT_BYTE ] = {0};
	memcpy( digest_salt , _digest , _HASH_LEN );
	memcpy( digest_salt + _HASH_LEN , signature + _SIGNATURE_BYTE , _SALT_BYTE );

	uint8_t digest[_HASH_LEN];
	sha2_chain_msg( digest , _HASH_LEN , digest_salt , _HASH_LEN + _SALT_BYTE );

	return gui_verify( pub_key , signature , digest );
}




