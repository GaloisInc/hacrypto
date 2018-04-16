#include "gen_randomness.h"


void shake4x_hash(uint8_t *out, unsigned long long outlen,
		 uint8_t *in, unsigned long long inlen) {


#if KINDI_KEM_SHAKEMODE == 128
	shake128(out, outlen, in, inlen);
#elif KINDI_KEM_SHAKEMODE == 256
	shake256(out, outlen, in, inlen);
#endif


}

//H
void kindi_crypto_stream(uint8_t *out, unsigned long long outlen,
		const uint8_t *in, unsigned long long inlen) {

#if KINDI_KEM_SHAKEMODE == 128
	shake128(out, outlen, in, inlen);
#elif KINDI_KEM_SHAKEMODE == 256
	shake256(out, outlen, in, inlen);
#endif

}

//H'
void kindi_crypto_stream_2(uint8_t *out, unsigned long long outlen,
		const uint8_t *in, unsigned long long inlen) {


#if KINDI_KEM_SHAKEMODE == 128
	shake128(out, outlen, in, inlen);
#elif KINDI_KEM_SHAKEMODE == 256
	shake256(out, outlen, in, inlen);
#endif

}

#define BUFFERLEN (KINDI_KEM_BYTESLOGRSECP1 * KINDI_KEM_L * KINDI_KEM_N + KINDI_KEM_MESSAGEBYTES)

void gen_randomness(poly_d *s, uint8_t *u, uint8_t *s1) {
#if KINDI_KEM_S1BITS == 1
	int i, a, x;

	uint8_t *buffer = malloc(BUFFERLEN);
	kindi_crypto_stream(buffer, BUFFERLEN, s1, KINDI_KEM_S1SIZE);

	int tmp, pos = 0;

	// set s1=LSB in s1_bar
	for (i = 0; i < KINDI_KEM_S1SIZE; i++)
		for (a = 0; a < 8; a++)
			s[0][a + 8 * i] = (s1[i] >> a) & 1;

	// set missing bits in s1_bar
	for (a = 0; a < KINDI_KEM_N; a++) {
		tmp = 0;
		for (x = 0; x < KINDI_KEM_BYTESLOGRSECP1; x++)
			tmp += (int) buffer[pos++] << x * 8;

		tmp &= KINDI_KEM_RSEC - 1;
		tmp = tmp << 1;
		s[0][a] = s[0][a] + tmp - KINDI_KEM_RSEC;
	}

	// set bits for s_2,..., s_L
	for (i = 1; i < KINDI_KEM_L; i++) {
		for (a = 0; a < KINDI_KEM_N; a++) {
			tmp = 0;
			for (x = 0; x < KINDI_KEM_BYTESLOGRSECP1; x++)
				tmp += (int) buffer[pos++] << x * 8;

			s[i][a] = (tmp & ((KINDI_KEM_RSEC << 1) - 1)) - KINDI_KEM_RSEC;
		}
	}

	memcpy(u, buffer + pos, KINDI_KEM_MESSAGEBYTES);

	free(buffer);
#elif KINDI_KEM_S1BITS == 2
	int i, a, x;

		uint8_t *buffer = malloc(BUFFERLEN);
		kindi_crypto_stream(buffer, BUFFERLEN, s1, KINDI_KEM_S1SIZE);

		int tmp, pos = 0;

		// set s1=LSB in s1_bar
		for (i = 0; i < KINDI_KEM_S1SIZE; i++)
			for (a = 0; a < 4; a++)
				s[0][a + 4 * i] = (s1[i] >> (2*a)) & 0x03;

		// set missing bits in s1_bar
		for (a = 0; a < KINDI_KEM_N; a++) {
			tmp = 0;
			for (x = 0; x < KINDI_KEM_BYTESLOGRSECP1; x++)
				tmp += (int) buffer[pos++] << x * 8;

			tmp &= (KINDI_KEM_RSEC>>1) - 1;
			tmp = tmp << 2;
			s[0][a] = s[0][a] + tmp - KINDI_KEM_RSEC;
		}

		// set bits for s_2,..., s_L
		for (i = 1; i < KINDI_KEM_L; i++) {
			for (a = 0; a < KINDI_KEM_N; a++) {
				tmp = 0;
				for (x = 0; x < KINDI_KEM_BYTESLOGRSECP1; x++)
					tmp += (int) buffer[pos++] << x * 8;

				s[i][a] = (tmp & ((KINDI_KEM_RSEC << 1) - 1)) - KINDI_KEM_RSEC;
			}
		}

		memcpy(u, buffer + pos, KINDI_KEM_MESSAGEBYTES);

		free(buffer);

#endif
}

