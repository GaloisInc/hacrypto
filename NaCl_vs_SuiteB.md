| Type | Suite B | NaCl | 
-------------------
| [Hash](http://en.wikipedia.org/wiki/Hash_function) | [SHA256/384](http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf) | [SHA256/512](http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf) | 
| [Digital Signature](http://en.wikipedia.org/wiki/Digital_Signature_Algorithm)  | [ECDSA Curve P-256/384](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf) | __ |
| [Message Authentication](http://en.wikipedia.org/wiki/Message_authentication_code) (symmetric) | __ | [HMAC_SHA](http://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf), [POLY1305-AES](http://cr.yp.to/mac.html) (one time authentication) | 
| [Key Exchange (ECDH)](http://en.wikipedia.org/wiki/Elliptic_curve_Diffie%E2%80%93Hellman) | [Curve P-256/384](http://csrc.nist.gov/groups/ST/toolkit/documents/SP800-56Arev1_3-8-07.pdf) | [Curve25519](http://cr.yp.to/ecdh.html) |
| [Encryption (symmetric)](http://en.wikipedia.org/wiki/Symmetric-key_algorithm) | [AES 128/256](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf) | [SALSA20](http://cr.yp.to/salsa20.html) (default) / [AES 128](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf) | 
