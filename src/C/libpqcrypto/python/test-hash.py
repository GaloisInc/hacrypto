import pqcrypto
m = pqcrypto.randombytes(1234567)
h = pqcrypto.hash.sha512(m)

import hashlib
H = hashlib.sha512()
H.update(m)
assert H.digest() == h
