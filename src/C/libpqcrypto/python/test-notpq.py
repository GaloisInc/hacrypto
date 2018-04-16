import pqcrypto

sm = pqcrypto.scalarmult.x25519notpq

a = pqcrypto.randombytes(sm.sklen)
A = sm.base(a)

b = pqcrypto.randombytes(sm.sklen)
B = sm.base(b)

aB = sm.scalarmult(a,B)
bA = sm(b,A)

assert aB == bA
