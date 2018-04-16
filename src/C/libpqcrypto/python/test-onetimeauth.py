import pqcrypto
mac = pqcrypto.onetimeauth.poly1305
k = pqcrypto.randombytes(mac.klen)
m = pqcrypto.randombytes(1234567)
a = mac.auth(m,k)
mac.verify(a,m,k)
