import os
import sys

import pqcrypto
kem = pqcrypto.kem.mceliece8192128
hash = pqcrypto.hash.shake256
enc = pqcrypto.stream.salsa20
auth = pqcrypto.onetimeauth.poly1305

with os.fdopen(0,"rb") as f: c = f.read()
with os.fdopen(8,"rb") as f: sk = f.read()
k = kem.dec(c[-kem.clen:],sk)
c = c[:-kem.clen]

h = hash(k)
kenc,h = h[:enc.klen],h[enc.klen:]
kauth = h[:auth.klen]

a,c = c[:auth.alen],c[auth.alen:]
auth.verify(a,c,kauth)

n = b"\0"*enc.nlen
m = enc.xor(c,n,kenc)
with os.fdopen(1,"wb") as f: f.write(m)
