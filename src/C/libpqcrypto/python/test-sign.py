import pqcrypto
sig = pqcrypto.sign.mqdss64
pk,sk = sig.keypair()
m = b"hello world"
sm = sig.sign(m,sk)
assert m == sig.open(sm,pk)
