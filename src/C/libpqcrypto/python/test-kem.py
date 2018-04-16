import pqcrypto
kem = pqcrypto.kem.newhope1024cca
pk,sk = kem.keypair()
c,k = kem.enc(pk)
assert k == kem.dec(c,sk)
