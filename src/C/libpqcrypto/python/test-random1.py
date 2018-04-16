import pqcrypto
kem = pqcrypto.kem.newhope1024cca
n = 10000
assert len(set(kem.keypair() for i in range(n))) == n
