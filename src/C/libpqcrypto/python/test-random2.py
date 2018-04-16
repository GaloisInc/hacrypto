import pqcrypto

for x in [pqcrypto.sign,pqcrypto.kem]:
  for p in dir(x):
    if p.startswith('_'): continue
    print(p)
    y = getattr(x,p)
    n = 100
    assert len(set(y.keypair() for i in range(n))) == n
