import pqcrypto
cipher = pqcrypto.stream.aes256ctr

k = pqcrypto.randombytes(cipher.klen)
n = pqcrypto.randombytes(cipher.nlen)
m = pqcrypto.randombytes(1234567)
c = cipher.xor(m,n,k)
assert m == cipher.xor(c,n,k)

from Crypto.Cipher import AES
from Crypto.Util import Counter
import binascii

nint = int(binascii.hexlify(n),16)
s = AES.new(k,AES.MODE_CTR,counter=Counter.new(128,initial_value=nint))
assert s.encrypt(m) == c
