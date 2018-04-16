import os
from ctypes import CDLL, c_char_p, c_int, c_ulonglong, POINTER, byref, create_string_buffer

lib = CDLL('%s/../lib/0/libpqcrypto.so' % os.path.dirname(os.path.abspath(__file__)))

class wrap_hash:
  def __init__(self,prefix,hlen):
    self.hlen = hlen
    self.c_hash = getattr(lib,'pqcrypto_hash_%s_impl' % prefix)
    self.c_hash.argtypes = [c_char_p,c_char_p,c_ulonglong]
    self.c_hash.restype = c_int

  def hash(self,m):
    mlen = c_ulonglong(len(m))
    m = create_string_buffer(m)
    h = create_string_buffer(self.hlen)
    if self.c_hash(h,m,mlen): raise Exception('hash failed')
    return h.raw

  __call__ = hash

class wrap_onetimeauth:
  def __init__(self,prefix,klen,alen):
    self.klen = klen
    self.alen = alen
    self.c_auth = getattr(lib,'pqcrypto_onetimeauth_%s_impl' % prefix)
    self.c_auth.argtypes = [c_char_p,c_char_p,c_ulonglong,c_char_p]
    self.c_auth.restype = c_int
    self.c_verify = getattr(lib,'pqcrypto_onetimeauth_%s_impl_verify' % prefix)
    self.c_verify.argtypes = [c_char_p,c_char_p,c_ulonglong,c_char_p]
    self.c_verify.restype = c_int

  def auth(self,m,k):
    assert len(k) == self.klen
    mlen = c_ulonglong(len(m))
    m = create_string_buffer(m)
    k = create_string_buffer(k)
    a = create_string_buffer(self.alen)
    if self.c_auth(a,m,mlen,k): raise Exception('auth failed')
    return a.raw

  def verify(self,a,m,k):
    assert len(k) == self.klen
    assert len(a) == self.alen
    mlen = c_ulonglong(len(m))
    m = create_string_buffer(m)
    k = create_string_buffer(k)
    a = create_string_buffer(a)
    if self.c_verify(a,m,mlen,k): raise Exception('verify failed')

  __call__ = auth

class wrap_stream:
  def __init__(self,prefix,klen,nlen):
    self.klen = klen
    self.nlen = nlen
    self.c_stream = getattr(lib,'pqcrypto_stream_%s_impl' % prefix)
    self.c_stream.argtypes = [c_char_p,c_ulonglong,c_char_p,c_char_p]
    self.c_stream.restype = c_int
    self.c_xor = getattr(lib,'pqcrypto_stream_%s_impl_xor' % prefix)
    self.c_xor.argtypes = [c_char_p,c_char_p,c_ulonglong,c_char_p,c_char_p]
    self.c_xor.restype = c_int

  def stream(self,mlen,n,k):
    assert len(n) == self.nlen
    assert len(k) == self.klen
    m = create_string_buffer(mlen)
    mlen = c_ulonglong(mlen)
    n = create_string_buffer(n)
    k = create_string_buffer(k)
    if self.c_stream(m,mlen,n,k): raise Exception('stream failed')
    return m.raw

  def xor(self,m,n,k):
    assert len(n) == self.nlen
    assert len(k) == self.klen
    mlen = c_ulonglong(len(m))
    c = create_string_buffer(len(m))
    m = create_string_buffer(m)
    n = create_string_buffer(n)
    k = create_string_buffer(k)
    # XXX: overlapping c with m doesn't seem to work with openssl aes
    if self.c_xor(c,m,mlen,n,k): raise Exception('xor failed')
    return c.raw

  __call__ = stream

class wrap_scalarmult:
  def __init__(self,prefix,pklen,sklen):
    self.pklen = pklen
    self.sklen = sklen
    self.c_base = getattr(lib,'pqcrypto_scalarmult_%s_impl_base' % prefix)
    self.c_base.argtypes = [c_char_p,c_char_p]
    self.c_base.restype = c_int
    self.c_scalarmult = getattr(lib,'pqcrypto_scalarmult_%s_impl' % prefix)
    self.c_scalarmult.argtypes = [c_char_p,c_char_p,c_char_p]
    self.c_scalarmult.restype = c_int

  def base(self,sk):
    assert len(sk) == self.sklen
    sk = create_string_buffer(sk)
    out = create_string_buffer(self.pklen)
    if self.c_base(out,sk): raise Exception('scalarmult_base failed')
    return out.raw

  def scalarmult(self,sk,pk):
    assert len(pk) == self.pklen
    assert len(sk) == self.sklen
    pk = create_string_buffer(pk)
    sk = create_string_buffer(sk)
    out = create_string_buffer(self.pklen)
    if self.c_scalarmult(out,sk,pk): raise Exception('scalarmult failed')
    return out.raw

  __call__ = scalarmult

class wrap_sign:
  def __init__(self,prefix,pklen,sklen,slen):
    self.pklen = pklen
    self.sklen = sklen
    self.slen = slen
    self.c_keypair = getattr(lib,'pqcrypto_sign_%s_impl_keypair' % prefix)
    self.c_keypair.argtypes = [c_char_p,c_char_p]
    self.c_keypair.restype = c_int
    self.c_sign = getattr(lib,'pqcrypto_sign_%s_impl' % prefix)
    self.c_sign.argtypes = [c_char_p,POINTER(c_ulonglong),c_char_p,c_ulonglong,c_char_p]
    self.c_sign.restype = c_int
    self.c_open = getattr(lib,'pqcrypto_sign_%s_impl_open' % prefix)
    self.c_open.argtypes = [c_char_p,POINTER(c_ulonglong),c_char_p,c_ulonglong,c_char_p]
    self.c_open.restype = c_int

  def keypair(self):
    pk = create_string_buffer(self.pklen)
    sk = create_string_buffer(self.sklen)
    if self.c_keypair(pk,sk): raise Exception('keypair failed')
    return pk.raw,sk.raw

  def sign(self,m,sk):
    assert len(sk) == self.sklen
    mlen = c_ulonglong(len(m))
    smlen = c_ulonglong(0)
    sm = create_string_buffer(len(m) + self.slen)
    m = create_string_buffer(m)
    sk = create_string_buffer(sk)
    if self.c_sign(sm,byref(smlen),m,mlen,sk): raise Exception('sign failed')
    return sm.raw[:smlen.value]

  def open(self,sm,pk):
    assert len(pk) == self.pklen
    smlen = c_ulonglong(len(sm))
    m = create_string_buffer(len(sm))
    mlen = c_ulonglong(0)
    pk = create_string_buffer(pk)
    if self.c_open(m,byref(mlen),sm,smlen,pk): raise Exception('open failed')
    return m.raw[:mlen.value]

  __call__ = keypair

class wrap_kem:
  def __init__(self,prefix,pklen,sklen,clen,klen):
    self.pklen = pklen
    self.sklen = sklen
    self.clen = clen
    self.klen = klen
    self.c_keypair = getattr(lib,'pqcrypto_kem_%s_impl_keypair' % prefix)
    self.c_keypair.argtypes = [c_char_p,c_char_p]
    self.c_keypair.restype = c_int
    self.c_enc = getattr(lib,'pqcrypto_kem_%s_impl_enc' % prefix)
    self.c_enc.argtypes = [c_char_p,c_char_p,c_char_p]
    self.c_enc.restype = c_int
    self.c_dec = getattr(lib,'pqcrypto_kem_%s_impl_dec' % prefix)
    self.c_dec.argtypes = [c_char_p,c_char_p,c_char_p]
    self.c_dec.restype = c_int

  def keypair(self):
    pk = create_string_buffer(self.pklen)
    sk = create_string_buffer(self.sklen)
    if self.c_keypair(pk,sk): raise Exception('keypair failed')
    return pk.raw,sk.raw

  def enc(self,pk):
    assert len(pk) == self.pklen
    c = create_string_buffer(self.clen)
    k = create_string_buffer(self.klen)
    pk = create_string_buffer(pk)
    if self.c_enc(c,k,pk): raise Exception('enc failed')
    return c.raw,k.raw

  def dec(self,c,sk):
    assert len(c) == self.clen
    assert len(sk) == self.sklen
    k = create_string_buffer(self.klen)
    c = create_string_buffer(c)
    sk = create_string_buffer(sk)
    if self.c_dec(k,c,sk): raise Exception('dec failed')
    return k.raw

  __call__ = keypair

class wrap_randombytes:
  def __init__(self):
    self.c_randombytes = getattr(lib,'pqrandombytes_impl')
    self.c_randombytes.argtypes = [c_char_p,c_ulonglong]
    self.c_randombytes.restype = None

  def __call__(self,rlen):
    r = create_string_buffer(rlen)
    rlen = c_ulonglong(rlen)
    self.c_randombytes(r,rlen)
    return r.raw

randombytes = wrap_randombytes()

class struct:
  pass

x = []
%crypto_hash: x += [('PRIMITIVE',CRYPTO_BYTES)]
hash = struct()
for p,hlen in x:
  try:
    setattr(hash,p,wrap_hash(p,hlen))
  except:
    pass

x = []
%crypto_onetimeauth: x += [('PRIMITIVE',CRYPTO_KEYBYTES,CRYPTO_BYTES)]
onetimeauth = struct()
for p,klen,alen in x:
  try:
    setattr(onetimeauth,p,wrap_onetimeauth(p,klen,alen))
  except:
    pass

x = []
%crypto_stream: x += [('PRIMITIVE',CRYPTO_KEYBYTES,CRYPTO_NONCEBYTES)]
stream = struct()
for p,klen,nlen in x:
  try:
    setattr(stream,p,wrap_stream(p,klen,nlen))
  except:
    pass

x = []
%crypto_scalarmult: x += [('PRIMITIVE',CRYPTO_BYTES,CRYPTO_SCALARBYTES)]
scalarmult = struct()
for p,pklen,sklen in x:
  try:
    setattr(scalarmult,p,wrap_scalarmult(p,pklen,sklen))
  except:
    pass

x = []
%crypto_sign: x += [('PRIMITIVE',CRYPTO_PUBLICKEYBYTES,CRYPTO_SECRETKEYBYTES,CRYPTO_BYTES)]
sign = struct()
for p,pklen,sklen,slen in x:
  try:
    setattr(sign,p,wrap_sign(p,pklen,sklen,slen))
  except:
    pass

x = []
%crypto_kem: x += [('PRIMITIVE',CRYPTO_PUBLICKEYBYTES,CRYPTO_SECRETKEYBYTES,CRYPTO_CIPHERTEXTBYTES,CRYPTO_BYTES)]
kem = struct()
for p,pklen,sklen,clen,klen in x:
  try:
    setattr(kem,p,wrap_kem(p,pklen,sklen,clen,klen))
  except:
    pass
