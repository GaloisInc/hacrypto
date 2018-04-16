#!/usr/bin/env python

import sys

operation = sys.argv[1]

var = []
function = []
loop = []
expected = '0'
unexpected = 'nonzero'
extrabytes = '0'

if operation == 'core':
  loop = 512
  var = [['h','OUTPUTBYTES'],['n','INPUTBYTES'],['k','KEYBYTES'],['c','CONSTBYTES']]
  function = [['',['h'],[],['n','k','c']]]

if operation == 'hashblocks':
  loop = 4096
  var = [['h','STATEBYTES'],['m',0]]
  function = [['',[],['h'],['m','mlen']]]
  expected = 'mlen % crypto_hashblocks_BLOCKBYTES'
  unexpected = 'unexpected value'

if operation == 'hash':
  loop = 64
  var = [['h','BYTES'],['m',0]]
  function = [['',['h'],[],['m','mlen']]]

if operation == 'stream':
  loop = 512
  var = [['k','KEYBYTES'],['n','NONCEBYTES'],['m',0],['c',0],['s',0]]
  function = [['',['s'],[],['slen','n','k']],['_xor',['c'],[],['m','mlen','n','k']]]

if operation in ['auth','onetimeauth']:
  loop = 4096
  var = [['h','BYTES'],['m',0],['k','KEYBYTES']]
  function = [['',['h'],[],['m','mlen','k']],['_verify',[],[],['h','m','mlen','k']]]

if operation == 'secretbox':
  loop = 4096
  var = [['k','KEYBYTES']]
  var += [['n','NONCEBYTES']]
  var += [['m',0]] # original message
  var += [['c',0]] # boxed message
  var += [['t',0]] # opened message
  function = [['',['c'],[],['m','mlen','n','k']]]
  function += [['_open',['t'],[],['c','clen','n','k']]]

if operation == 'aead':
  loop = 64
  var = [['k','KEYBYTES']]
  var += [['s','NSECBYTES']]
  var += [['p','NPUBBYTES']]
  var += [['a',0]] # additional data
  var += [['m',0]] # original message
  var += [['c',0]] # boxed message
  var += [['t',0]] # opened message
  var += [['r','NSECBYTES']] # opened s
  function = [['_encrypt',['c','&clen'],[],['m','mlen','a','alen','s','p','k']]]
  function += [['_decrypt',['t','&tlen','r'],[],['c','clen','a','alen','p','k']]]
  extrabytes = 'crypto_aead_ABYTES'

if operation == 'rng':
  loop = 64
  var = [['k','KEYBYTES']]
  var += [['r','OUTPUTBYTES']]
  var += [['n','KEYBYTES']]
  function = [['',['r','n'],[],['k']]]

if operation == 'scalarmult':
  loop = 64
  var = [['a','SCALARBYTES']] # alice secret key
  var += [['b','SCALARBYTES']] # bob secret key
  var += [['c','BYTES']] # alice public key
  var += [['d','BYTES']] # bob public key
  var += [['e','BYTES']] # alice shared secret
  var += [['f','BYTES']] # bob shared secret
  function = [['_base',['c'],[],['a']]]
  function += [['_base',['d'],[],['b']]]
  function += [['',['e'],[],['a','d']]]
  function += [['',['f'],[],['b','c']]]

if operation == 'box':
  loop = 512
  var = [['a','SECRETKEYBYTES']] # alice secret key
  var += [['b','SECRETKEYBYTES']] # bob secret key
  var += [['y','PUBLICKEYBYTES']] # alice public key
  var += [['z','PUBLICKEYBYTES']] # bob public key
  var += [['e','BEFORENMBYTES']] # alice shared secret
  var += [['f','BEFORENMBYTES']] # bob shared secret
  var += [['n','NONCEBYTES']]
  var += [['m',0]] # original message
  var += [['c',0]] # boxed message
  var += [['d',0]] # boxed message, second try
  var += [['t',0]] # opened message
  function = [['_keypair',['y','a'],[],[]]]
  function += [['_keypair',['z','b'],[],[]]]
  function += [['',['c'],[],['m','mlen','n','z','a']]]
  function += [['_open',['t'],[],['c','clen','n','y','b']]]
  function += [['_beforenm',['e'],[],['z','a']]]
  function += [['_beforenm',['f'],[],['y','b']]]
  function += [['_afternm',['d'],[],['m','mlen','n','e']]]
  function += [['_open_afternm',['t'],[],['d','dlen','n','f']]]

if operation == 'dh':
  loop = 64
  var = [['a','SECRETKEYBYTES']] # alice secret key
  var += [['b','SECRETKEYBYTES']] # bob secret key
  var += [['c','PUBLICKEYBYTES']] # alice public key
  var += [['d','PUBLICKEYBYTES']] # bob public key
  var += [['e','BYTES']] # alice shared secret
  var += [['f','BYTES']] # bob shared secret
  function = [['_keypair',['c','a'],[],[]]]
  function += [['_keypair',['d','b'],[],[]]]
  function += [['',['e'],[],['d','a']]]
  function += [['',['f'],[],['c','b']]]

if operation == 'sign':
  loop = 8
  var = [['p','PUBLICKEYBYTES']]
  var += [['s','SECRETKEYBYTES']]
  var += [['m',0]] # original message
  var += [['c',0]] # signed message
  var += [['t',0]] # opened message
  function = [['_keypair',['p','s'],[],[]]]
  function += [['',['c','&clen'],[],['m','mlen','s']]]
  function += [['_open',['t','&tlen'],[],['c','clen','p']]]
  extrabytes = 'crypto_sign_BYTES'

if operation == 'encrypt':
  loop = 8
  var = [['p','PUBLICKEYBYTES']]
  var += [['s','SECRETKEYBYTES']]
  var += [['m',0]] # original message
  var += [['c',0]] # encrypted message
  var += [['t',0]] # opened message
  function = [['_keypair',['p','s'],[],[]]]
  function += [['',['c','&clen'],[],['m','mlen','p']]]
  function += [['_open',['t','&tlen'],[],['c','clen','s']]]
  extrabytes = 'crypto_encrypt_BYTES'

if operation == 'kem':
  loop = 8
  var = [['p','PUBLICKEYBYTES']]
  var += [['s','SECRETKEYBYTES']]
  var += [['k','BYTES']]
  var += [['c','CIPHERTEXTBYTES']]
  var += [['t','BYTES']]
  function = [['_keypair',['p','s'],[],[]]]
  function += [['_enc',['c','k'],[],['p']]]
  function += [['_dec',['t'],[],['c','s']]]

length = dict()
for v,n in var: length[v] = n

print '/*'
print ' * crypto_%s/try-notest.c version 20180223' % operation
print ' * D. J. Bernstein'
print ' * Public domain.'
print ' * Auto-generated by trygen-notest.py; do not edit.'
print ' */'
print ''
print '#include "crypto_%s.h"' % operation
print '#include "try.h"'
if operation in ['box','encrypt','scalarmult','sign']:
  print '#include "randombytes.h"'
print ''
print 'const char *primitiveimplementation = crypto_%s_implementation;' % operation
print ''

tunebytes = not operation in ['core','dh','scalarmult']
if tunebytes:
  print '#define TUNE_BYTES 1536'
  print '#ifdef SMALL'
  print '#define MAXTEST_BYTES 128'
  print '#else'
  print '#define MAXTEST_BYTES 4096'
  print '#endif'

print '#ifdef SMALL'
print '#define LOOPS %s' % loop
print '#else'
print '#define LOOPS %s' % (loop * 8)
print '#endif'
print ''

for v,n in var:
  print 'static unsigned char *%s;' % v

for v,n in var:
  print 'static unsigned char *%s2;' % v

for v,n in var:
  if n == 0:
    print 'unsigned long long %slen;' % v
  else:
    print '#define %slen crypto_%s_%s' % (v,operation,n)

# preallocate(): before resource limits are set
print ''
print 'void preallocate(void)'
print '{'
if operation in ['dh','encrypt','kem','sign']:
  print '#ifdef RAND_R_PRNG_NOT_SEEDED'
  print '  RAND_status();'
  print '#endif'
print '}'

# allocate(): set aside storage for test, predoit, doit
print ''
print 'void allocate(void)'
print '{'
print '  unsigned long long alloclen = 0;'
if tunebytes:
  print '  if (alloclen < TUNE_BYTES) alloclen = TUNE_BYTES;'
  if extrabytes != '0':
    print '  if (alloclen < MAXTEST_BYTES + %s) alloclen = MAXTEST_BYTES + %s;' % (extrabytes,extrabytes)
  else:
    print '  if (alloclen < MAXTEST_BYTES) alloclen = MAXTEST_BYTES;'
for v,n in var:
  if n:
    print '  if (alloclen < crypto_%s_%s) alloclen = crypto_%s_%s;' % (operation,n,operation,n)
for v,n in var:
  print '  %s = alignedcalloc(alloclen);' % v
for v,n in var:
  print '  %s2 = alignedcalloc(alloclen);' % v
print '}'

# predoit(): precomputations for doit
print ''
print 'void predoit(void)'
print '{'
if operation == 'scalarmult':
  print '  randombytes(a,alen);'
  print '  randombytes(b,blen);'
if operation == 'box':
  print '  crypto_box_keypair(y,a);'
  print '  crypto_box_keypair(z,b);'
  print '  randombytes(m,mlen);'
  print '  randombytes(n,nlen);'
if operation == 'encrypt':
  print '  crypto_encrypt_keypair(p,s);'
  print '  mlen = TUNE_BYTES;'
  print '  clen = 0;'
  print '  randombytes(m,mlen);'
if operation == 'kem':
  print '  crypto_kem_keypair(p,s);'
if operation == 'sign':
  print '  crypto_sign_keypair(p,s);'
  print '  mlen = TUNE_BYTES;'
  print '  clen = 0;'
  print '  randombytes(m,mlen);'
print '}'

# doit(): main computations to select implementation
print ''
print 'void doit(void)'
print '{'
if operation == 'aead':
  print '  crypto_aead_encrypt(c,&clen,m,TUNE_BYTES,a,TUNE_BYTES,s,p,k);'
  print '  crypto_aead_decrypt(t,&tlen,r,c,clen,a,TUNE_BYTES,p,k);'
if operation == 'auth':
  print '  crypto_auth(h,m,TUNE_BYTES,k);'
  print '  crypto_auth_verify(h,m,TUNE_BYTES,k);'
if operation == 'box':
  print '  crypto_box(c,m,TUNE_BYTES + crypto_box_ZEROBYTES,n,y,b);'
  print '  crypto_box_open(t,c,TUNE_BYTES + crypto_box_ZEROBYTES,n,z,a);'
if operation == 'core':
  print '  crypto_core(h,n,k,c);'
if operation == 'dh':
  print '  crypto_dh_keypair(c,a);'
  print '  crypto_dh_keypair(d,b);'
  print '  crypto_dh(e,d,a);'
  print '  crypto_dh(f,c,b);'
if operation == 'encrypt':
  print '  crypto_encrypt(c,&clen,m,mlen,p);'
  print '  crypto_encrypt_open(t,&tlen,c,clen,s);'
if operation == 'kem':
  print '  crypto_kem_enc(c,k,p);'
  print '  crypto_kem_dec(t,c,s);'
if operation == 'hashblocks':
  print '  crypto_hashblocks(h,m,TUNE_BYTES);'
if operation == 'hash':
  print '  crypto_hash(h,m,TUNE_BYTES);'
if operation == 'onetimeauth':
  print '  crypto_onetimeauth(h,m,TUNE_BYTES,k);'
  print '  crypto_onetimeauth_verify(h,m,TUNE_BYTES,k);'
if operation == 'rng':
  print '  crypto_rng(r,n,k);'
if operation == 'scalarmult':
  print '  crypto_scalarmult_base(c,a);'
  print '  crypto_scalarmult_base(d,b);'
  print '  crypto_scalarmult(e,a,d);'
  print '  crypto_scalarmult(f,b,c);'
if operation == 'secretbox':
  print '  crypto_secretbox(c,m,TUNE_BYTES + crypto_secretbox_ZEROBYTES,n,k);'
  print '  crypto_secretbox_open(t,c,TUNE_BYTES + crypto_secretbox_ZEROBYTES,n,k);'
if operation == 'sign':
  print '  crypto_sign(c,&clen,m,mlen,s);'
  print '  crypto_sign_open(t,&tlen,c,clen,p);'
if operation == 'stream':
  print '  crypto_stream_xor(c,m,TUNE_BYTES,n,k);'
if operation == 'verify':
  print '  crypto_verify(x,y);'
print '}'

