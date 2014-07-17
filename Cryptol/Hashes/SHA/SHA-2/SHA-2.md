# Aborted SHA-2 Literate Cryptol version 2 specification
 * Dylan McNamee
 * Sigbjorn Finne
 * Frank Seaton Taylor
 * Joseph Kiniry
 * Joey Dodds

Tue Jul  8 11:01:47 PDT 2014

## Abstract

There's good stuff in here, but it ain't SHA-2.

# Header Comments

<!-- @kiniry Update header comment. -->
```example
// Copyright (c) 2007-2009, Galois, Inc.
//
// Author: Sigbjorn Finne

// Based on spec in FIPS180-2 doc: http://csrc.nist.gov/publications/fips/fips180-2/fips180-2withchangenotice.pdf

// Frank Seaton Taylor removed eveything unnecessary to SHA-384

// Frank Seaton Taylor made Ch, Maj, [sS]igma_[01] be explicit functions

module SHA384 where
```

### 4.1.2 SHA-256 Functions

SHA-256 uses six logical functions, where each function operates on
32-bit words, which are represented as x, y, and z. The result of each
function is a new 32-bit word.

<!-- start with eqn 4.4 -->
\begin{eqnarray}
    Ch(x,y,z) = (x \wedge y) \oplus (\neg x \wedge z) \\
    Maj(x,y,z) = (x \wedge y) \oplus (x \wedge z) \oplus (y \wedge z) \\
    \sum_0^{\{256\}}(x) = ROTR^2(x) \oplus ROTR^{13}(x) \oplus ROTR^{22}(x) \\
    \sum_1^{256}(x) = ROTR^6(x) \oplus ROTR^{11}(x) \oplus ROTR^{25}(x) \\
    \sigma_0^{256}(x) = ROTR^7(x) \oplus ROTR^{18}(x) \oplus SHR^3(x) \\
    \sigma_1^{256}(x) = ROTR^{17}(x) \oplus ROTR^{19}(x) \oplus SHR^{10}(x) \\
\end{eqnarray}

```example
// In Cryptol,
Ch : ([64],[64],[64]) -> [64]
Ch(x,y,z) = (x && y) ^ ((~x) && z)
Maj : ([64],[64],[64]) -> [64]
Maj(x,y,z) = (x && y) ^ (x && z) ^ (y && z)
UpperSigma_0 : [64] -> [64]
UpperSigma_0(x) = (x >>> 28) ^ (x >>> 34) ^ (x >>> 39)
UpperSigma_1 : [64] -> [64]
UpperSigma_1(x) = (x >>> 14) ^ (x >>> 18) ^ (x >>> 41)
LowerSigma_0 : [64] -> [64]
LowerSigma_0(x) = (x >>> 1) ^ (x >>> 8) ^ (x >> 7)
LowerSigma_1 : [64] -> [64]
LowerSigma_1(x) = (x >>> 19) ^ (x >>> 61) ^ (x >> 6)
```

### 4.2.2 SHA-256 Constants

SHA-256 uses a sequence of sixty-four constant 32-bit words,
$K_0^{256},K_1^{256},\ldots,K_{63}^{256}$. These words represent the first
thirty-two bits of the fractional parts of the cube roots of the first
sixty-four prime numbers. In hex, these constant words are (from left
to right)

\begin{verbatim}
428a2f98 71374491 b5c0fbcf e9b5dba5 3956c25b 59f111f1 923f82a4 ab1c5ed5
d807aa98 12835b01 243185be 550c7dc3 72be5d74 80deb1fe 9bdc06a7 c19bf174
e49b69c1 efbe4786 0fc19dc6 240ca1cc 2de92c6f 4a7484aa 5cb0a9dc 76f988da
983e5152 a831c66d b00327c8 bf597fc7 c6e00bf3 d5a79147 06ca6351 14292967
27b70a85 2e1b2138 4d2c6dfc 53380d13 650a7354 766a0abb 81c2c92e 92722c85
a2bfe8a1 a81a664b c24b8b70 c76c51a3 d192e819 d6990624 f40e3585 106aa070
19a4c116 1e376c08 2748774c 34b0bcb5 391c0cb3 4ed8aa4a 5b9cca4f 682e6ff3
748f82ee 78a5636f 84c87814 8cc70208 90befffa a4506ceb bef9a3f7 c67178f2.
\end{verbatim}

# 5. PREPROCESSING

Preprocessing shall take place before hash computation begins. This
preprocessing consists of three steps: padding the message, $M$
(Sec. 5.1), parsing the padded message into message blocks (Sec. 5.2),
and setting the initial hash value, $H^{(0)}$ (Sec. 5.3).

## 5.1 Padding the Message

The message, $M$, shall be padded before hash computation begins. The
purpose of this padding is to ensure that the padded message is a
multiple of 512 or 1024 bits, depending on the algorithm.

### 5.1.1 SHA-1 and SHA-256

Suppose that the length of the message, $M$, is $l$ bits. Append the
bit ``1'' to the end of the message, followed by $k$ zero bits, where
$k$ is the smallest, non-negative solution to the equation $l + 1 + k
\equiv 448 mod 512$. Then append the 64-bit block that is equal to the
number $l$ expressed using a binary representation. For example, the
(8-bit ASCII) message ```\textbf{abc}''' has length $8 \times 3 = 24$,
so the message is padded with a one bit, then $448 − (24 + 1) = 423$
zero bits, and then the message length, to become the 512-bit padded
message

<!-- @kiniry Tue Jul  8 11:33:12 PDT 2014 Convert to LaTeX.
423 64
678 64748
01100001 01100010 01100011 1 00...00 00...011000 . 14243 14243 14243 123
``a'' ``b'' ``c'' l = 24
-->

The length of the padded message should now be a multiple of 512 bits.

## 5.2 Parsing the Padded Message

After a message has been padded, it must be parsed into $N$ $m$-bit
blocks before the hash computation can begin.

### 5.2.1 SHA-1 and SHA-256

For SHA-1 and SHA-256, the padded message is parsed into $N$ 512-bit
blocks, $M^{(1)}, M^{(2)},\ldots, M^{(N)}$. Since the 512 bits of the
input block may be expressed as sixteen 32-bit words, the first 32
bits of message block $i$ are denoted $M_0^{(i)}$,the next 32 bits are
$M_1^{(i)}$, and soon up to $M_{15}^{(i)}$.

## 5.3 Setting the Initial Hash Value ($H^{(0)}$)

Before hash computation begins for each of the secure hash algorithms,
the initial hash value, $H^{(0)}$, must be set. The size and number of
words in $H^{(0)}$ depends on the message digest size.

### 5.3.2 SHA-256

For SHA-256, the initial hash value, $H^{(0)}$, shall consist of the
following eight 32-bit words, in hex:
\begin{eqnarray}
H_0^{(0)} = 6a09e667
H_1^{(0)} = bb67ae85
H_2^{(0)} = 3c6ef372
H_3^{(0)} = a54ff53a
H_4^{(0)} = 510e527f
H_5^{(0)} = 9b05688c
H_6^{(0)} = 1f83d9ab
H_7^{(0)} = 5be0cd19\text{.}
\end{eqnarray}

These words were obtained by taking the first thirty-two bits of the
fractional parts of the square roots of the first eight prime numbers.

# 6. SECURE HASH ALGORITHMS

In the following sections, SHA-512 is described before SHA-384. That
is because the SHA-384 algorithm is identical to SHA-512, with the
exception of using a different initial hash value and truncating the
final hash value to 384 bits.  For each of the secure hash algorithms,
there may exist alternate computation methods that yield identical
results; one example is the alternative SHA-1 computation described in
Sec. 6.1.3. Such alternate methods may be implemented in conformance
to this standard.

## 6.2 SHA-256

<!--- @kiniry Tue Jul  8 11:33:12 PDT 2014 Convert to LaTeX.
SHA-256 may be used to hash a message, M, having a length of l bits, where 0 ≤ l < 264 . The algorithm uses 1) a message schedule of sixty-four 32-bit words, 2) eight working variables of 32 bits each, and 3) a hash value of eight 32-bit words. The final result of SHA-256 is a 256-bit message digest.
The words of the message schedule are labeled W0, W1,..., W63. The eight working variables are labeled a, b, c, d, e, f, g, and h. The words of the hash value are labeled H0(i),H1(i) ,K,H7(i) ,
which will hold the initial hash value, H(0), replaced by each successive intermediate hash value (after each message block is processed), H(i), and ending with the final hash value, H(N). SHA- 256 also uses two temporary words, T1 and T2.
Appendix B gives several detailed examples of SHA-256.
￼￼￼￼￼￼￼￼18
6.2.1
6.2.2
SHA-256 Preprocessing
1. Pad the message, M, according to Sec. 5.1.1;
2. Parse the padded message into N 512-bit message blocks, M(1), M(2), ..., M(N),
according to Sec. 5.2.1; and
3. Set the initial hash value, H(0), as specified in Sec. 5.3.2.
SHA-256 Hash Computation
The SHA-256 hash computation uses functions and constants previously defined in Sec. 4.1.2 and Sec. 4.2.2, respectively. Addition (+) is performed modulo 232.
After preprocessing is completed, each message block, M(1), M(2), ..., M(N), is processed in order, using the following steps:
For i=1 to N: {
1. Prepare the message schedule, {Wt} : M(i)
t Wt =
σ1{256}(Wt−2)+Wt−7 +σ0{256}(Wt−15)+Wt−16
2. Initialize the eight working variables, a, b, c, d, e, f, g, and h, with the (i-1)st hash
value:
a = H 0( i − 1 ) b = H 1( i − 1 ) c = H 2( i − 1 ) d = H 3( i − 1 ) e = H 4( i − 1 )
f =H5(i−1) g = H 6( i − 1 ) h = H 7( i − 1 )
3. For t=0 to 63: {
￼19
0≤t ≤15 16≤t≤63
{256} {256}
T1 =h+∑1 (e)+Ch(e,f,g)+Kt +Wt
T2 =∑{256}(a)+Maj(a,b,c) 0
h=g g=f f=e
e=d+T 1
d=c c=b b=a a=T1 +T2
}
4. Compute the ith intermediate hash value H(i):
H0(i) =a+H0(i−1) H1(i) =b+H1(i−1) H2(i) =c+H2(i−1) H3(i) =d+H3(i−1) H4(i) =e+H4(i−1) H 5( i ) = f + H 5( i − 1 ) H6(i) =g+H6(i−1) H7(i) =h+H7(i−1)
}
After repeating steps one through four a total of N times (i.e., after processing M(N)), the resulting
256-bit message digest of the message, M, is
H0(N) H1(N) H2(N) H3(N) H4(N) H5(N) H6(N) H7(N) .
--->

```example
// @refinement Block512_T1 \triangleq T_1
Block512_T1 : [64] -> [64] -> [64] -> [64] -> [64] -> [64] -> [64]
Block512_T1 h e f g w k = h + UpperSigma_1(e) + Ch(e,f,g) + k + w

Block512_T2 : [64] -> [64] -> [64] -> [64]
Block512_T2 a b c = UpperSigma_0(a) + Maj(a,b,c)

Block512_W : [64] -> [64] -> [64] -> [64] -> [64] 
Block512_W W2 W7 W15 W16 = LowerSigma_1(W2) + W7 + LowerSigma_0(W15) + W16
```

Block512_Inner : [80][64] -> [9][64] -> [9][64]
Block512_Inner Ws [h, g, f, e, d, c, b, a, t] = [h', g', f', e', d', c', b', a', t']
  where
    a' = t1 + t2
    b' = a
    c' = b
    d' = c
    e' = d + t1
    f' = e
    g' = f
    h' = g
    t1 = Block512_T1 h e f g (Ws@t) (Ks512@t)
    t2 = Block512_T2 a b c
    t' = t + 1

iv384 : [8][64]
iv384 = [ 0xcbbb9d5dc1059ed8,
          0x629a292a367cd507,
          0x9159015a3070dd17,
          0x152fecd8f70e5939,
          0x67332667ffc00b31,
          0x8eb44a8768581511,
          0xdb0c2e0d64f98fa7,
          0x47b5481dbefa4fa4]

sha384 : [127][8] -> [384]
sha384 msg = take`{384} (join(Hs ! 0))
 where
  Hs : [3][8][64]
  Hs = [iv384] #
       [block512(H, split M)
            | H <- Hs
            | M <- pad512(join msg)]

block512 : ([8][64], [16][64]) -> [8][64]
block512 ([H0, H1, H2, H3, H4, H5, H6, H7], M) = [ (H0+a), (H1+b), (H2+c), (H3+d),
                                                   (H4+e), (H5+f), (H6+g), (H7+h) ]
 where
  Ws : [80][64]
  Ws = M # [ Block512_W W2 W7 W15 W16
            | W16 <- drop`{16 - 16} Ws
            | W15 <- drop`{16 - 15} Ws
            | W7  <- drop`{16 -  7} Ws
            | W2  <- drop`{16 -  2} Ws
            | _t <- [16..79]]
  outs = [[H7, H6, H5, H4, H3, H2, H1, H0, 0]] #
          [ Block512_Inner Ws outs' | outs' <- outs]
  [h, g, f, e, d, c, b, a, t] = outs@80

pad512 : [127 * 8] -> [2][1024]
pad512 msg = split(msg # [True] # zero # (width msg : [128]))

Ks512 : [80][64]
Ks512 = [ 0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
          0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
          0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
          0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
          0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
          0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
          0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
          0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
          0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
          0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
          0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
          0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
          0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
          0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
          0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
          0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
          0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
          0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
          0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
          0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817]

```
