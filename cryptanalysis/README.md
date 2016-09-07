general cryptoanalysis attacks

- chosen prefix collisions
- oracle
- nonce abuse and reuse [3: 18, 5: 38]
- authenticated abuse (e.g., length 0)
- IV reuse [1: 2]
- forgery
- linear [1: 14]
- differential [1: 15, 16, 17]
- cube [1: 7, 8]
- correlation [1: 13, 12, 10, 11, 3]
- algebraic [1: 4, 5]
- birthday bound security [2: 1, 3: 19]
- security proofs [2: 1]
- chosen plaintext (CPA) [3: 18]
- strong pseudo-random permutation SPRP
- flaws in lightweight AE [3: 5, 12, 22]
- state/key recovery
- forcing internal collisions through queries
- plaintext length leak
- slide [8: 6]
- rotational [8: 21]
- internal differential [8: 29]
- related-cipher [8: 33]
- self-similarity
- related-key differential [7: 2, 3]
- Meet-in-the-Middle (MITM) [7: 9, 11, 13, 24]
- Block-wise Adaptive Adversaries [9: 12]

components
- (Linear) Diffusion
- ANF Algebraic Normal Form
- Confusion and Diffusion a la Shannon '45
- HMAC Keyed-Hashing for Message Authentication
- LFSR Linear Feedback Shift Register
- MDS Maximum Distance Separable matrices [x: 17]
- MRAE Nonce-Reuse Miuse-Resistence [5: 38]
- PMAC Parallelizable Message Authentication Code [4: 26]
- PRF Pseudo-Random Function Family
- PRG Pseudo-Random Generator
- PRI Pseudo-Random Injection [5: 38]
- PRP Pseudo-Random Permutation ("strong"?)
- RAE Robust Authenticated-Encryption [5: 17]
- S-box
- SPN Substitution Permutation Network (substitution permutation product)
- Sponge Function/Construction
- TBC Tweakable BlockCipher
- UMAC Universal Hashing Message Authentication
- VMAC Universal Hashing Message Authentication using block ciphers [10: 4]
- URP Uniform Random Permutation
- TC3

modes
- CCM [3: 21]
- CCFB [4: 22]
- CFB [3: 17]
- CLOC
- CMAC [4: 5]
- COPA [9: 1]
- CPFB
- CTR
- CWC [3: 13]
- EAX [3: 2]
- ELmD
- EME [5: 15, 16, 9: 9]
- FFX [5: 5, 12]
- GCM [2: 5, 3: 16]
- IAPM [3: 11]
- OCB 2.0 [3: 20], OCB 3
- OMAC [4: 17]
- OTR [4: 23, 24, 5: 26]
- SCT [8: 30]
- SILC
- TBC [5: 24]
- XEX (xor-encrypt-xor) tweakable
- XTS (ciphertext stealing)

new schemes
- 3-Way (SPN-based)
- ALE [3: 4]
- ALE [8: 7]
- ALRED [5: 9, 10, 39, 41]
- BTM [9: 11]
- CAST (Adams and Tavares, design procedure uses bent functions to
  design its S-boxes)
- Deoxys-BC [8]
- FIDES [3: 3]
- Grain (stream cipher that uses an NLFSR whose nonlinear feedback
  poly is the sum of a bent function and a linear function)
- HAVAL (hash using equivalence classes of bent functions on six vars)
- HBS [9: 10]
- Hamsi [6: 11]
- Hummingbird-2 [3: 6]
- Lucifer (pre-DES from Feistel at IBM)
- Luffa [6: 7]
- MARVIN [5: 9, 10, 39, 41]
- MonkeyDuplex [6: 8]
- PELICAN [5: 9, 10, 39, 41]
- SAFER (SPN-based)
- SHARK (SPN-based)
- SIV [9: 20]
- Skipjack
- SpongeWrap [6: 4]
- Sponge duplex [9: 3]
- Spritz (RC4 redesign)
- Square (SPN-based)
- TWINE [7: 30]
- McOE-D [9: 7]

case studies
- AEZ using alternative scaled down primitives other than AES4

1: acornv2
2: aescoav2
3: aesjambuv2
4: aesotrv2
5: aezv4
6: asconv11
7: clocv2
8: deoxysv13
9: elmdv20
10: hs1sivv2

x: icepolev2
