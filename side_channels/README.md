attacks

- timing/leakage
 + operator choice
 + data cache
 + instruction cache
 + branch prediction cache
- secret-dependent dataflow
- power consumption
- RF emissions
- electromagnetic emissions
- fault induction (glitching)
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

countermeasures
- normalizing
- randomization
- masking
- bitslicing to avoid lookup tables
- sharing-based side-channel countermeasures (threshold impls) [6: 2, 13]
- affine transformations
- search algorithms and tools for evaluating a key schedule (8: 4, 5,
  14, 16, 28, 32)

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
