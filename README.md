# hacrypto


## Intro
Snapshots, architectures, audits, validation, and verification of crypto libraries

## Snapshots
Snapshots are contained in the language directories ([C](C), [Java](Java), [C++](C++), [C#](C#), [Javascript](Javascript)). 
A complete list of snapshots is available in the audit file

## Audits
Quick audits of some of the libraries in [Audits.md](Audits.md).

## Architecture
BON specifications for the hacrypto library can be found in the [arch](arch) folder, along with a [HTML view](http://htmlpreview.github.io/?https://github.com/GaloisInc/hacrypto/blob/master/arch/index.html#system_chart:HACRYPTO_SYSTEM) of the architecture, and generated tests.

## Cryptol
Cryptol 2 implementation of SHA256, along with older cryptol implementations, and C implementations generated from those.

## Verification/Valdiation
The [callsha](callsha) folder contains experiments with building, calling, and running frama-c value analysis on SHA256 implementations from NSS, Sodium, and a (macro expanded)[http://www.cs.princeton.edu/~appel/papers/verif-sha.pdf] (and verified in coq) OpenSSL.
