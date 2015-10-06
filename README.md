# hacrypto


## Intro
Snapshots, architectures, audits, validation, and verification of crypto libraries

## Snapshots
Source snapshots are all in the [src](src) directory. They are orgranized by language then library, then version directories. Our goal for snapshots is breadth. Please let us know if there is anything that we are missing!

## Audits
Quick audits of some of the libraries in [AUDITS.md](AUDITS.md).

## Architecture
BON specifications for the hacrypto library can be found in the [arch](arch) folder, along with a [HTML view](http://htmlpreview.github.io/?https://github.com/GaloisInc/hacrypto/blob/master/arch/index.html#system_chart:HACRYPTO_SYSTEM) of the architecture, and generated tests.


## Test generation
The TestGen contains a project that generates test cases and harnesses for crypto libraries. A primary goal is to generate CAVP tests and hopefully find some insufficiencies in the testing.

## Verification/Validation
The [Verification/VST/sha](Verification/VST/sha) folder contains experiments with building, calling, and running frama-c value analysis on SHA256 implementations from NSS, Sodium, and a [macro expanded and verified in Coq](http://www.cs.princeton.edu/~appel/papers/verif-sha.pdf) OpenSSL.
