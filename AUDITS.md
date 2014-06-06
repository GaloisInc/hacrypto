High-level Quality Audits of Crypto Libraries
=============================================

##### Joe Kiniry and Joey Dodds, Galois

Relevant Libraries
------------------

| Name              | Site                                   | PL   | Status   |  
|-------------------|----------------------------------------|------|----------|
| BouncyCastle 1.50 | https://www.bouncycastle.org/java.html | Java | Complete |  
| BouncyCastle 1.7  | http://www.bouncycastle.org/csharp/    | C#   | Ongoing  |  
| OpenSSL           |                                        | C    | Ongoing  |  
| NaCl              | http://nacl.cr.yp.to/                  | C    | Complete |  
| Nettle            | http://www.lysator.liu.se/~nisse/nettle/ | C    | Ongoing  |  
| Cryptlib          |                                        | C    | Ongoing  |   
| libmcrypt         | http://mcrypt.sourceforge.net/         | C    | Ongoing  |  
| libtomcrypt       | http://libtom.org/?page=features       | C    | Ongoing  |  
| MIRACL            | http://www.certivox.com/miracl/        | C    | Complete |  
| OpenAES           |                                        | C    | Ongoing  |  
| relic             |                                        | C    | Ongoing  |  

libtomcrypt
---------------------------
| | |
|------|----------------|
| Size | 39K C |
| Age | 2001-2007 |
| Key Metrics |  |
| Documentation | [doc file](https://github.com/GaloisInc/hacrypto/blob/master/c/libtomcrypt-1.17/doc/crypt.pdf) |
| License | public domain |
| Feature Description | |
| Examples | [1K C](https://github.com/GaloisInc/hacrypto/tree/master/c/libtomcrypt-1.17/demos)|
| Community | [IRC chat](http://webchat.freenode.net/?channels=libtom), [list](https://groups.google.com/forum/#!forum/libtom) |
| Wiki | no |
| Tracker | no |
| Support | no |
| API Design | modular, standard |
| Architecture Specifications | no |
| Design Specifications | no |
| Behavioral Specifications | no |
| Engineering Practices | Written completely in C, Requires only gcc to build |
| Tests | 3k handwritten C, includes some randomness |
| Other Evidence of Correctness | |
| Validation | tests |
| Verification | no |
| Published Materials | no |
| Other Comments | |

libmcrypt
---------------------------
| | |
|------|----------------|
| Other Comments | private-key only|

MIRACL
---------------------------
| | |
|------|----------------|
| Size | 48K C, 45K CPP (says it has a cpp wrapper, but there must be more)|
| Age | unknown-current |
| Key Metrics | most code at top level |
| Documentation | [users manual and refs](https://certivox.org/display/EXT/MIRACL+User%27s+Manual) |
| License | AGPL, closed source available |
| Feature Description | Low level, comes with libraries for high precision math, autogenerates optimal assembly |
| Examples | [Example programs](https://certivox.org/display/EXT/8.+Example+Programs) in the user manual |
| Community | [CertiVox community](https://certivox.org/display/WLCM/Community) [Twitter](https://twitter.com/CertiVox) |
| Wiki | no |
| Tracker | [JIRA tracker](https://sdlc.certivox.com/browse/MIRACL) |
| Support | [support list](http://lists.certivox.org/mailman/listinfo/miracl-users) |
| API Design | Allows developer designed APIs |	
| Architecture Specifications | no |
| Design Specifications | no |
| Behavioral Specifications | no |
| Engineering Practices | no|
| Tests | not provided|
| Other Evidence of Correctness | no |
| Validation | [some users](http://www.certivox.com/about-certivox/testimonials/) |
| Verification | no|
| Published Materials | no |
| Other Comments | no |

Nettle
---------------------------
| | |
|------|----------------|
| Size | 45k c, 11k asm |
| Age | 1998 - current (active as of 6/5/14) |
| Key Metrics | 27k c at top level, x86_64 5k asm, x86 2k asm, arm 3k asm, sparc32 & 64 .5k asm each, tools 2k c |
| Documentation | html with installation, examples, [api reference](http://www.lysator.liu.se/~nisse/nettle/nettle.html) |
| License | LGPL |
| Feature Description | low level crypto only with a simple, general interface|
| Examples | [website](http://www.lysator.liu.se/~nisse/nettle/nettle.html#Example) , 3k examples in example directory|
| Community | [mailing list](http://lists.lysator.liu.se/mailman/listinfo/nettle-bugs) |
| Wiki | no |
| Tracker | no |
| Support | mailing list or [email](mailto:nisse@lysator.liu.se) with questions|
| API Design | general, low level only api|
| Architecture Specifications | no |
| Design Specifications | no |
| Behavioral Specifications | no |
| Engineering Practices | no memory allocation  |
| Tests | 12k of hand-coded tests, |
| Other Evidence of Correctness | no |
| Validation | tests |
| Verification | no |
| Published Materials | |
| Other Comments | |


NaCl
---------------------------
| | |
|------|----------------|
| Size | 19K asm, 13K C |
| Age | 2008 - 2011 |
| Key Metrics | crypto_stream 13k asm, 2k c; crypto_scalarmult 5K asm, 1K c; curvecp 3k c; crypto_ontimeauth 1k c, 1k asm |
| Documentation | [examples on the website](http://nacl.cr.yp.to/box.html) |
| License | public domain |
| Feature Description | [website](http://nacl.cr.yp.to/features.html) |
| Examples | tests, documentation is mostly examples|
| Community | not much |
| Wiki | no |
| Tracker | no |
| Support | no |
| API Design | very small api |
| Architecture Specifications | no |
| Design Specifications | no |
| Behavioral Specifications | no |
| Engineering Practices | no data-dependent branches or array indices, no dynamic memory allocation |
| Tests | 1K of C tests, 1K C++ tests |
| Other Evidence of Correctness | code practices help, authors pay attention to cryptoanalysis |
| Validation | some validation done against sage and python libraries to compare results in a report at http://cr.yp.to/highspeed/naclcrypto-20090310.pdf|
| Verification | no |
| Published Materials | [LatinCrypt 2012 paper](http://cr.yp.to/highspeed/coolnacl-20120725.pdf) ; [high level tech report](http://nacl.cr.yp.to/securing-communication.pdf)  |
| Other Comments | engineering practices seem verification friendly, not sure about large amounts of asm |


BouncyCastle 1.50 for Java, 
---------------------------
| | |
|------|----------------|
| Size | 448K of Java |
| Age | under development from 2000-2014 |
| Key Metrics | core is 128K, 84 packages, and 1125 classes (128K/84/1125); provider is 57K/41/963; mail is 5K/5/53; pg is 18K/9/171; pkix 28K/32/436 |
| Documentation | release notes, high-level specification, fair API docs |
| License | MIT X Consortium (mostly) |
| Feature Description | provided at a high-level in a [specifications document](https://www.bouncycastle.org/specifications.html) |
| Examples | provided via unit tests and discussed on StackExchance frequently |
| Community | developer and announce [mailing lists](https://www.bouncycastle.org/mailing_lists.html) |
| Wiki | JIRA wiki unavailable as of 4 June 2014 |
| Tracker | JIRA tracker unavailable as of 4 June 2014 and poorly updated when live |
| Support | Legion of the Bouncy Castle is an NGO and [Crypto Workshop](http://www.cryptoworkshop.com/) is a for-profit company consultancy work |
| API Design | has both a lightweight API and a JCE provider |
| Architecture Specifications | N/A |
| Design Specifications | N/A |
| Behavioral Specifications | N/A |
| Engineering Practices | lightweight coding standard, hand-written unit tests, conformance to open API as facade for lightweight internal API |
| Tests | 99K of JUnit test code; core/provider/mail/pg/pkix test count 238/37/131/42/216 for a total of 664 tests |
| Other Evidence of Correctness | handful of assertions in J2ME version of core |
| Validation | moderate manual testing focusing on hand-identified scenarios and published test vectors; enormous number of clients |
| Verification | N/A |
| Published Materials | [Oracle's Java Cryptography Extensions Architecture (JCE)](http://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html), [several books have been published about the JCE](http://www.amazon.com/s/ref=nb_sb_noss?url=search-alias%3Daps&field-keywords=Java%20cryptography) |
| Other Comments | Conforms to JCE |

BouncyCastle 1.7 for C#, 7 April 2011
-------------------------------------

template,
---------------------------
| | |
|------|----------------|
| Size | |
| Age |  |
| Key Metrics |  |
| Documentation | |
| License | |
| Feature Description | |
| Examples | |
| Community | |
| Wiki | |
| Tracker |  |
| Support |  |
| API Design | |
| Architecture Specifications | |
| Design Specifications | |
| Behavioral Specifications | |
| Engineering Practices | |
| Tests | |
| Other Evidence of Correctness | |
| Validation | |
| Verification | |
| Published Materials | |
| Other Comments | |


Line counts generated using David A. Wheeler's 'SLOCCount'.
