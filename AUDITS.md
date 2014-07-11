High-level Quality Audits of Crypto Libraries
=============================================

##### Joe Kiniry and Joey Dodds, Galois


Relevant Libraries
------------------

| Name              | Site                                   | PL   | Status   |  
|-------------------|----------------------------------------|------|----------|
| [BouncyCastle 1.50 for Java, ](#user-content-bouncycastle-150-for-java-) | https://www.bouncycastle.org/java.html | Java | Complete |
| [BouncyCastle 1.7 for C#, 7 April 2011](#user-content-bouncycastle-17-for-c-7-april-2011) | http://www.bouncycastle.org/csharp/    | C#   | Ongoing  |
| [OpenSSL](#user-content-openssl) | http://www.openssl.org/ | C    | Complete  |
| [NaCl](#user-content-nacl)  | http://nacl.cr.yp.to/                  | C    | Complete |
| [Nettle](#user-content-nettle)  | http://www.lysator.liu.se/~nisse/nettle/ | C    | Complete  |
| [Cryptlib](#user-content-cryptlib)   |   http://www.cryptlib.com/  | C    | Complete  |
| [libmcrypt](#user-content-libmcrypt) | http://mcrypt.sourceforge.net/         | C    | Private/shared key only  |
| [libtomcrypt](#user-content-libtomcrypt) | http://libtom.org/?page=features       | C    | Complete  |
| [MIRACL](#user-content-miracl) | http://www.certivox.com/miracl/        | C    | Complete |
| OpenAES           |                                        | C    | Ongoing  |
| [RELIC](#user-content-relic) | https://code.google.com/p/relic-toolkit/  | C    | Complete  |
| ffmpeg | http://www.ffmpeg.org/ | C, C++ | Ongoing |
| Android crypto | Originally seen in Mozilla's repo under ./mozilla/mobile/android/base/sync/crypto/ and ./mobile/android/base/sync/jpake/ | Java | Not Archived |
| Java SDK | javax.crypto | Java | Not Archived |
| Mozilla hawk-brower, identity, passwordmgr, sync | | Javascript | Ongoing |
| Mozilla SRTP | | C | Ongoing |
| [Mozilla NSS](#user-content-mozilla-nss) | https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS | C | Complete |
| [PolarSSL](#user-content-polarssl) | https://polarssl.org/ | C | Complete | 
| [OpenBSD Framework](#user-content-openbsd-framework) | http://www.openbsd.org/crypto.html | C | Complete |
| [FreeBSD Framework] | | C | Not Started |
| [NetBSD Framework] | | C | Not Started |
| [Sodium](#user-content-sodium) | https://github.com/jedisct1/libsodium | C | Complete |
| libressl from OpenBSD foundation |  | C | Not Started |
| Google's boringssl | | C | Not Started |
| Google's JavaScript library | | Javascript | Not Started |
| Crypto++ | http://www.cryptopp.com/ | C++ | Not Started| 
| LibreSSL (portable) | http://www.libressl.org/ | C | Not Started | 

Sodium
---------------------------
| | |
|------|----------------|
| Size | 17K C, 1K asm |
| Age | 2013-current |
| Key Metrics | 4K crypto-sign, 4K crypto-stream, 1K generic hash, 1K pwhash (generic hash and pwhash are not in NaCl) |
| Documentation | [README](https://github.com/jedisct1/libsodium/blob/master/README.markdown), most of the NaCl documentation applies|
| License | [ISC license](http://en.wikipedia.org/wiki/ISC_license) |
| Feature Description | Portable NaCl plus generic hash, password hash, short hash, and additional (simpler) api functions|
| Examples | tests, NaCl documentation|
| Community | no |
| Wiki | no |
| Tracker | no |
| Support | no |
| API Design | Same as NaCl plus _easy functions|
| Architecture Specifications | no |
| Design Specifications | no |
| Behavioral Specifications | no |
| Engineering Practices | unknown |
| Tests | 3K handwritten C|
| Other Evidence of Correctness | no |
| Validation | no |
| Verification | no |
| Published Materials | no |
| Other Comments | The portable version of NaCl. Worth looking into how similar implementations are to NaCl, if the same coding practices are used. A decent amount of what is included in this library is gathered from sources other than NaCl. It is not safe to assume that this is a straight port |

Cryptlib
---------------------------
| | |
|------|----------------|
| Size | 241K C, 63K asm |
| Age |  |
| Key Metrics |  |
| Documentation | [user guide](ftp://ftp.franken.de/pub/crypt/cryptlib/manual.pdf) |
| License | [sleepycat](http://opensource.org/licenses/Sleepycat) GPL compatible |
| Feature Description | supports many platforms, full implementations of protocols such as S/MIME and SSL, can use hardware accelerators |
| Examples | [website](http://www.cryptlib.com/security-software/programming-code-examples), manual is filled with examples |
| Community | no |
| Wiki | no |
| Tracker | no |
| Support | by email |
| API Design | Three layers, high, middle and low, covered in manual|
| Architecture Specifications | no |
| Design Specifications | no |
| Behavioral Specifications | no |
| Engineering Practices | |
| Tests | 30K, Handwritten, lots of comments|
| Other Evidence of Correctness | [numerous clients](http://www.cryptlib.com/security-software/clients-users) |
| Validation | tests |
| Verification | no  |
| Published Materials | |
| Other Comments | |

OpenBSD Framework
---------------------------
| | |
|------|----------------|
| Size | 9K c |
| Age | 2000-current |
| Key Metrics | all source top level|
| Documentation | Well documented code|
| License | BSD |
| Feature Description | in the kernel, makes use of hardware accelerators, |
| Examples | |
| Community | [mailing lists](http://www.openbsd.org/mail.html) |
| Wiki | |
| Tracker | [bugs database](http://www.openbsd.org/report.html) |
| Support | http://www.openbsd.org/mail.html |
| API Design | added to the system as a device/service layer |
| Architecture Specifications | no |
| Design Specifications | no |
| Behavioral Specifications | no |
| Engineering Practices | [BSD style](http://www.openbsd.org/cgi-bin/man.cgi?query=style&sektion=9&apropos=0&manpath=OpenBSD+Current&arch=) |
| Tests | |
| Other Evidence of Correctness | BSD is known to pay attention to security |
| Validation | |
| Verification | |
| Published Materials | [The Design of the OpenBSD Cryptographic Framework](http://www.openbsd.org/papers/ocf.pdf)|
| Other Comments | [alleged backdoor](http://marc.info/?l=openbsd-tech&m=129236621626462&w=2) |

Mozilla NSS
---------------------------
| | |
|------|----------------|
| Size | 478K C, 50K asm, 15k sh (harness for tests)|
| Age | 1995-current |
| Key Metrics | 434K lib, 88K command |
| Documentation | [overview](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Overview) (many broken links), a few docs in docs folder ([incomplete](https://bugzilla.mozilla.org/show_bug.cgi?id=836477) |
| License | MPL |
| Feature Description | [open standards](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Overview#Interoperability_and_Open_Standards) |
| Examples | [example list](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/NSS_Sample_Code) |
| Community | [list](https://lists.mozilla.org/listinfo/dev-security), [stack overflow](http://stackoverflow.com/r/mozilla), [google group](http://groups.google.com/group/mozilla.dev.security) |
| Wiki | [main site](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS) |
| Tracker | [Bugzilla](https://bugzilla.mozilla.org/buglist.cgi?query_format=specific&order=relevance+desc&bug_status=__open__&product=NSS&content=NSS&comments=0) |
| Support | [Mozilla support] (https://support.mozilla.org/en-US/)|
| API Design | [Layered](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/NSS_API_GUIDELINES), separates into a few libraries |
| Architecture Specifications | no |
| Design Specifications | no |
| Behavioral Specifications | no |
| Engineering Practices | [Numerous, described below anchor link](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/NSS_API_GUIDELINES#Naming_Conventions) |
| Tests | custom harness, lines hard to count. Pass/Fail tests|
| Other Evidence of Correctness | [used in several high-profile projects](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Overview) |
| Validation | |
| Verification | no |
| Published Materials | no |
| Other Comments | [built on top of nspr](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS#NSS_is_built_on_top_of_Netscape_Portable_Runtime_(NSPR)) |

PolarSSL
---------------------------
| | |
|------|----------------|
| Size | 54k C |
| Age | 2006-current (6/11/2014) |
| Key Metrics | 36K library |
| Documentation | [Doxygen](https://polarssl.org/api/index.html), [Design page](https://polarssl.org/high-level-design) |
| License | GPL or closed source|
| Feature Description | [webpage](https://polarssl.org/features) |
| Examples | [11k programs directory](https://github.com/polarssl/polarssl/tree/development/programs) |
| Community | [Discussion forum](https://polarssl.org/discussions) |
| Wiki | no |
| Tracker | [tickets](https://polarssl.org/tickets) |
| Support | [Discussion forum](https://polarssl.org/discussions) |
| API Design | [Doxygen](https://polarssl.org/api/index.html) |
| Architecture Specifications | no |
| Design Specifications | no |
| Behavioral Specifications | no |
| Engineering Practices | no global code, loosly coupled, portable, [coding standards](https://polarssl.org/kb/development/polarssl-coding-standards) |
| Tests | [2k of tests](https://polarssl.org/kb/generic/what-tests-and-checks-are-run-for-polarssl) using custom perl harness|
| Other Evidence of Correctness |  |
| Validation | script to compare results with OpenSSL, [used by a number of projects](https://polarssl.org/kb/generic/projects-using-polarssl)|
| Verification | |
| Published Materials | |
| Other Comments | [security center, listing attacks and bugs](https://polarssl.org/security)|

OpenSSL
---------------------------
| | |
|------|----------------|
| Size | 274K C, 70K Perl, 11K asm|
| Age | 1998 - current (6/10/14) |
| Key Metrics | 246K crypto, 20K SSL, 34K apps, 15K engines, 10K demos |
| Documentation | [various documents](http://www.openssl.org/docs/) |
| License | [Apache-style](http://www.openssl.org/source/license.html) |
| Feature Description | SSL, TLS |
| Examples | 10K demos, Numerous examples on the internet|
| Community | [mailing lists](http://www.openssl.org/support/community.html) |
| Wiki | |
| Tracker | [request tracker](http://www.openssl.org/support/rt.html) |
| Support | lists, hire team members |
| API Design | no |
| Architecture Specifications | no |
| Design Specifications | no |
| Behavioral Specifications | no |
| Engineering Practices | none specified |
| Tests | hard to count, scattered through dirs. Handwritten tests for each function |
| Other Evidence of Correctness | widely used and attacked |
| Validation | |
| Verification | |
| Published Materials | |
| Other Comments | |

RELIC
---------------------------
| | |
|------|----------------|
| Size | 60K c, 14K asm |
| Age | 2009-current (as of 6/10/14) |
| Key Metrics |  |
| Documentation | [autogenerated HTML](https://code.google.com/p/relic-toolkit/downloads/detail?name=relic-doc.tar.gz) | 
| License | LGPL |
| Feature Description | Portable, flexible, tests for every implemented function|
| Examples | no |
| Community | [google group](https://groups.google.com/forum/#!forum/relic-discuss) |
| Wiki | [google code](https://code.google.com/p/relic-toolkit/w/list) |
| Tracker | [google code](https://code.google.com/p/relic-toolkit/issues/list) |
| Support | tracker and community |
| API Design | |
| Architecture Specifications | no |
| Design Specifications | no |
| Behavioral Specifications | no |
| Engineering Practices | |
| Tests | 14K C, hand written with randomness|
| Other Evidence of Correctness | no |
| Validation | tests, a few clients [tinyPBC](https://sites.google.com/site/tinypbc/) |
| Verification | no |
| Published Materials | no |
| Other Comments | website says this is alpha-level software|

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


BouncyCastle 1.50 for Java
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

template
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
