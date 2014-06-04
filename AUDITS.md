High-level Quality Audits of Crypto Libraries
=============================================

##### Joe Kiniry and Joey Dodds, Galois

Relevant Libraries
------------------

| Name              | Site                                   | PL   | Status   |
| BouncyCastle 1.50 | https://www.bouncycastle.org/java.html | Java | Complete |
| BouncyCastle 1.7  | http://www.bouncycastle.org/csharp/    | C#   | Ongoing  |
| OpenSSL           |                                        | C    | Ongoing  |
| NaCl              |                                        | C    | Ongoing  |
| Nettle            |                                        | C    | Ongoing  |

BouncyCastle 1.50 for Java, 
---------------------------

| Size | 448K of Java |
| Age | under development from 2000-2014 |
| Key Metrics | core is 128K, 84 packages, and 1125 classes (128K/84/1125); provider is 57K/41/963; mail is 5K/5/53; pg is 18K/9/171; pkix 28K/32/436 |
| Documentation | release notes, high-level specification, API docs |
| License | MIT X Consortium (mostly) |
| Feature Description | provided at a high-level in a [specifications document](https://www.bouncycastle.org/specifications.html) |
| Examples | provided via unit tests and discussed on StackExchance frequently |
| Community | developer and announce [mailing lists](https://www.bouncycastle.org/mailing_lists.html) |
| Wiki | JIRA wiki unavailable as of 4 June 2014 |
| Tracker | JIRA tracker unavailable as of 4 June 2014 and poorly updated when live |
| Support | Legion of the Bouncy Castle is an NGO and [Crypto Workshop](http://www.cryptoworkshop.com/) is a for-profit company consultancy work |
| API Design | has both a lightweight API and a JCE provider |
| Architecture Spec | N/A |
| Design Spec | N/A |
| Engineering Practices | lightweight coding standard, hand-written unit tests, conformance to open API as facade for lightweight internal API |
| Tests | 99K of JUnit test code; core/provider/mail/pg/pkix test count 238/37/131/42/216 for a total of 664 tests |
| Other Evidence of Correctness | handful of assertions in J2ME version of core |
| Validation | moderate manual testing focusing on hand-identified scenarios and published test vectors; enormous number of clients |
| Verification | N/A |
| Published Materials | [Oracle's Java Cryptography Extensions Architecture (JCE)](http://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html), [several books have been published about the JCE](http://www.amazon.com/s/ref=nb_sb_noss?url=search-alias%3Daps&field-keywords=Java%20cryptography) |
| Other Comments | Conforms to JCE |

BouncyCastle 1.7 for C#, 7 April 2011
-------------------------------------


