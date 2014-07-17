#VST SHA256 Verification

This is a full verification of SHA256 in Coq using the [VST](http://vst.cs.princeton.edu/) framework.
A macro-expanded SHA256 reference implementation from [OpenSSL](http://www.openssl.org/) is verified 
with respect to a functional implementation of the same function. This guarantees safety and correctness
w.r.t the Coq spec when the program is compiled by [CompCert](http://compcert.inria.fr/)