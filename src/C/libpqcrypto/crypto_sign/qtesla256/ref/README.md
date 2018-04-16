# Reference implementation for qTESLA-256

Compile:

make

it generates two executable "test\_qtesla" and "PQCgenKAT\_sign":

To report cycle counts that spend during Key generation, Signature generation and
Verification:

./test\_qtesla

To generate new KAT files:

./PQCgenKAT\_sign


Testing pregenerated KAT files:

make testKATs

This make rule compile a program which run the signature scheme with seeds
from proper file in KAT directory, and checks if pregenerated values can be
obtained. It prints out an error message if there is any inconsistency.



