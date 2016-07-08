                                 LatticeCrypto v1.0 (C Edition)
                                 ==============================

LatticeCrypto is a post-quantum secure cryptography library based on the Ring-Learning with Errors (R-LWE) 
problem. The version 1.0 of the library implements the instantiation of Peikert's key exchange [1] due to 
Alkim, Ducas, Pöppelmann and Schwabe [2], and incorporates novel techniques to provide higher performance.

The library was developed by Microsoft Research for experimentation purposes. 


1. CONTENTS:
   --------

Visual Studio/LatticeCrypto/LatticeCrypto.sln  - Visual Studio 2013 solution file for compilation in Windows
Visual Studio/tests/                           - Test project
makefile                                       - Makefile for compilation using the GNU GCC or clang compilers
                                                 on Linux 
/                                              - Library C and header files                                     
AMD64/                                         - Optimized implementation of the NTT for x64 platforms
generic/                                       - Implementation of the NTT in portable C
tests/                                         - Test files
README.txt                                     - This readme file


2. MAIN FEATURES:
   -------------
   
- Support arithmetic functions for computations in power-of-2 cyclotomic rings that are the basis for 
  implementing Ring-LWE-based cryptographic algorithms.
- Support key exchange providing at least 128 bits of quantum and classical security.
- All functions evaluating secret data have regular, constant-time execution, which provides protection 
  against timing and cache attacks.
- Support for Windows OS using Microsoft Visual Studio and Linux OS using GNU GCC and clang.     
- Basic implementation of the underlying arithmetic functions using portable C to enable support on
  a wide range of platforms including x64, x86 and ARM.  
- Optional high-performance implementation of the underlying arithmetic functions for x64 platforms on
  Linux using assembly and AVX2 vector instructions.
- Testing and benchmarking code for the Number Theoretic Transform (NTT) and key exchange. See tests.c.


3. SUPPORTED PLATFORMS:
   -------------------

LatticeCrypto v1.0 is supported on a wide range of platforms including x64, x86 and ARM devices running
Windows or Linux OS. We have tested the library with Microsoft Visual Studio 2013 and 2015, GNU GCC v4.7, 
v4.8 and v4.9, and clang v3.6 and v3.7. See instructions below to choose an implementation option and 
compile on one of the supported platforms.


4. USER-PROVIDED FUNCTIONS:
   -----------------------

LatticeCrypto requires the user to provide three functions to compute a key exchange: 

- a pseudo-random generation function that generates seeds (passed as octets) which are used for the 
  generation of private keys and error polynomials,
- an extendable output function that receives a seed and outputs n elements in the range [0, PARAMETER_Q)
  (passed as 32-bit digits), and
- a stream cipher function (e.g., AES-CTR) that generates random values (passed as octets) used during 
  generation of error polynomials and the reconciliation.

See random.c for additional details about the use of these functions. These functions should be provided 
to the function LatticeCrypto_initialize() during initialization. Follow tests.c (see kex_test()) as an 
example on how to perform this initialization. 

(Unsafe) example functions are provided in test_extras.c for testing purposes (see random_bytes_test(),
extendable_output_test() and stream_output_test()). NOTE THAT THIS SHOULD NOT BE USED IN PRODUCTION CODE.

Finally, the outputs of the shared key functions are not processed by a key derivation function (e.g., 
a hash). The user is responsible for post-processing to derive cryptographic keys from the shared secret 
(e.g., see NIST Special Publication 800-108).   


5. IMPLEMENTATION OPTIONS:
   ----------------------

The following implementation options are available:

- The library contains a portable implementation (enabled by the "GENERIC" option) and an optimized
  x64 implementation. Note that non-x64 platforms are only supported by the generic implementation. 

- Optimized x64 assembly implementation based on AVX2 vector instructions enabled by the "ASM" and 
  "AVX2" options in Linux.

Follow the instructions in Section 6 - INSTRUCTIONS FOR WINDOWS OS or Section 7 - "INSTRUCTIONS FOR 
LINUX OS" to configure these different options.    


6. INSTRUCTIONS FOR WINDOWS OS:
   ---------------------------

BUILDING THE LIBRARY WITH VISUAL STUDIO:
---------------------------------------

Open the solution file (LatticeCrypto.sln) in Visual Studio, and select one of the supported platforms
as Platform. Then choose "Generic" from the configuration menu.

Finally, select "Build Solution" from the "Build" menu. 

RUNNING THE TESTS:
-----------------

After building the solution file, there should be an executable file available: tests.exe, to run tests 
for the NTT and the key exchange. 

USING THE LIBRARY:
-----------------

After building the solution file, add the generated LatticeCrypto.lib file to the set of References for 
a project, and add LatticeCrypto.h to the list of Header Files of a project.


7. INSTRUCTIONS FOR LINUX OS:
   -------------------------

BUILDING THE LIBRARY AND EXECUTING THE TESTS WITH GNU GCC OR CLANG:
------------------------------------------------------------------

To compile on Linux using GNU GCC or clang, execute the following command:

make ARCH=[x64/x86/ARM] CC=[gcc/clang] ASM=[TRUE/FALSE] AVX2=[TRUE/FALSE] GENERIC=[TRUE/FALSE]

After compilation, run test.

For example, to compile the key exchange tests using clang and the fully optimized x64 implementation 
in assembly, execute:

make CC=clang ARCH=x64 ASM=TRUE AVX2=TRUE

Whenever an unsupported configuration is applied, the following message will be displayed: #error -- 
"Unsupported configuration". For example, the use of the fast AVX2 assembly implementation (ASM=TRUE
and AVX2=TRUE) is not supported when selecting the portable implementation (i.e., if GENERIC=TRUE). 
Similarly, x86 and ARM are only supported when GENERIC=TRUE.


REFERENCES
----------

[1] C. Peikert, "Lattice cryptography for the internet", in Post-Quantum Cryptography - 6th International 
    Workshop (PQCrypto 2014), LNCS 8772, pp. 197-219. Springer, 2014.
[2] E. Alkim, L. Ducas, T. Pöppelmann and P. Schwabe, "Post-quantum key exchange - a new hope", IACR Cryp-
    tology ePrint Archive, Report 2015/1092, 2015.