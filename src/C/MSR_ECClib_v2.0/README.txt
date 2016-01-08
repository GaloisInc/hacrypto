                                 MSR ECCLib v2.0 (C Edition)
                                 ===========================

The MSR ECCLib v2.0 library (C Edition) implements essential elliptic curve functions supporting 
the NUMS ("Nothing Up My Sleeve") curves [NUMS]. These curves were obtained using a very simple 
and deterministic generation procedure with minimal room for parameter manipulation. The library 
was developed by Microsoft Research for experimentation purposes. 

The library is made available under the MIT License. 


1. CONTENTS:
   --------

MSR_ECClib_v2.0.sln    - Visual Studio 2013 solution file for compilation in Windows
makefile               - Makefile for compilation using the GNU GCC compiler for x64 platforms on
                         Linux 
makefile_x86           - Makefile for compilation using the GNU GCC compiler for x86 platforms on
                         Linux
makefile_arm           - Makefile for compilation using the GNU GCC compiler for ARM platforms on
                         Linux
MSR_ECClib/            - Library project directory
Sample/                - Sample project
Tests/                 - Test projects (crypto_tests, ecc_tests and fp_tests)
README.txt             - This readme file


2. MAIN FEATURES:
   -------------
   
- Support for 6 curves covering 3 security levels (128, 192 and 256 bits): 
     * Curves numsp256d1, numsp384d1 and numsp512d1 in Weierstrass form with curve parameter a=-3.
     * Curves numsp256t1, numsp384t1 and numsp512t1 in twisted Edwards form with curve parameter a=1.
  See [NUMS] for complete details.
- Support for 3 core elliptic curve operations: variable-base scalar multiplication, fixed-base 
  scalar multiplication and double scalar multiplication.
- Support for Windows OS using Microsoft Visual Studio and Linux OS using GNU GCC.    
- Generic implementations of the underlying arithmetic functions to enable support on a wide range
  of platforms including x64, x86 and ARM. The different C implementations are based on generic C,
  extended types (Linux) and intrinsics (Windows).
- Optimized implementations of the underlying arithmetic functions for x64 platforms using assembly
  language.  
- Testing and benchmarking code for elliptic curve and field arithmetic functions. See ecc_tests.c 
  and fp_tests.c.
- API for ECDSA and ephemeral elliptic curve Diffie-Hellman key exchange (ECDHE). See msr_ecclib.h 
  and ecc_crypto.c.
- Sample code and testing/benchmarking code for ECDSA and ECDH. See sample.c and crypto_tests.c.
- All functions evaluating secret data have regular, constant-time execution, protecting against 
  timing and cache attacks.

2.1. NEW FEATURES IN VERSION 2.0: 

Based on feedback received, MSR ECCLib v2.0 replaces the original twisted Edwards curves that were 
proposed in [ECC15] by new twisted Edwards curves with a complete addition law. See [NUMS] for full 
details. 


3. SUPPORTED PLATFORMS:
   -------------------

MSR ECCLib v2.0 is supported in a wide range of platforms including x64, x86 and ARM devices running
Windows or Linux OS. We have tested the library with Microsoft Visual Studio 2013 and GNU GCC v4.7 and 
v4.8. See instructions below to choose an implementation option and compile on one of the supported 
platforms. 


4. CHOOSING AN IMPLEMENTATION OPTION:
   ---------------------------------

The library provides 2 preprocessor macros to choose an implementation option: TARGET_GENERIC and
USE_ASM. These macros can be given value "1" (ON) or "0" (OFF). To modify the default configuration:

- For Visual Studio in Windows, (after opening MSR_ECClib_v1.2a.sln and choosing a platform - see 
  "Building the Library with Visual Studio" below) go to the property window of the MSR_ECClib project,
  go to Configuration Properties > C/C++ > Preprocessor. Make any suitable changes to the values of
  TARGET_GENERIC and USE_ASM in the Preprocessor Definitions entry. 

- For GNU GCC in Linux, look for the CFLAGS definition in the makefile corresponding to the targeted
  platform (see "Building the Library and Executing the Tests with GNU GCC Compiler" below). Make any
  suitable changes to the values of TARGET_GENERIC and USE_ASM.

When TARGET_GENERIC is set, an architecture-independent C implementation of the arithmetic is used.
This option overrides any selection in USE_ASM. That is, to use the assembly implementation of the 
field arithmetic, USE_ASM must be set to "1" and TARGET_GENERIC must be set to "0" (note that some  
other functions are only available in C, such as arithmetic modulo the order). As per version 1.2, 
USE_ASM is only available for x64 platforms. 
If TARGET_GENERIC=0 (and USE_ASM=0 in x64): in Windows, the intrinsics-based implementation is used;
in Linux, the implementation with extended types (128-bit integer datatype for x64 and 64-bit integer
datatype for x86/ARM) is used.

Out-of-the-box, the library is compiled with TARGET_GENERIC set to "0". In addition, for x64, USE_ASM
is set to "1".


5. INSTRUCTIONS FOR WINDOWS OS:
   ---------------------------

BUILDING THE LIBRARY WITH VISUAL STUDIO:
---------------------------------------

Open the solution file (MSR_ECClib_v2.0.sln) in Visual Studio 2013, select one of the supported
platforms as Platform, select "Release" as configuration option, (if needed) change the default 
implementation option (see Section 4), and select "Build Solution" from the "Build" menu. Available
options for Platform are: x64, x86 and ARM.

(**) Common error in Visual Studio: Visual Studio can compile multiple projects at once. Since the 
projects in this release share files, the compiler might produce an error if attempts to reference 
the same file at the same time.

Solution: configure Visual Studio to set the maximum number of parallel builds to only one: go to
Tools > Options > Projects and Solutions > Build and Run, and set the maximum number of 
parallel project builds to 1. 

RUNNING THE TESTS:
-----------------

After building the solution file, run crypto_tests.exe, ecc_tests.exe and fp_tests.exe generated
at <LibraryPath>\<Platform>\Release\crypto_tests\, <LibraryPath>\<Platform>\Release\ecc_tests\ and 
<LibraryPath>\<Platform>\Release\fp_tests\, respectively, from the command prompt.

RUNNING THE SAMPLE CODE:
-----------------------

After building the solution file, run sample.exe generated at <LibraryPath>\<Platform>\Release\sample\ 
from the command prompt. Follow the sample project and the code in <LibraryPath>\Sample\sample.c 
as an example of the use of the library.

USING THE LIBRARY:
-----------------

After building the solution file, add the MSR_ECClib_v2.0.lib file generated at <LibraryPath>\<Platform>\
Release\ to the set of References for a project, and add msr_ecclib.h located at <LibraryPath>\MSR_ECClib\ 
to the list of Header Files of a project.

PLATFORMS WITH NO AVX SUPPORT:
-----------------------------

Before building and for each project in the solution (crypto_tests, ecc_tests, fp_tests, MSR_ECClib
and sample), open the project property window, go to Configuration Properties > C/C++ > Preprocessor.
Delete "_AVX_" from the Preprocessor Definitions entry. Proceed to build following the instructions
above. These instructions do not apply to ARM. 


6. INSTRUCTIONS FOR LINUX OS:
   -------------------------

BUILDING THE LIBRARY AND EXECUTING THE TESTS WITH GNU GCC COMPILER:
------------------------------------------------------------------

First, (if needed) change the default implementation option in the targeted makefile (see Section 4).
Open a terminal and execute "make <module> -f <makefile>" from the library path, where module can be 
crypto_tests, ecc_tests, fp_tests or sample (if "module" is not given any entry, crypto_tests is 
compiled by default), and <makefile> can be makefile (intended for x64), makefile_x86 and makefile_arm
(if the -f option is not used, makefile is used by default). Then, run any of the generated executables.
Executing "make clean" deletes all generated object and executable files. 
Follow the sample code in <LibraryPath>\Sample\sample.c as an example of the use of the library.

PLATFORMS WITH NO AVX SUPPORT:
-----------------------------

Before running "make", open for editing the makefile corresponding to the targeted platform (located in
<LibraryPath>) and delete "_AVX_" from the preprocessor definitions in the CFLAGS macro. Proceed to
build following the instructions above. 
These instructions do not apply to ARM. 


REFERENCES:
----------

[ECC15]   Joppe W. Bos and Craig Costello and Patrick Longa and Michael Naehrig. 
          Selecting Elliptic Curves for Cryptography: An Efficiency and Security Analysis.
          Journal of Cryptographic Engineering (to appear), 2015. 
          Available at: http://eprint.iacr.org/2014/130.

[NUMS]    Joppe W. Bos and Craig Costello and Patrick Longa and Michael Naehrig.
          Specification of Curve Selection and Supported Curve Parameters in MSR ECCLib. 
          Tech Report no. MSR-TR-2014-92, June 2015. 
          http://research.microsoft.com/apps/pubs/default.aspx?id=219966.