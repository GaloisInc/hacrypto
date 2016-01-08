
                                  FourQlib v1.0 (C Edition)
                                  =========================

FourQlib v1.0 library (C Edition) implements essential elliptic curve functions supporting FourQ,
a new, high-security, high-performance elliptic curve that targets the 128-bit security level [1]. 
The library was developed by Microsoft Research for experimentation purposes. 

The library is made available under the MIT License. 


1. CONTENTS:
   --------

Visual Studio/FourQ/            - Folder with Visual Studio 2013 solution and project files 
                                  for compilation in Windows.
Visual Studio/ecc_tests/        - Folder with Visual Studio project files for testing in Windows.
makefile                        - Makefile for compilation using the GNU GCC compiler on Linux. 
*.c                             - Library files.
*.h                             - Header files.  
generic/                        - Folder with library files for portable implementation.
AMD64/                          - Folder with library files for x64 implementation.
README.txt                      - This readme file.


2. MAIN FEATURES:
   -------------
   
- Support for 2 core elliptic curve operations: variable-base scalar multiplication and fixed-base 
  scalar multiplication.
- Support for Windows OS using Microsoft Visual Studio and Linux OS using GNU GCC.    
- Basic implementation of the underlying arithmetic functions using portable C to enable support on
  a wide range of platforms including x64, x86 and ARM. 
- Optimized implementation of the underlying arithmetic functions for x64 platforms with optional, 
  high-performance x64 assembly for Linux.
- Testing and benchmarking code for elliptic curve functions. See ecc_tests.c. 
- All functions evaluating secret data have regular, constant-time execution, protecting against 
  timing and cache attacks.
- Option to disable the use of the fast endomorphisms.


3. SUPPORTED PLATFORMS:
   -------------------

FourQlib v1.0 is supported in a wide range of platforms including x64, x86 and ARM devices running
Windows or Linux OS. We have tested the library with Microsoft Visual Studio 2013 and GNU GCC v4.7 
and v4.8. See instructions below to choose an implementation option and compile on one of the suppor-
ted platforms. 


4. IMPLEMENTATION OPTIONS:
   ----------------------

The following implementation options are available:

- The library contains a portable implementation (enabled by the "GENERIC" option) and an optimized
  x64 implementation. Note that non-x64 platforms are only supported by the generic implementation. 

- Use of special AVX or AVX2 instructions for constant-time table lookups enabled by defining _AVX_ 
  or _AVX2_ (Windows) or by the "AVX" and "AVX2" options (Linux).

- Optimized x64 assembly implementations enabled by the "ASM" option in Linux.

- Use of fast endomorphisms enabled by the "USE_ENDO" option.

Follow the instructions in Section 5 - INSTRUCTIONS FOR WINDOWS OS or Section 6 - "INSTRUCTIONS FOR 
LINUX OS" to configure these different options.


5. INSTRUCTIONS FOR WINDOWS OS:
   ---------------------------

BUILDING THE LIBRARY WITH VISUAL STUDIO:
---------------------------------------

Open the solution file (FourQ.sln) in Visual Studio 2013, select one of the available configurations 
from the Solution Configurations menu ("Release" corresponding to the high-speed x64 implementation 
and "Generic" corresponding to the portable implementation) and select one of the Solution Platforms 
(x64 or Win32). Note that Win32 is only supported with the "Generic" solution configuration.

By default, USE_ENDO=true and (for x64) _AVX_ is defined. To modify this configuration, go to the pro-
perty window of the FourQ project, go to Configuration Properties > C/C++ > Preprocessor. Make any 
suitable changes, e.g., delete _AVX_ if AVX instructions are not supported, replace _AVX_ by _AVX2_ if 
AVX2 instructions are supported, or set USE_ENDO=true or false. Repeat these steps for the ecc_tests 
project.

Finally, select "Build Solution" from the "Build" menu. 

RUNNING THE TESTS:
-----------------

After building the solution, run ecc_tests.exe generated at <LibraryPath>\Visual Studio\FourQ\x64\
<Configuration> for x64 or at <LibraryPath>\Visual Studio\FourQ\Generic for x86.

USING THE LIBRARY:
-----------------

After building the solution, add the FourQ.lib file generated at <LibraryPath>\Visual Studio\FourQ\x64\
<Configuration> for x64 or at <LibraryPath>\Visual Studio\FourQ\Generic for x86 to the set of References 
for a project, and add FourQ.h to the list of Header Files of a project.


6. INSTRUCTIONS FOR LINUX OS:
   -------------------------

BUILDING THE LIBRARY AND EXECUTING THE TESTS WITH GNU GCC COMPILER:
------------------------------------------------------------------

To compile on Linux using the GNU GCC compiler, execute the following command from the command prompt:

make ARCH=[x64/x86/ARM] ASM=[TRUE/FALSE] AVX=[TRUE/FALSE] AVX2=[TRUE/FALSE] USE_ENDO=[TRUE/FALSE] GENERIC=[TRUE/FALSE]

After compilation, run ecc_tests.

For example, to compile the fully optimized x64 implementation in assembly using the efficient endomor-
phisms on a machine with AVX2 support (e.g, Intel's Haswell), execute:

make ARCH=x64 ASM=TRUE AVX2=TRUE USE_ENDO=TRUE

Whenever an unsupported configuration is applied, the following message will be displayed: #error -- 
"Unsupported configuration". For example, the use of assembly or any of the AVX options is not suppor-
ted when selecting the portable implementation (i.e., if GENERIC=TRUE). Similarly, x86 and ARM are only 
supported when GENERIC=TRUE.  


REFERENCES:
----------

[1]   Craig Costello and Patrick Longa. 
      FourQ: four-dimensional decompositions on a Q-curve over the Mersenne prime.
      Advances in Cryptology - ASIACRYPT 2015 (to appear), 2015. 
      Extended version available at: http://eprint.iacr.org/2015/565.
 
