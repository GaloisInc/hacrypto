#Test Generation for cryptographic primitives

This Java project automatically generates tests given minimal
user input. There are two types of tests available: Known Answer
Tests (KAT) where the user gives input/output pairs, and comparison
tests, where random inputs are generated and the outputs of
each implementation are checked against each other.


## How to generate tests

Load the project up in eclipse. Example test definition files are 
in the [test_defs](test_defs) folder. Running the project in the 
state it is provided in the repository will create a test folder 
in the callsha directory. To define tests you must create

  * A file called C_tests, defining which tests to run.
  * A file called <primitive>_KAT where primitive is the primitive you are
    providing inputs and outputs for.
    
### C_tests
The C_tests file has the following form

	<Language>
	<include1> <include2> ...
	<compiler args>
	<primitive name> KAT <implementation1> <implementation2> ...
	<primitive name> Compare <output size (bytes)> <min input size> <max output size> <number of tests> <implementations>
	
  * __Languages__ can only be C for now
  * __includes__, separated by spaces, should be .h files specifying functions that
    will be called by the tests. These function must have names <primitive name>_<implementation>
    and match APIs given <!--TODO link to the APIs -->
  * __Complier args__ will be passed to the compiler by the makefile. These might be -l arguments
    that point to the libraries being tested
  * __primitive name__ must match the primitive name on the functions being called
  * __implementation__ are the names of each implementation you wish to test. These must
    match the function names you are importing

### KAT file
   
If you have defined a KAT in the C_tests file, you must also create a file
containing input/output pairs. This file should be named <primitive>_KAT. and
has the form

	<input0>
	!!! <output0>
	<input1>
	!!! <output1>
	
where the inputs are strings, possibly over multiple lines (line breaks will be replaced with \n)
and the outputs are the hexidecimal representation of the expected output. You must provide a space
between the !!! and the <output>

##Generated tests

The output is a directory (currently only inside of callsha) containing
   * One file <primitive>_<implementation>_KAT.c for each primitive/implementation
     being tested with KAT
   * One file <primitive>_compare.c for each primitive with a comparison test
   * A Makefile that will build all the files in the directory
   * A header, tests.h containing the names of all tests in all files generated
   * run_tests.c which contains an entry point that runs each test
   
To build and run the tests
	make
	./tests(.exe)

The tests currently succeed silently, and print out a message on failure. No output
means that all tests worked successfully.