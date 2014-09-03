#Test Generation for cryptographic primitives

This project generates NIST style tests for CAVP certification. It takes in
a particular file format (in the [test_defs](test_defs) folder) and outputs
a .req and a .rsp file containing the input and output file for the test. 


## How to generate tests

Load the project up in eclipse. It is a standalone project, so you will
need to create a workspace and then import it as an existing project.

Example test definition files are  in the [test_defs](test_defs) folder. 
Running the "Test" configuration an output folder in the callsha directory.
The output directory can be modified by altering the definition of "main" in
hacrypto.Test.java 

To define tests you must create

  * A file called tests that specifies where the test files will be found
  * Test files, possibly in subdirectories of the following form
  
### Test file

The test file has a number of lines of the form:

	<Algorithm> <Test Type> <Arguments>

specifying the algorithm names as they are referred to in the C code, a test type such as
file or KAT, and any arguments that are associated  
followed by a line

	Languages <languages>
	

	 
    
### C_tests
The C_tests file has the following form

	<Language>
	<include1> <include2> ...
	<compiler args>
	<primitive name> KAT <implementation1> <implementation2> ...
	<primitive name> Compare <output size (bytes)> <min input size> <max output size> <number of tests> <implementations>
	
  * __Languages__ can only be C for now
  * __includes__, separated by spaces, should be .h files specifying functions that
    will be called by the tests. These function must have names `<primitive name>`_`<implementation>`
    and match APIs given 
  * __Complier args__ will be passed to the compiler by the makefile. These might be -l arguments
    that point to the libraries being tested
  * __primitive name__ must match the primitive name on the functions being called
  * __implementation__ are the names of each implementation you wish to test. These must
    match the function names you are importing

### KAT file
   
If you have defined a KAT in the C_tests file, you must also create a file
containing input/output pairs. This file should be named `<primitive>`_KAT. and
has the form

	<input0>
	!!! <output0>
	<input1>
	!!! <output1>
	
where the inputs are strings, possibly over multiple lines (line breaks will be replaced with \n)
and the outputs are the hexidecimal representation of the expected output. You must provide a space
between the !!! and the `<output>`

##Generated tests

The output is a directory (currently only inside of callsha) containing
   * One file `<primitive>`_`<implementation>`_KAT.c for each primitive/implementation
     being tested with KAT
   * One file `<primitive>`_compare.c for each primitive with a comparison test
   * A Makefile that will build all the files in the directory
   * A header, tests.h containing the names of all tests in all files generated
   * run_tests.c which contains an entry point that runs each test
   
To build and run the tests
	make
	./tests(.exe)

The tests currently succeed silently, and print out a message on failure. No output
means that all tests worked successfully.



	 * # comments appear on lines beginning with #
	 * # number of inputs given in this file
	 * inputs = 1
	 * 
	 * # each input gets a name input/<number/> and has properties specified after and _
	 * # the name is what appears in the req file
	 * input0_name = COUNT
	 * # type can be count, random, length, or increase
	 * # count is a conter that increases by one each test
	 * input0_type = count
	 * # max is a property for count that specifies a modulus for the counting
	 * input0_max = 9
	 * 
	 * input1_name = KEY
	 * input1_type = random
input1_minlength = 128 
input1_maxlength = 128

input2_name = IV
input2_type = random
input2_minlength = 128
input2_maxlength = 128

#mult means there are multiple inputs. Each of the inputs needs to be finite
input3_mult = 2
input3_name0 = PLAINTEXT
input3_type0 = increase
input3_minlength0 = 128
input3_maxlength0 = 1280
input3_stepsize0 = 128 

input3_name1 = CIPHERTEXT
input3_type1 = increase
input3_minlength1 = 128
input3_maxlength1 = 1280
input3_stepsize1 = 128 

output0_name = CIPHERTEXT
#this specifies the input that this output ends on... output 1 begins after it
output0_end = 3
output0_args = 3
output0_arg0 = 1
output0_arg1 = 2
output0_arg2 = 3
output0_function = AES/CBC/ENC

output1_name = PLAINTEXT
output1_args = 3
output1_arg0 = 1
output1_arg1 = 2
output1_arg2 = 3
output1_function = AES/CBC/DEC

