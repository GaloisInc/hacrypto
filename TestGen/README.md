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

	<algorithm> <test type> <arguments>

specifying the algorithm names as they are referred to in the C code, a test type such as
file or KAT, and any arguments that are associated with that test type. At the end of the
file there should be a line:

	Languages <language1> <language2> ...
	
Specifying the language that harnesses for the tests should be generated in. Each of these
will need to correspond with a <langauge>_tests file.
	

	 
    
### Language_tests
The Language_tests file has the following form

	<include1> <include2> ...
	<compiler args>
	<algorithm> <implementation1> <implementation2> ...
	
  * __includes__, separated by spaces, should be .h files specifying functions that
    will be called by the tests. These function must have names `<primitive name>`_`<implementation>`
    and match APIs given 
  * __Complier args__ will be passed to the compiler by the makefile. These might be -l arguments
    that point to the libraries being tested
  * __algorithm__ matches an algorithm name from the test file
  * __implementation__ are the names of each implementation you wish to test. These must
    match the function names you are importing


### Test definition files

The test definition files allow specification of the NIST tests for FIPS. An annoted
test definition for AES follows. Line order does not matter:

	#the number of inputs
	inputs = 4

	# each input must be specified with a 0 indexed name index<indexnumber>
	# the name property specifies the name that will be given in the .req file
	# this test will be printed in the req file as "COUNT = ..."
	input0_name = COUNT
	
	# the input type count is a counter that increases for each tests
	input0_type = COUNT
	
	# If a max is given, the counter will restart to the given minimum
	# after it prints the max. All values default to 0 if they aren't given
	# this is the case for input_0 min in this case
	input0_max = 9
	
	input1_name = KEY
	# a random input is given a length and an optional count and will generate
	# random hex strings until the count is reached. If no count is given it
	# will generate random strings until another input runs out.	
	input1_type = random
	# if min and max length are the same, all inputs will have the same length
	input1_minlength = 128 
	input1_maxlength = 128
	
	input2_name = IV
	input2_type = random
	input2_minlength = 128
	input2_maxlength = 128
	
	# mult means there are multiple inputs. They will be used in order, switching to the next
	# when the current one is finished
	input3_mult = 2
	# the multiple input is specified with a 0 indexed integer trailing the propety name
	input3_name0 = PLAINTEXT
	# increase gives a random input with a size that increases by a fixed length
	input3_type0 = increase
	input3_minlength0 = 128
	input3_maxlength0 = 1280
	input3_stepsize0 = 128 
	
	#input3_1 will be used when input3_0 is finished
	input3_name1 = CYPHERTEXT
	input3_type1 = increase
	input3_minlength1 = 128
	input3_maxlength1 = 1280
	input3_stepsize1 = 128 
	
	# there can be one output at a time for any test
	output0_name = CYPHERTEXT
	# this specifies the input that this output ends with... output 1 begins after it
	# so we will switch outputs when input3_0 switches to input3_1
	output0_end = 3
	# args gives the count of arguments 
	output0_args = 3
	# this specifies the order of arguments as they are given to the java function.
	# in this case arg 1 (the second argument) is given as the first argument to
	# the Java implementation of AES
	output0_arg0 = 1
	output0_arg1 = 2
	output0_arg2 = 3
	# the function name as defined in req.Output.java
	output0_function = AES/CBC/ENC
	
	output1_name = PLAINTEXT
	output1_args = 3
	output1_arg0 = 1
	output1_arg1 = 2
	output1_arg2 = 3
	output1_function = AES/CBC/DEC

More example files can be found in the test_defs folder

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
