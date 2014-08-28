#Test Generation for cryptographic primitives

This project generates NIST style tests for CAVP certification. It takes in
a particular file format (in the [test_defs](test_defs) folder) and outputs
a .req and a .rsp file containing the input and output file for the test. 


## How to generate tests

Load the project up in eclipse. It is a standalone project, so you will
need to create a workspace and then import it as an existing project. In order
to enable many of the algorithms we need you must also install 
[Unlimited strength policies](http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html)
to your JRE.

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

##How Test Definitions work
Test definitions appear as a series of key value equalities. 
There must always be a definition

	inputs = <inputCt> 

where inputCt gives the number of inputs that are declared. The definitions take the form

input<n>_<property><m> = <value>

- **n** gives the number of the test. These range from 0 .. inputCt-1
- **property** can have a variety of values. These are mentioned in the Test Types section
- **m** some inputs are made up of multiple inputs. If this is the case m is given to specify which of them this input refers to
- **value** possible values are discussed along with their properties in the next section.

An input can be either finite or infinite. Inputs will continue to be generated until some finite input finishes. For inputs
made of multiple other inputs, once the current input runs out, the next one will be used.

##Test types

This is a list of the available test types and their properties. Any integer values default to 0.
input types appear with a definition input<n>_type. All
inputs have the **name** property which gives the name that will be printed before the input
in the output files. Unless specified all lengths are given in bits

- **length** prints the length of another argument. That argument must be a byte string
	* **lengthof** gives the number of the input that this length input prints the length of
	  so if we want the length of an input ```input0_type =...``` we would write ```lengthof = 0```
	* **unit** can be used to specify that the length should be printed in bytes with ```unit = bytes```	

- **random** prints a random byte string in hex.
	* **minlength** minimum length of the generated string
	* **maxlength** maximum length of the generated string. If this is less than minlength all generates strings
	  will be of length minLength
	* **ct** number of tests to create. If 0 is given an unlimited number of tests will be generated

- **increase** prints random byte strings of increasing length
	* **minlength** length to start generating at
	* **maxlength** maximum length of the generated string. If a string would be longer, it will start back at minlength
	* **stepsize** how many bits to increase the size of each output by

- **randomsequence** prints a random byte string of length defined by an integer sequence
	* **sequence** takes the form [<i1>, <i2>, ..., <in>] and specifies a sequence of lengths in bits
	* **repeat** number of times to repeat the sequence. A value of 0 will repeat forever
	* **changeEvery** how many outputs to print before changing to the next length in the sequence 

- **count** increasing integers
	* **min** where to start the count
	* **max** the count will be modulo the max
	
- **rngv** a special input used to generate the V value for the RNG test

- **fixed** generates a byte value that changes by incrementing (possibly by 0)
	* **number** number of inputs to generate. 0 means unlimited
	* **value** specifies the starting value as a hex string. If no value is given you must specify length
	* **length** optional if value is specified. The length of the input. If no value has been specified a random value of this length will be generated
	* **increment** a base 10 integer specifying how much to increment the hex string by each time. Increment treats the byte string as big-endian

- **sequence** a sequence of integers
	* **values** the sequence of integer values to print. takes the form [<i1>, <i2>, ..., <in>]
	* **repeat** number of times to repeat the sequence. A value of 0 will repeat forever
	* **changeEvery** how many inputs to print before changing to the next value in the sequence

##Outputs
Multiple outputs can be specified per file, but only one is generated at a time. An output can be linked to an input and when that input is finished, the output
will change to the next one as well. An output also specifies the order that arguments should be given to the java implementation of the function.

outputs have the followint properties

- **name** like name for inputs. Printed before the output in the .rsp file
- **args** the number of arguments given to the output function
- **arg<n>** for n=0..args-1 the input number to be given as the nth input the the Java function specified by the output
- **function** the function to use for the output. The current list of functions follows.

The functions that can currently be used are as follows

-SHA1 
-SHA256 
-SHA224 
-SHA384 
-SHA512 
-AES/CBC/ENC
-AES/CBC/DEC 
-AES/CFB128/ENC 
-AES/CFB128/DEC 
-AES/CFB8/ENC 
-AES/CFB8/DEC
-AES/ECB/ENC 
-AES/ECB/DEC 
-AES/OFB/ENC 
-AES/OFB/DEC
-RNG/AES
-HMAC

##Example file

The test definition files allow specification of the NIST tests for FIPS. An annotated
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

The output is a directory containing
   * A directory called req and a directory called rsp. These contain the generated test files with names matching the input files that specify them
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
