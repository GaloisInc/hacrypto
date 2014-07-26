CXCompare(testname, inputsize, input, outputsize, result, funcs) ::= <<
void <testname>(){
	unsigned char input[<inputsize>] = <input>;
	unsigned char result0[<outputsize>] = <result>;
	unsigned char result1[<outputsize>];
	
	<funcs: {func | <CCompare_help(inputsize, outputsize, func, "given answer", testname)>}; separator = "\n">
		
} >>
