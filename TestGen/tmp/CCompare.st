CCompare(testname, inputsize, input, outputsize, firstfunc, funcs) ::= <<
void <testname>(){
	unsigned char input[<inputsize>] = <input>;
	unsigned char result0[<outputsize>];
	unsigned char result1[<outputsize>];
	
	<firstfunc>(input, result0, <inputsize>);
	
	<funcs: {func | <CCompare_help(inputsize, outputsize, func, firstfunc, testname)>}; separator = "\n">
		
} >>
