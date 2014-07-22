CKAT_check(func, inputsize, outputsize, testname) ::= <<
<func>(input, result, <inputsize>);
check_Kat(result, expected_result, <outputsize>, "<testname>_<func>");
>>

CKAT(testname, inputsize, input, outputsize, answer, funcs) ::= <<
<testname>(){
	unsigned char input[<inputsize>] = "<input>";
	unsigned char result[<outputsize>];
	unsigned char expected_result[<outputsize>] = {
	<answer>
	};
	

	<funcs: {func | <CKAT_check(func, inputsize, outputsize, testname)>}; separator = "\n\n">
	
} >>