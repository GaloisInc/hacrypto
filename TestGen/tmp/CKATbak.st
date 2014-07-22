CKAT(testname, inputsize, input, outputsize, answer, funcs) ::= <<
<testname>(){
	unsigned char input[<inputsize>] = "<input>";
	unsigned char result[<outputsize>];
	unsigned char expected_result[<outputsize>] = {
	<answer>
	};
	
	<funcs:{func | <func>(input, result, <inputsize>);}; separator = "\n">
	
	check_KAT(result, expected_result, <outputsize>, "<testname>");
} >>