CKAT(testname, inputsize, input, outputsize, answer, func, repeat) ::= <<
<testname>(){
	unsigned char input[<inputsize>] = <input>;
	<repeat>
	unsigned char result[<outputsize>];
	unsigned char expected_result[<outputsize>] = {
	<answer>
	};
	
	<func>(input, result, <inputsize>);
	check_KAT(result, expected_result, <outputsize>, "<testname>");
	
} >>