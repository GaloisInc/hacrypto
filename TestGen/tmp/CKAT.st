CKAT(testname, inputsize, input, outputsize, answer, func) ::= <<
<testname>(){
	unsigned char input[<inputsize>] = <input>;
	unsigned char result[<outputsize>];
	unsigned char expected_result[<outputsize>] = {
	<answer>
	};
	
	<func>(input, result, <inputsize>);
	check_KAT(result, expected_result, <outputsize>, "<testname>");
	
} >>