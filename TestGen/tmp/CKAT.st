CKAT(testname, inputsize, input, outputsize, answer, func, repeat, malloc, comment) ::= <<
<if(comment)>
// <comment>
<else>
<endif>
<testname>(){
    <if (malloc)>
    unsigned char *input = malloc(sizeof(char) * <inputsize>);
    <else>
	unsigned char input[<inputsize>] = <input>;
	<endif>
	<repeat>
	unsigned char result[<outputsize>];
	unsigned char expected_result[<outputsize>] = {
	<answer>
	};
	
	<func>(input, result, <inputsize>);
	check_KAT(result, expected_result, <outputsize>, "<testname>");
	
} >>