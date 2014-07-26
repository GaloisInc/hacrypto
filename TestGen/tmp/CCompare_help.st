CCompare_help(inputsize, outputsize, func, firstfunc, testname) ::= <<
memset(result1, 0, <outputsize>);
<func>(input, result1, <inputsize>);
check_test(result0, result1, <outputsize>, "Disagreement between <firstfunc> and <func> in <testname>\n");

>>