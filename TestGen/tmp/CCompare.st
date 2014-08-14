CCompare(funcs, funcct, algorithm, testname) ::= <<
void <algorithm>_<testname>(){
	printf("running <algorithm>_<testname>\n");
	int (*funcs[<funcct>])(unsigned char *, unsigned char *, unsigned long long);
		
		<funcs: {func | funcs[<i0>] = <func>;}; separator = "\n">
		do_comparison1("../<algorithm><testname>.req", "../<algorithm><testname>_out", funcs, <funcct>);
} >>
