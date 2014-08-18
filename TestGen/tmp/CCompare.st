CCompare(libs, funcct, algorithm, testname) ::= <<
void <algorithm>_<testname>(){
	printf("running <algorithm>_<testname>\n");
	int (*funcs[<funcct>])(unsigned char *, unsigned char *, unsigned long long);
	char *reqnames[<funcct>] = {
		<libs : {lib | "output/<algorithm><testname><lib>.rsp"}; separator = ",\n"> 
	};
	<libs: {lib | funcs[<i0>] = <algorithm>_<lib>;}; separator = "\n">
	do_comparison1("../<algorithm><testname>.req", "../<algorithm><testname>_out", funcs, <funcct>, reqnames);
} >>
