CCompare(funcs, funcct, algorithm) ::= <<
void <algorithm>_compare(){
	int (*funcs[<funcct>])(unsigned char *, unsigned char *, unsigned long long);
		
		<funcs: {func | funcs[<i0>] = <func>;}; separator = "\n">
		do_comparison1("../<algorithm>_compare_in", "../<algorithm>_compare_out", funcs, <funcct>);
	
		
} >>
