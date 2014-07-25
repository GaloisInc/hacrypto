repeat(repeats, string, stringlength) ::= <<
char to_repeat[] = <string>;
	
int i;
for(i=0; i\<<repeats>; i++){
	memcpy(input + i*<stringlength>, to_repeat, <stringlength>);
}

>>