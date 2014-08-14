#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "Ccommon_test.h"
#include "../../callsha.h"

void SHA256_shortMsg(){
	printf("running SHA256_shortMsg\n");
	int (*funcs[3])(unsigned char *, unsigned char *, unsigned long long);

		funcs[0] = SHA256_VST;
		funcs[1] = SHA256_NSS;
		funcs[2] = SHA256_sodium;
		do_comparison1("../SHA256shortMsg.req", "../SHA256shortMsg_out", funcs, 3);
} 

void SHA256_longMsg(){
	printf("running SHA256_longMsg\n");
	int (*funcs[3])(unsigned char *, unsigned char *, unsigned long long);

		funcs[0] = SHA256_VST;
		funcs[1] = SHA256_NSS;
		funcs[2] = SHA256_sodium;
		do_comparison1("../SHA256longMsg.req", "../SHA256longMsg_out", funcs, 3);
} 
