#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "Ccommon_test.h"
#include "../../callsha.h"

void SHA256_compare(){
	int (*funcs[3])(unsigned char *, unsigned char *, unsigned long long);

		funcs[0] = SHA256_VST;
		funcs[1] = SHA256_NSS;
		funcs[2] = SHA256_sodium;
		do_comparison1("../SHA256_compare_in", "../SHA256_compare_out", funcs, 3);


} 
