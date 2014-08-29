#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "callsha.h"

int compare_results(unsigned char *res1, unsigned char *res2, int length)
{
	int i;
	for(i=0; i<length; i++)
	{
		if(res1[i]!=res2[i]){
			return 0;
		}
	}
	return 1;
}

int check_KAT(unsigned char *result,
        unsigned char *expected_result, int length,
        unsigned char *testname){
	if(!compare_results(result, expected_result, length)){
		printf("%s failed!\n",testname);
		return 1;
	}
	return 0;
}

test0(){
	unsigned char input[43] = "The quick brown fox jumps over the lazy dog";
	unsigned char result[32];
	unsigned char expected_result[32] = {
	0xd7, 0xa8, 0xfb, 0xb3, 0x07, 0xd7, 0x80, 0x94, 
	0x69, 0xca, 0x9a, 0xbc, 0xb0, 0x08, 0x2e, 0x4f, 
	0x8d, 0x56, 0x51, 0xe4, 0x6d, 0x3c, 0xdb, 0x76, 
	0x2d, 0x02, 0xd0, 0xbf, 0x37, 0xc9, 0xe5, 0x92

	};

	SHA256_VST(input, result, 43);

	check_KAT(result, expected_result, 32, "test0");
} 

int main(){
	test0();

	return 1;
}

