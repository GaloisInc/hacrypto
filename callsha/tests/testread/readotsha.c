#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "Ccommon_test.h"
#include "../hashes.h"

void SHA256_compare_read(FILE *fp){
	
	unsigned char c;
	int length;
	fscanf(fp, "%d", &length);
	unsigned char* input = malloc(length * sizeof(char));
	int i=0;
	while(fscanf(fp, "%2hhx", &c) > 0){
		input[i++] = c;
	}
	
	
	printf("Checking string %s\n", input);
	unsigned char result0[32];
	unsigned char result1[32];

	SHA256_VST(input, result0, length * sizeof(char));

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, length * sizeof(char));
	check_test(result0, result1, 32, "Disagreement between SHA256_VST and SHA256_NSS in SHA256_compare_0\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, length * sizeof(char));
	check_test(result0, result1, 32, "Disagreement between SHA256_VST and SHA256_sodium in SHA256_compare_0\n");

	fscanf(fp, "%s", &c); //read the delimiter
	
}

int main(){
	FILE *fp = fopen("input", "r");
	SHA256_compare_read(fp);
	SHA256_compare_read(fp);
	fflush(stdout);
}