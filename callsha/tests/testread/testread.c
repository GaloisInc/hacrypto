#include <stdio.h>
#include <stdlib.h>
#include "../../callsha.h"
#include "../Ccommon_test.h"

void print_hex(unsigned char *digest, long long length){
	int i;
	for (i=0;i<length;i++)
		printf("%02x",digest[i]);
}

int main(){
	int (*p[3])(unsigned char *,unsigned char *, unsigned long long);
	p[0] = SHA256_VST;
	p[1] = SHA256_NSS;
	p[2] = SHA256_sodium;
	do_comparison1("SHA256_compare_in", "SHA256_compare_out", p, 3);
}

int do_comparison1(char *infile, char *outfile, int (*funcs[])(char *, char *, unsigned long long), int funcslength){
	setbuf(stdout,NULL);
	FILE *fpin = fopen(infile, "r");
	FILE *fpout = fopen(outfile, "r");
		
	if (fpin == NULL) {
		fprintf(stderr, "Can't open input file in.list!\n");
		exit(1);
	}
	
	if (fpout == NULL) {
		fprintf(stderr, "Can't open input file in.list!\n");
		exit(1);
	}
	
	int inlength, outlength, i, testno;
	testno=1;
	while(fscanf(fpin, "%d", &inlength) != EOF && fscanf(fpout, "%d", &outlength) != EOF){
		unsigned char* input = malloc(inlength * sizeof(char));
		unsigned char* output1 = malloc(outlength * sizeof(char));
		unsigned char* output2 = malloc(outlength * sizeof(char));
		
		for(i=0; i<inlength; i++){
			fscanf(fpin, "%2hhx", &input[i]);
		}
		for(i=0; i<outlength; i++){
			fscanf(fpout, "%2hhx", &output1[i]);
		}
		
		for(i=0; i<funcslength; i++){
			funcs[i](input, output2, inlength);
			if (!compare_results(output1, output2, outlength)){
				printf("Test on line %d of file SHA256_compare_in failed for function %d\n", testno, i);
			}
		}
		
		free(input);
		free(output1);
		free(output2);
		testno++;
	}
	
	return 0;
}

