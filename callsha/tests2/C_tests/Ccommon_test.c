#include <stdio.h>
#include <stdlib.h>

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

int check_test(unsigned char *result0, unsigned char *result1, int length, unsigned char *errormsg){
	if(!compare_results(result0, result1, length)){
		printf(errormsg);
		return 0;
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

//specialized to one input... may need versions for more
//not sure if it is worth making it fully generic with
//respect to number of inputs
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
