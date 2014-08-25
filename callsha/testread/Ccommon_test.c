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
//TODO This function expects a very correct file for SHA256. Maybe it can/should be generalized?
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

	unsigned long inlength, outlength;
	int i, testno;
	unsigned char nextstring[50]; //should be safe unless comments are malicious...
	testno=1;
	while(fscanf(fpin, "%s", nextstring) != EOF){
		while(nextstring[0] == '#' || nextstring[0] == '[' ){
			fscanf(fpin, "%*[^\n]\n", NULL); //skip a line, it is a comment or additional data
			fscanf(fpin, "%s", nextstring); //should be Len when loop stops
			printf(nextstring);
		}
		
		fscanf(fpin, "%s", nextstring); //read the "="
		fscanf(fpin, "%lu", &inlength); 
		
		unsigned char* input = malloc(inlength * sizeof(char));
		
		fscanf(fpin, "%s", nextstring); //read msg
		fscanf(fpin, "%s", nextstring); //read "="
		
		for(i=0; i<inlength; i++){
			fscanf(fpin, "%2hhx", &input[i]);
		}
		
		void print_result(unsigned char *out, int length)
		
		fscanf(fpout, "%d", &outlength);
		unsigned char* output1 = malloc(outlength * sizeof(char));
		unsigned char* output2 = malloc(outlength * sizeof(char));
		
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
		printf("%d\n", testno);
	}
	
	return 0;
}

int main(){
	return do_comparison1("SHA256_compar_in", "SHA256_compare_out", NULL, 0);
}
