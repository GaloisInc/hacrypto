#include "callsha.h"
#include "hashes.h"
#include <stdio.h>
#include <string.h>


typedef struct{
	int ct;
	char *imps;
}Strl;
/*
Strl read_imps(){
   FILE *fp;
   fp = fopen(SHA256_implementations.txt,"r");
   if(!fp) {
		fprintf(stderr, "Can't open input file SHA256_implementations.txt!\n");
		exit(1);
   }
   
   char word[10];
   int ct;
   
   while (fscanf(fp, "%s", word) != EOF)
   {
	
   }
	
}*/

int test_known_answer(char* input, char* output, 
	int (*SHA256_fp)(unsigned char *, unsigned char *, long long unsigned int)){
    unsigned char result[crypto_hash_sha256_BYTES]; 
	SHA256_fp(input,result, strlen(input));
	int match = compare_results(result, output, strlen(output));
	if (match) {
		return 1;}
	else {
		printf("result didn't match");//TODO better message
		return 0;
	}
}
/*
int main(){
	unsigned char input1[] = "sample input";
	unsigned char output1[crypto_hash_sha256_BYTES] = "";
	return test_known_answer(input1, output1, &sha256_VST);
}*/
