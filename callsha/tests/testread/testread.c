#include <stdio.h>
#include <stdlib.h>

int main(){
	FILE *fp = fopen("input", "r");
	unsigned char a, b, c;
	unsigned char results1, results2;
		
	if (fp == NULL) {
		fprintf(stderr, "Can't open input file in.list!\n");
		exit(1);
	}	
	
	int length;
	while(fscanf(fp, "%d", &length) != EOF){
		unsigned char* instring = malloc(length * sizeof(char));
		int i=0;
		for(i=0; i<length; i++){
			fscanf(fp, "%2hhx", &c);
			instring[i] = c;
		}
	
		printf("read %s \n", instring);
		free(instring);
	}
	
	return 0;
}