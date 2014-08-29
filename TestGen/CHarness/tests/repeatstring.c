#include<stdlib.h>
#include<stdio.h>
#include<string.h>

int main(){
	int insize = 3;
	int repeat = 7;
	char *input = malloc (sizeof(char) * insize * repeat);
	char to_repeat[] = "abc";
	
	int i;
	for(i=0; i<repeat; i++){
		memcpy(input + i*insize, to_repeat, insize);
	}
	printf(input);
}