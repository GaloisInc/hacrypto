//from frama-c value analysis documentation:
//http://frama-c.com/download/frama-c-value-analysis.pdf

#include<string.h>

void* memcpy (void* region1, const void* region2, size_t n)
{
	char * dest = (char*) region1;
	const char* first = (const char*) region2;
	const char* last = ((const char*) region2) + n;
	char* result = (char*) region1;
	while (first != last){
	  *dest++ = *first++;
	}
	return result;
}

void* memset (void* dest, int val, size_t len)
{
	unsigned char *ptr = (unsigned char*)dest;
	while (len-- > 0)
		*ptr++ = val;
	return dest;
}
