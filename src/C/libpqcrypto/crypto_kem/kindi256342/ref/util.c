#include "util.h"

int cmp_llu(const void *a, const void*b) {
	if (*(unsigned long long *) a < *(unsigned long long *) b)
		return -1;
	if (*(unsigned long long *) a > *(unsigned long long *) b)
		return 1;
	return 0;
}

unsigned long long median(unsigned long long *l, size_t llen) {
	qsort(l, llen, sizeof(unsigned long long), cmp_llu);

	if (llen % 2)
		return l[llen / 2];
	else
		return (l[llen / 2 - 1] + l[llen / 2]) / 2;
}

unsigned long long average(unsigned long long *t, size_t tlen) {
	unsigned long long acc = 0;
	size_t i;
	for (i = 0; i < tlen; i++)
		acc += t[i];
	return acc / (tlen);
}

void print_results(const char *s, unsigned long long *t, size_t tlen) {

	printf(" %s", s);
	printf("\n");
	printf("     median:  %llu\n", median(t, tlen));
	if (tlen > 1)
		printf("     average: %llu\n", average(t, tlen - 1));
	printf("\n");
}

void print_char_hex(const char *s, const unsigned char *c, int len) {
	int i;
	printf("\n%s=\n", s);
	for (i = 0; i < len; i++)
		printf(" %#02x,", c[i]);
	printf("\n");
}

void print_parameters() {
	printf("*************************************\n\n");
	printf("              Testbench\n\n");
	printf("              KINDI (KEM)\n\n");
	printf("              ref           \n");
	printf("*************************************\n");
	printf("\n--> Parameters:\n");
	printf("\tLAMBDA\t\t= %d\n"
			"\tN\t\t= %d\n"
			"\tQ\t\t= %d ("
			"2**%d)\n"
			"\tL1\t\t= %d\n"
			"\tR_SEC\t\t= %d\n"
			"\tMESSAGE_SIZE\t= %d bits\n"
			"\t\t\t= %d bytes\n\n",
	KINDI_KEM_LAMBDA, KINDI_KEM_N, KINDI_KEM_Q,
	KINDI_KEM_LOGQ,

			KINDI_KEM_L, KINDI_KEM_RSEC,
			KINDI_KEM_MESSAGEBYTES * 8, KINDI_KEM_MESSAGEBYTES);

	printf("--------------------------------\n");
}

void print_timings(double avg_enc, double avg_dec, unsigned long long *t_enc,
		unsigned long long *t_dec, size_t tlen) {

	printf("--> Timings:\n\n");
	printf("\tenc = %f ms / %llu cyc\n",
			((avg_enc / CLOCKS_PER_SEC) / tlen) * 1000, average(t_enc, tlen));
	printf("\tdec = %f ms / %llu cyc\n",
			((avg_dec / CLOCKS_PER_SEC) / tlen) * 1000, average(t_dec, tlen));
}
