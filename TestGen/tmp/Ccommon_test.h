int compare_results(unsigned char *res1, unsigned char *res2, int length);

int check_KAT(unsigned char *result,
        unsigned char *expected_result, int length,
        unsigned char *testname);

int do_comparison1(char *infile, char *outfile, int (*funcs[])(unsigned char *, unsigned char *, unsigned long long), int funcslength);
