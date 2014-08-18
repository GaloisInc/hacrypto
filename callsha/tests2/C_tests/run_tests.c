#include "tests.h"

int main(){
	SHA256_VST_KAT_0();
	SHA256_VST_KAT_1();
	SHA256_VST_KAT_2();
	SHA256_VST_KAT_3();
	SHA256_VST_KAT_4();
	SHA256_VST_KAT_5();
	SHA256_VST_KAT_6();
	SHA256_VST_KAT_7();
	SHA256_NSS_KAT_0();
	SHA256_NSS_KAT_1();
	SHA256_NSS_KAT_2();
	SHA256_NSS_KAT_3();
	SHA256_NSS_KAT_4();
	SHA256_NSS_KAT_5();
	SHA256_NSS_KAT_6();
	SHA256_NSS_KAT_7();
	SHA256_sodium_KAT_0();
	SHA256_sodium_KAT_1();
	SHA256_sodium_KAT_2();
	SHA256_sodium_KAT_3();
	SHA256_sodium_KAT_4();
	SHA256_sodium_KAT_5();
	SHA256_sodium_KAT_6();
	SHA256_sodium_KAT_7();
	SHA256_shortMsg();
	SHA256_longMsg();

	return 1;
}