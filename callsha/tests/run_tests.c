#include "tests.h"

int main(){
	SHA256_VST_KAT_0();
	SHA256_VST_KAT_1();
	SHA256_VST_KAT_2();
	SHA256_NSS_KAT_0();
	SHA256_NSS_KAT_1();
	SHA256_NSS_KAT_2();
	SHA256_sodium_KAT_0();
	SHA256_sodium_KAT_1();
	SHA256_sodium_KAT_2();

	return 1;
}