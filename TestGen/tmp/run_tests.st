run_tests(testNames) ::= <<
#include "tests.h"

int main(){
	<testNames:{n | <n>();}; separator="\n">

	return 1;
}
>>