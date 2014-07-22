Ctests(imports, KATtests, testNames) ::= <<
#include \<string.h>
#include \<stdlib.h>
#include \<stdio.h>
#include "Ccommon_test.h"
<imports:{import | #include "<import>"}; separator="\n">

<KATtests; separator="\n\n">

>>