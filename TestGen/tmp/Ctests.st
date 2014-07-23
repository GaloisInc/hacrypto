Ctests(imports, tests) ::= <<
#include \<string.h>
#include \<stdlib.h>
#include \<stdio.h>
#include "Ccommon_test.h"
<imports:{import | #include "<import>"}; separator="\n">

<tests; separator="\n\n">

>>