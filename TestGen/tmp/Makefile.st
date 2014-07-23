Makefile (cFiles, ccargs) ::= <<
all : tests

tests : <cFiles; separator = " ">
	gcc Ccommon_test.c run_tests.c <cFiles; separator = " ">  test_sha.a -o tests <ccargs>
>>
