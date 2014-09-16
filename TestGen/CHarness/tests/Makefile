all : tests

tests : SHA256_VST_KAT.c SHA256_NSS_KAT.c SHA256_sodium_KAT.c SHA256_compare.c SHA256_Xcompare.c
	gcc Ccommon_test.c run_tests.c SHA256_VST_KAT.c SHA256_NSS_KAT.c SHA256_sodium_KAT.c SHA256_compare.c SHA256_Xcompare.c  test_sha.a -o tests -L/usr/local/lib -lsodium