#include <string.h>
#include <stdio.h>
#include "hashes.h"
#include "callsha.h"

int vst_entry (){
	unsigned char input[] = "This is a test string";
	unsigned char result[crypto_hash_sha256_BYTES] = "";
	
	return sha256_VST(input, result, 21); // 21 is strlen(input)
	
}


int nss_entry (){
	unsigned char input[] = "This is a test string";
	unsigned char result[crypto_hash_sha256_BYTES] = "";
	
	return sha256_NSS(input, result, 21); // 21 is strlen(input)
	
}


int compare_vst_NSS(unsigned char input){
	unsigned char input[] = "This is a test string";
	unsigned char nss_result[crypto_hash_sha256_BYTES] = "";
	unsigned char vst_result[crypto_hash_sha256_BYTES] = "";
	
	sha256_VST(input, vst_result, 21);
	sha256_NSS(input, nss_result, 21);
	
	int result = compare_results(vst_result, nss_result, crypto_hash_sha256_BYTES);

	return result;
}

int compare_vst_NSS_static(){
	return compare_vst_NSS("This is a test string");
}

int compare_vst_NSS_n(int n){
	unsigned char input[n];
	int i;

	for (i =0; i <n; i ++) input[n]= Frama_C_interval (0 , 255);

	return compare_vst_NSS(input);
}

int compare_vst_NSS_3(){
	return compare_vst_NSS_n(3);
}

