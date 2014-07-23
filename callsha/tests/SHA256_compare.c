#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "Ccommon_test.h"
#include "../hashes.h"

void SHA256_compare_0(){
	unsigned char input[93] = { 244, 55, 56, 233, 124, 137, 129, 197, 157, 23, 33, 116, 120, 210, 95, 82, 205, 49, 70, 246, 17, 145, 182, 56, 93, 183, 49, 142, 187, 156, 199, 212, 109, 44, 113, 183, 21, 10, 172, 153, 164, 122, 183, 76, 122, 3, 243, 12, 63, 218, 95, 198, 165, 108, 212, 20, 78, 198, 26, 22, 140, 55, 102, 229, 244, 137, 10, 92, 114, 21, 150, 220, 19, 228, 184, 33, 55, 136, 65, 190, 189, 232, 224, 2, 91, 75, 218, 132, 165, 7, 228, 234, 116 };
	unsigned char result0[32];
	unsigned char result1[32];

	SHA256_VST(input, result0, 93);

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 93);
	check_test(result0, result1, 32, "Disagreement between SHA256_VST and SHA256_NSS in SHA256_compare_0");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 93);
	check_test(result0, result1, 32, "Disagreement between SHA256_VST and SHA256_sodium in SHA256_compare_0");


} 

void SHA256_compare_1(){
	unsigned char input[59] = { 166, 147, 222, 246, 15, 165, 114, 180, 88, 114, 174, 30, 155, 84, 209, 93, 64, 88, 102, 225, 98, 176, 173, 251, 223, 185, 13, 54, 236, 43, 195, 208, 227, 213, 43, 182, 61, 1, 154, 151, 2, 150, 33, 133, 76, 15, 104, 111, 44, 131, 90, 28, 174, 201, 198, 18, 201, 100, 4 };
	unsigned char result0[32];
	unsigned char result1[32];

	SHA256_VST(input, result0, 59);

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 59);
	check_test(result0, result1, 32, "Disagreement between SHA256_VST and SHA256_NSS in SHA256_compare_1");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 59);
	check_test(result0, result1, 32, "Disagreement between SHA256_VST and SHA256_sodium in SHA256_compare_1");


} 

void SHA256_compare_2(){
	unsigned char input[80] = { 86, 236, 4, 235, 137, 66, 48, 140, 146, 194, 167, 52, 107, 209, 247, 37, 190, 137, 175, 169, 38, 226, 178, 171, 65, 73, 76, 225, 39, 141, 108, 115, 89, 224, 18, 247, 148, 204, 119, 204, 88, 43, 26, 172, 184, 216, 104, 50, 155, 57, 27, 206, 51, 92, 224, 178, 121, 91, 86, 92, 14, 144, 47, 81, 229, 61, 8, 116, 178, 172, 70, 25, 37, 202, 70, 224, 50, 191, 113, 57 };
	unsigned char result0[32];
	unsigned char result1[32];

	SHA256_VST(input, result0, 80);

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 80);
	check_test(result0, result1, 32, "Disagreement between SHA256_VST and SHA256_NSS in SHA256_compare_2");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 80);
	check_test(result0, result1, 32, "Disagreement between SHA256_VST and SHA256_sodium in SHA256_compare_2");


} 

void SHA256_compare_3(){
	unsigned char input[1] = { 131 };
	unsigned char result0[32];
	unsigned char result1[32];

	SHA256_VST(input, result0, 1);

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 1);
	check_test(result0, result1, 32, "Disagreement between SHA256_VST and SHA256_NSS in SHA256_compare_3");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 1);
	check_test(result0, result1, 32, "Disagreement between SHA256_VST and SHA256_sodium in SHA256_compare_3");


} 

void SHA256_compare_4(){
	unsigned char input[84] = { 187, 38, 220, 1, 166, 7, 14, 41, 130, 135, 178, 108, 79, 31, 70, 140, 158, 147, 32, 85, 64, 81, 172, 85, 68, 220, 27, 183, 165, 82, 73, 130, 119, 236, 30, 151, 241, 7, 28, 47, 189, 237, 223, 177, 47, 49, 15, 252, 31, 213, 97, 47, 205, 88, 223, 211, 232, 80, 119, 187, 7, 47, 249, 143, 159, 189, 243, 50, 137, 86, 70, 169, 177, 231, 10, 199, 150, 237, 236, 241, 85, 22, 89, 197 };
	unsigned char result0[32];
	unsigned char result1[32];

	SHA256_VST(input, result0, 84);

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 84);
	check_test(result0, result1, 32, "Disagreement between SHA256_VST and SHA256_NSS in SHA256_compare_4");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 84);
	check_test(result0, result1, 32, "Disagreement between SHA256_VST and SHA256_sodium in SHA256_compare_4");


} 

void SHA256_compare_5(){
	unsigned char input[22] = { 191, 190, 43, 57, 96, 183, 218, 174, 98, 135, 147, 171, 182, 139, 137, 227, 155, 187, 162, 19, 84, 165 };
	unsigned char result0[32];
	unsigned char result1[32];

	SHA256_VST(input, result0, 22);

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 22);
	check_test(result0, result1, 32, "Disagreement between SHA256_VST and SHA256_NSS in SHA256_compare_5");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 22);
	check_test(result0, result1, 32, "Disagreement between SHA256_VST and SHA256_sodium in SHA256_compare_5");


} 

void SHA256_compare_6(){
	unsigned char input[12] = { 239, 197, 24, 170, 186, 180, 160, 171, 207, 227, 154, 167 };
	unsigned char result0[32];
	unsigned char result1[32];

	SHA256_VST(input, result0, 12);

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 12);
	check_test(result0, result1, 32, "Disagreement between SHA256_VST and SHA256_NSS in SHA256_compare_6");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 12);
	check_test(result0, result1, 32, "Disagreement between SHA256_VST and SHA256_sodium in SHA256_compare_6");


} 

void SHA256_compare_7(){
	unsigned char input[43] = { 255, 211, 149, 252, 0, 212, 55, 143, 79, 67, 122, 218, 128, 23, 155, 239, 199, 194, 58, 92, 160, 2, 197, 216, 164, 54, 125, 42, 65, 42, 114, 31, 232, 116, 175, 16, 142, 16, 239, 48, 66, 107, 125 };
	unsigned char result0[32];
	unsigned char result1[32];

	SHA256_VST(input, result0, 43);

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 43);
	check_test(result0, result1, 32, "Disagreement between SHA256_VST and SHA256_NSS in SHA256_compare_7");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 43);
	check_test(result0, result1, 32, "Disagreement between SHA256_VST and SHA256_sodium in SHA256_compare_7");


} 

void SHA256_compare_8(){
	unsigned char input[89] = { 171, 108, 122, 232, 8, 82, 9, 51, 247, 217, 228, 95, 248, 125, 251, 109, 182, 81, 9, 104, 146, 249, 142, 53, 62, 130, 126, 52, 77, 148, 0, 172, 225, 225, 42, 245, 16, 6, 252, 126, 209, 187, 165, 214, 138, 248, 73, 23, 44, 181, 184, 92, 227, 84, 115, 149, 68, 72, 9, 176, 91, 223, 49, 229, 226, 99, 137, 20, 23, 79, 2, 9, 14, 31, 120, 91, 69, 69, 227, 138, 69, 164, 140, 1, 46, 76, 247, 191, 188 };
	unsigned char result0[32];
	unsigned char result1[32];

	SHA256_VST(input, result0, 89);

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 89);
	check_test(result0, result1, 32, "Disagreement between SHA256_VST and SHA256_NSS in SHA256_compare_8");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 89);
	check_test(result0, result1, 32, "Disagreement between SHA256_VST and SHA256_sodium in SHA256_compare_8");


} 

void SHA256_compare_9(){
	unsigned char input[38] = { 81, 35, 153, 200, 182, 157, 126, 220, 4, 117, 32, 3, 135, 115, 140, 237, 218, 6, 153, 226, 185, 47, 115, 204, 63, 123, 238, 163, 89, 107, 172, 135, 134, 87, 232, 249, 209, 195 };
	unsigned char result0[32];
	unsigned char result1[32];

	SHA256_VST(input, result0, 38);

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 38);
	check_test(result0, result1, 32, "Disagreement between SHA256_VST and SHA256_NSS in SHA256_compare_9");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 38);
	check_test(result0, result1, 32, "Disagreement between SHA256_VST and SHA256_sodium in SHA256_compare_9");


} 
