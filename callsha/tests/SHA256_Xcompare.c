#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "Ccommon_test.h"
#include "../hashes.h"

void SHA256_Xcompare_0(){
	unsigned char input[90] = { 190 ,65 ,151 ,204 ,177 ,38 ,208 ,122 ,138 ,155 ,0 ,214 ,173 ,149 ,182 ,184 ,82 ,243 ,182 ,169 ,18 ,63 ,230 ,64 ,201 ,247 ,161 ,225 ,27 ,162 ,117 ,7 ,236 ,177 ,122 ,130 ,154 ,245 ,89 ,243 ,45 ,181 ,132 ,251 ,77 ,15 ,5 ,102 ,177 ,76 ,160 ,19 ,67 ,184 ,190 ,189 ,39 ,197 ,31 ,202 ,156 ,61 ,0 ,10 ,193 ,196 ,32 ,217 ,22 ,18 ,246 ,188 ,79 ,95 ,253 ,101 ,82 ,252 ,38 ,101 ,154 ,74 ,50 ,164 ,186 ,102 ,224 ,247 ,100 ,215 };
	unsigned char result0[32] = { 0x4E, 0xF5, 0x82, 0xEB, 0x5B, 0x8B, 0xC4, 0xE3, 
0xFE, 0xC2, 0xC5, 0x5E, 0x6D, 0xC5, 0x55, 0x1F, 
0x52, 0x8A, 0x2A, 0xFA, 0x93, 0x32, 0xAD, 0xE4, 
0x85, 0x47, 0x06, 0x94, 0xB4, 0xB0, 0xAE, 0x7F
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 90);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_0\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 90);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_0\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 90);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_0\n");


} 

void SHA256_Xcompare_1(){
	unsigned char input[26] = { 189 ,45 ,162 ,87 ,77 ,83 ,37 ,130 ,145 ,79 ,219 ,68 ,63 ,40 ,184 ,56 ,146 ,162 ,235 ,53 ,118 ,200 ,224 ,87 ,241 ,202 };
	unsigned char result0[32] = { 0xBE, 0x9C, 0xB2, 0x81, 0x6F, 0x86, 0xA2, 0xA0, 
0x20, 0x78, 0xFF, 0x3D, 0x02, 0x15, 0x1A, 0xA2, 
0xAF, 0x45, 0xE1, 0x60, 0xDE, 0x66, 0xC9, 0x1F, 
0x71, 0x5F, 0x5A, 0xBD, 0x2E, 0xAE, 0xB6, 0x82
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 26);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_1\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 26);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_1\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 26);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_1\n");


} 

void SHA256_Xcompare_2(){
	unsigned char input[80] = { 136 ,130 ,90 ,131 ,186 ,49 ,63 ,248 ,85 ,100 ,83 ,203 ,7 ,210 ,41 ,199 ,128 ,106 ,215 ,241 ,15 ,62 ,228 ,106 ,68 ,173 ,216 ,92 ,253 ,51 ,204 ,162 ,107 ,219 ,236 ,61 ,174 ,29 ,157 ,5 ,66 ,121 ,137 ,30 ,148 ,38 ,234 ,35 ,49 ,65 ,107 ,91 ,45 ,73 ,152 ,222 ,85 ,153 ,94 ,56 ,79 ,103 ,224 ,9 ,212 ,3 ,12 ,118 ,204 ,37 ,106 ,152 ,196 ,75 ,145 ,217 ,65 ,139 ,16 ,55 };
	unsigned char result0[32] = { 0xCC, 0x9C, 0x1C, 0x1F, 0xC9, 0x37, 0xB4, 0x68, 
0xBB, 0x4A, 0xB4, 0x42, 0xD2, 0x47, 0x7A, 0xE4, 
0x41, 0xF7, 0x6B, 0x5E, 0xD3, 0x1A, 0x04, 0x47, 
0x5E, 0x7F, 0x37, 0x02, 0x2A, 0x3A, 0x0C, 0x1C
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 80);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_2\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 80);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_2\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 80);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_2\n");


} 

void SHA256_Xcompare_3(){
	unsigned char input[14] = { 14 ,27 ,199 ,241 ,34 ,100 ,169 ,214 ,195 ,160 ,139 ,16 ,214 ,58 };
	unsigned char result0[32] = { 0x1E, 0x8E, 0x75, 0x32, 0x6A, 0x32, 0xAB, 0xCA, 
0xF3, 0x57, 0xB0, 0xC2, 0xC8, 0xAD, 0x8C, 0xC3, 
0x36, 0x95, 0xDD, 0x8E, 0x03, 0xDB, 0x7D, 0xD5, 
0x22, 0xF9, 0x89, 0x35, 0x31, 0xC4, 0xF3, 0xA8
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 14);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_3\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 14);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_3\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 14);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_3\n");


} 

void SHA256_Xcompare_4(){
	unsigned char input[37] = { 138 ,111 ,247 ,37 ,96 ,184 ,88 ,161 ,128 ,37 ,165 ,117 ,4 ,115 ,94 ,181 ,43 ,89 ,214 ,78 ,20 ,137 ,230 ,20 ,166 ,131 ,100 ,244 ,184 ,243 ,129 ,234 ,6 ,83 ,196 ,203 ,182 };
	unsigned char result0[32] = { 0x29, 0x59, 0xE0, 0x46, 0xC7, 0x7F, 0xEB, 0x62, 
0xF1, 0x3A, 0x8B, 0x47, 0x22, 0x40, 0x57, 0x20, 
0x1D, 0xAF, 0x1B, 0x63, 0x58, 0x65, 0xBD, 0xFA, 
0xA7, 0xC8, 0x7E, 0xDB, 0x27, 0xF9, 0x4D, 0x53
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 37);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_4\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 37);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_4\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 37);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_4\n");


} 

void SHA256_Xcompare_5(){
	unsigned char input[93] = { 245 ,204 ,3 ,91 ,246 ,6 ,27 ,234 ,177 ,233 ,67 ,213 ,31 ,134 ,117 ,32 ,241 ,40 ,204 ,84 ,240 ,83 ,43 ,72 ,250 ,58 ,13 ,215 ,176 ,106 ,204 ,224 ,218 ,223 ,143 ,151 ,140 ,27 ,1 ,164 ,61 ,143 ,200 ,23 ,63 ,255 ,75 ,136 ,42 ,214 ,193 ,233 ,196 ,227 ,87 ,238 ,89 ,238 ,209 ,94 ,80 ,131 ,243 ,54 ,64 ,108 ,11 ,209 ,250 ,80 ,145 ,62 ,15 ,252 ,44 ,215 ,168 ,193 ,44 ,24 ,44 ,211 ,35 ,125 ,63 ,188 ,10 ,82 ,245 ,10 ,167 ,170 ,49 };
	unsigned char result0[32] = { 0x8C, 0x8B, 0x2A, 0xFD, 0x6E, 0x00, 0xBE, 0x4A, 
0x5D, 0xAC, 0x69, 0x69, 0x6B, 0x54, 0x69, 0x5E, 
0x6A, 0x7B, 0xA1, 0xBA, 0x8F, 0xF8, 0x70, 0xB8, 
0x71, 0x8E, 0xD5, 0x32, 0x1F, 0xA5, 0x5E, 0x17
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 93);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_5\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 93);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_5\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 93);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_5\n");


} 

void SHA256_Xcompare_6(){
	unsigned char input[37] = { 210 ,105 ,63 ,51 ,176 ,234 ,18 ,162 ,32 ,70 ,24 ,39 ,17 ,13 ,13 ,77 ,230 ,35 ,249 ,191 ,97 ,229 ,182 ,151 ,89 ,250 ,136 ,197 ,172 ,42 ,106 ,245 ,167 ,61 ,169 ,81 ,95 };
	unsigned char result0[32] = { 0x4A, 0xFB, 0xB8, 0x2D, 0x29, 0xDB, 0xD3, 0x27, 
0xB2, 0x0C, 0xC4, 0x43, 0xBF, 0xFA, 0xC8, 0x15, 
0x8A, 0xAA, 0xA7, 0x52, 0x76, 0x86, 0x35, 0x75, 
0x93, 0x01, 0xA3, 0x55, 0x93, 0x26, 0x12, 0xF2
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 37);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_6\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 37);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_6\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 37);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_6\n");


} 

void SHA256_Xcompare_7(){
	unsigned char input[84] = { 202 ,92 ,152 ,129 ,127 ,66 ,32 ,84 ,39 ,212 ,217 ,123 ,181 ,123 ,77 ,120 ,50 ,176 ,12 ,163 ,148 ,213 ,122 ,45 ,144 ,15 ,20 ,71 ,10 ,10 ,166 ,45 ,153 ,173 ,250 ,33 ,149 ,133 ,126 ,82 ,66 ,250 ,208 ,34 ,148 ,59 ,225 ,240 ,55 ,35 ,192 ,78 ,182 ,152 ,9 ,149 ,104 ,202 ,31 ,228 ,60 ,110 ,153 ,159 ,151 ,115 ,75 ,251 ,248 ,20 ,229 ,194 ,164 ,225 ,31 ,187 ,44 ,165 ,199 ,31 ,174 ,125 ,151 ,26 };
	unsigned char result0[32] = { 0xE1, 0xDB, 0xD3, 0x47, 0xEA, 0xA0, 0xA4, 0xBB, 
0x35, 0x15, 0xFE, 0x9B, 0xF8, 0x31, 0x71, 0x36, 
0xFD, 0xD9, 0x5C, 0x30, 0xEC, 0x8F, 0xC2, 0x5C, 
0xD8, 0x85, 0x29, 0x4A, 0xDD, 0x85, 0x06, 0xD7
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 84);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_7\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 84);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_7\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 84);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_7\n");


} 

void SHA256_Xcompare_8(){
	unsigned char input[90] = { 67 ,197 ,99 ,139 ,253 ,238 ,213 ,212 ,47 ,114 ,117 ,130 ,59 ,87 ,211 ,244 ,177 ,229 ,142 ,89 ,20 ,138 ,239 ,131 ,29 ,42 ,142 ,102 ,31 ,142 ,119 ,225 ,47 ,233 ,195 ,83 ,72 ,107 ,4 ,248 ,161 ,210 ,9 ,176 ,53 ,134 ,142 ,124 ,194 ,109 ,160 ,209 ,200 ,10 ,44 ,149 ,29 ,2 ,230 ,28 ,53 ,213 ,239 ,147 ,110 ,118 ,222 ,130 ,60 ,155 ,109 ,255 ,128 ,138 ,239 ,49 ,128 ,83 ,231 ,110 ,164 ,247 ,130 ,96 ,41 ,15 ,178 ,176 ,219 ,156 };
	unsigned char result0[32] = { 0xE5, 0x0F, 0x30, 0x51, 0xA2, 0xA5, 0xF7, 0xEE, 
0xD0, 0x3D, 0xEB, 0xD1, 0x1B, 0x32, 0xDB, 0x51, 
0x93, 0x63, 0xA8, 0x7A, 0xDC, 0xE4, 0x84, 0x5F, 
0x60, 0x58, 0x60, 0xD9, 0x22, 0x42, 0x28, 0x69
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 90);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_8\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 90);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_8\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 90);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_8\n");


} 

void SHA256_Xcompare_9(){
	unsigned char input[26] = { 248 ,54 ,4 ,7 ,153 ,144 ,6 ,39 ,52 ,18 ,41 ,20 ,253 ,156 ,95 ,29 ,22 ,242 ,73 ,15 ,250 ,78 ,156 ,109 ,154 ,237 };
	unsigned char result0[32] = { 0x81, 0xD2, 0x14, 0x5F, 0xC9, 0xF9, 0x1D, 0x5F, 
0x1E, 0xED, 0xB2, 0x89, 0x2D, 0x83, 0xC8, 0xB8, 
0x7F, 0x46, 0x00, 0xEB, 0x16, 0x75, 0xF7, 0x3A, 
0x03, 0x45, 0xC1, 0x67, 0xAD, 0x06, 0x18, 0x67
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 26);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_9\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 26);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_9\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 26);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_9\n");


} 

void SHA256_Xcompare_10(){
	unsigned char input[19] = { 246 ,128 ,20 ,36 ,70 ,199 ,92 ,130 ,121 ,107 ,42 ,47 ,78 ,49 ,162 ,88 ,79 ,103 ,119 };
	unsigned char result0[32] = { 0x99, 0x0B, 0xE2, 0x4C, 0xA0, 0x0B, 0x4E, 0x65, 
0xC7, 0xF1, 0xF4, 0xC9, 0xCE, 0x4A, 0x5A, 0x3B, 
0x16, 0x9B, 0xAB, 0x93, 0x76, 0x52, 0x38, 0x47, 
0xF9, 0xC9, 0xD3, 0x96, 0xDE, 0xE7, 0x3C, 0x2D
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 19);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_10\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 19);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_10\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 19);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_10\n");


} 

void SHA256_Xcompare_11(){
	unsigned char input[34] = { 47 ,50 ,146 ,175 ,39 ,57 ,128 ,11 ,72 ,9 ,231 ,61 ,205 ,197 ,195 ,76 ,223 ,119 ,121 ,63 ,91 ,164 ,126 ,75 ,117 ,119 ,32 ,148 ,115 ,146 ,27 ,197 ,132 ,49 };
	unsigned char result0[32] = { 0x17, 0x48, 0x5A, 0xDC, 0x61, 0x2F, 0x0D, 0x79, 
0x1F, 0xE2, 0x03, 0xA8, 0x64, 0x8B, 0x4A, 0xA7, 
0xB3, 0xA1, 0xB1, 0x39, 0xB9, 0xF2, 0x59, 0x43, 
0xC7, 0x88, 0xDE, 0x46, 0x3C, 0x9A, 0xAA, 0x2A
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 34);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_11\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 34);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_11\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 34);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_11\n");


} 

void SHA256_Xcompare_12(){
	unsigned char input[20] = { 1 ,134 ,45 ,150 ,221 ,77 ,102 ,72 ,72 ,159 ,146 ,135 ,206 ,51 ,219 ,84 ,38 ,163 ,54 ,173 };
	unsigned char result0[32] = { 0xB9, 0x72, 0x80, 0x8A, 0xEB, 0xA2, 0x92, 0xF8, 
0x2E, 0xC8, 0x19, 0x3C, 0xAB, 0xEB, 0xE9, 0x1F, 
0xBD, 0xE9, 0x16, 0x43, 0x48, 0xFE, 0x0F, 0xC1, 
0x8E, 0x59, 0x68, 0x14, 0xE7, 0x34, 0xDC, 0x87
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 20);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_12\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 20);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_12\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 20);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_12\n");


} 

void SHA256_Xcompare_13(){
	unsigned char input[71] = { 21 ,202 ,248 ,175 ,246 ,55 ,174 ,7 ,229 ,32 ,247 ,230 ,200 ,28 ,29 ,47 ,108 ,198 ,75 ,66 ,151 ,187 ,78 ,227 ,243 ,229 ,191 ,105 ,35 ,132 ,234 ,238 ,118 ,208 ,136 ,18 ,36 ,180 ,210 ,39 ,242 ,185 ,63 ,254 ,2 ,60 ,45 ,242 ,88 ,149 ,47 ,249 ,104 ,186 ,84 ,57 ,224 ,160 ,7 ,207 ,208 ,80 ,63 ,251 ,203 ,61 ,158 ,103 ,133 ,131 ,21 };
	unsigned char result0[32] = { 0xFE, 0x5A, 0xBE, 0xCF, 0x15, 0x2D, 0xB2, 0xCD, 
0x07, 0xC4, 0x25, 0x7E, 0xB9, 0x9B, 0x73, 0x7F, 
0xE8, 0x4A, 0xA1, 0x05, 0x91, 0x52, 0xD4, 0x0D, 
0xA9, 0x20, 0xB7, 0xE0, 0x2E, 0x31, 0x3A, 0xDE
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 71);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_13\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 71);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_13\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 71);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_13\n");


} 

void SHA256_Xcompare_14(){
	unsigned char input[22] = { 168 ,225 ,79 ,72 ,234 ,13 ,139 ,7 ,57 ,102 ,77 ,45 ,230 ,84 ,18 ,66 ,59 ,113 ,7 ,53 ,78 ,174 };
	unsigned char result0[32] = { 0x3D, 0xA2, 0xBC, 0x27, 0x4A, 0xDC, 0x17, 0x8B, 
0xAA, 0xA5, 0xF5, 0xAC, 0x8D, 0x1F, 0x4E, 0x5C, 
0xAA, 0x87, 0xF8, 0x7B, 0x38, 0x33, 0x57, 0x88, 
0xCD, 0xE0, 0x0B, 0x2C, 0xAC, 0xE3, 0x29, 0x24
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 22);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_14\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 22);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_14\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 22);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_14\n");


} 

void SHA256_Xcompare_15(){
	unsigned char input[13] = { 111 ,52 ,27 ,145 ,246 ,224 ,165 ,211 ,87 ,114 ,39 ,48 ,197 };
	unsigned char result0[32] = { 0x45, 0x06, 0x2E, 0xC6, 0xEE, 0xCC, 0x3B, 0x9E, 
0xBB, 0xBE, 0x56, 0xF5, 0xFE, 0x14, 0xD0, 0x82, 
0xF0, 0x34, 0x3A, 0xF6, 0xC0, 0x8C, 0x35, 0xD3, 
0xCD, 0xB2, 0x5E, 0x31, 0xD0, 0xAF, 0xFE, 0x8D
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 13);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_15\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 13);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_15\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 13);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_15\n");


} 

void SHA256_Xcompare_16(){
	unsigned char input[17] = { 100 ,122 ,98 ,30 ,204 ,47 ,99 ,37 ,11 ,153 ,147 ,76 ,89 ,27 ,252 ,34 ,208 };
	unsigned char result0[32] = { 0x51, 0x8F, 0x5F, 0x6B, 0x29, 0x9E, 0x3C, 0x37, 
0x4F, 0x2B, 0xBC, 0xEB, 0xD0, 0x20, 0xD0, 0x25, 
0x79, 0x2D, 0x8F, 0xC4, 0x2B, 0xBA, 0x1B, 0x88, 
0x31, 0xBC, 0x79, 0x1E, 0x42, 0xE8, 0xE2, 0x6E
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 17);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_16\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 17);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_16\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 17);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_16\n");


} 

void SHA256_Xcompare_17(){
	unsigned char input[23] = { 12 ,28 ,116 ,134 ,227 ,90 ,58 ,144 ,46 ,85 ,210 ,183 ,40 ,96 ,219 ,129 ,79 ,108 ,142 ,44 ,92 ,64 ,137 };
	unsigned char result0[32] = { 0x70, 0x70, 0x5E, 0x11, 0x84, 0x58, 0xDE, 0xDF, 
0xF1, 0x8E, 0x16, 0x2E, 0x90, 0x02, 0xD3, 0x25, 
0xA8, 0xB3, 0x2C, 0x43, 0x09, 0xFA, 0x5E, 0xF1, 
0x92, 0xB5, 0xA9, 0xCB, 0x7E, 0x56, 0xDE, 0xC6
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 23);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_17\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 23);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_17\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 23);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_17\n");


} 

void SHA256_Xcompare_18(){
	unsigned char input[45] = { 51 ,224 ,214 ,172 ,207 ,190 ,171 ,3 ,15 ,61 ,63 ,205 ,225 ,86 ,148 ,26 ,215 ,219 ,57 ,50 ,2 ,182 ,51 ,215 ,249 ,103 ,220 ,85 ,224 ,104 ,250 ,47 ,45 ,42 ,39 ,154 ,23 ,217 ,29 ,36 ,190 ,93 ,177 ,240 ,171 };
	unsigned char result0[32] = { 0x8B, 0x7C, 0xD1, 0x0B, 0x1F, 0xAD, 0x84, 0xAE, 
0x4E, 0x48, 0x49, 0xFE, 0xE3, 0x02, 0x9E, 0x1E, 
0xD5, 0x3E, 0x01, 0x50, 0xC5, 0x58, 0xC8, 0x9B, 
0xE5, 0xEE, 0x01, 0x9C, 0xB0, 0x5B, 0xCD, 0xDB
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 45);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_18\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 45);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_18\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 45);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_18\n");


} 

void SHA256_Xcompare_19(){
	unsigned char input[17] = { 127 ,187 ,236 ,41 ,224 ,171 ,255 ,10 ,143 ,55 ,118 ,212 ,23 ,222 ,124 ,159 ,175 };
	unsigned char result0[32] = { 0x8B, 0xC2, 0xBD, 0xF9, 0x69, 0xB1, 0x6D, 0xC6, 
0xDE, 0x98, 0x71, 0xA6, 0x2E, 0x0E, 0x43, 0x62, 
0x50, 0x06, 0x62, 0xEC, 0x90, 0x9C, 0xB4, 0xBA, 
0x9C, 0x35, 0xCA, 0x7D, 0x0A, 0x6A, 0x5C, 0x73
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 17);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_19\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 17);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_19\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 17);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_19\n");


} 

void SHA256_Xcompare_20(){
	unsigned char input[15] = { 26 ,197 ,127 ,120 ,233 ,230 ,190 ,233 ,35 ,104 ,31 ,114 ,122 ,109 ,103 };
	unsigned char result0[32] = { 0xED, 0xBD, 0x5A, 0x34, 0x8F, 0xDE, 0xAF, 0xCF, 
0x5C, 0x0E, 0xE9, 0xA6, 0x75, 0x13, 0x85, 0x48, 
0x1B, 0x34, 0x3C, 0x92, 0x75, 0x45, 0x6F, 0x51, 
0x73, 0x3C, 0x32, 0x28, 0x90, 0xDD, 0x13, 0x89
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 15);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_20\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 15);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_20\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 15);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_20\n");


} 

void SHA256_Xcompare_21(){
	unsigned char input[61] = { 75 ,241 ,93 ,112 ,165 ,173 ,112 ,220 ,142 ,226 ,153 ,21 ,163 ,182 ,174 ,11 ,154 ,234 ,43 ,48 ,207 ,137 ,115 ,210 ,95 ,24 ,200 ,44 ,246 ,98 ,190 ,116 ,114 ,144 ,122 ,70 ,205 ,206 ,107 ,131 ,131 ,90 ,208 ,137 ,31 ,250 ,248 ,151 ,61 ,47 ,166 ,106 ,103 ,29 ,211 ,143 ,224 ,180 ,241 ,200 ,126 };
	unsigned char result0[32] = { 0x9C, 0xDB, 0x11, 0xC7, 0xC8, 0xC4, 0xB9, 0xC2, 
0xFC, 0x5C, 0xD3, 0x8A, 0xB1, 0x60, 0x58, 0x27, 
0xFD, 0x61, 0x22, 0xA2, 0x2E, 0x32, 0x5E, 0x5B, 
0x52, 0x41, 0xC9, 0xBF, 0xAB, 0x25, 0xF9, 0x8C
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 61);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_21\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 61);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_21\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 61);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_21\n");


} 

void SHA256_Xcompare_22(){
	unsigned char input[54] = { 62 ,78 ,75 ,28 ,165 ,221 ,69 ,172 ,73 ,34 ,37 ,0 ,171 ,179 ,188 ,152 ,85 ,171 ,119 ,188 ,126 ,74 ,155 ,193 ,175 ,88 ,55 ,103 ,240 ,16 ,39 ,156 ,211 ,189 ,113 ,230 ,3 ,229 ,190 ,36 ,65 ,145 ,255 ,225 ,82 ,156 ,251 ,123 ,6 ,180 ,150 ,111 ,112 ,18 };
	unsigned char result0[32] = { 0xA9, 0xFD, 0x35, 0xFA, 0xD8, 0xF1, 0x1A, 0x15, 
0xB2, 0x77, 0x2D, 0x26, 0xD2, 0x03, 0xC2, 0xFE, 
0x8A, 0xF5, 0xCA, 0x5C, 0x27, 0xA8, 0xFD, 0x75, 
0x6C, 0xD9, 0xA0, 0xA1, 0xD7, 0x42, 0x7F, 0xCE
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 54);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_22\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 54);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_22\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 54);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_22\n");


} 

void SHA256_Xcompare_23(){
	unsigned char input[10] = { 193 ,186 ,154 ,239 ,171 ,163 ,182 ,115 ,155 ,2 };
	unsigned char result0[32] = { 0x38, 0xA3, 0x4D, 0xAF, 0xEC, 0x12, 0x55, 0xB4, 
0x5E, 0x68, 0x49, 0xDC, 0x1C, 0xAD, 0x25, 0x1A, 
0x8E, 0x69, 0x01, 0xB8, 0x5F, 0xB2, 0xE9, 0xBA, 
0x35, 0x42, 0xB4, 0xCD, 0xAD, 0xF1, 0x79, 0x7C
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 10);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_23\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 10);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_23\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 10);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_23\n");


} 

void SHA256_Xcompare_24(){
	unsigned char input[77] = { 179 ,209 ,75 ,108 ,108 ,44 ,127 ,56 ,34 ,122 ,176 ,17 ,61 ,163 ,183 ,36 ,125 ,62 ,55 ,97 ,169 ,62 ,143 ,36 ,227 ,139 ,105 ,8 ,17 ,156 ,100 ,191 ,229 ,238 ,55 ,132 ,122 ,10 ,58 ,196 ,176 ,245 ,88 ,143 ,137 ,149 ,47 ,178 ,244 ,110 ,213 ,184 ,244 ,90 ,219 ,97 ,67 ,20 ,175 ,229 ,157 ,37 ,23 ,250 ,15 ,128 ,112 ,30 ,171 ,225 ,255 ,188 ,111 ,162 ,64 ,21 ,95 };
	unsigned char result0[32] = { 0x66, 0xF1, 0xAD, 0x2D, 0x13, 0x26, 0x0D, 0xA3, 
0x78, 0xE9, 0xAD, 0xD5, 0x87, 0x89, 0x11, 0x40, 
0x96, 0x97, 0x11, 0xD8, 0xC5, 0xBC, 0x2F, 0x13, 
0x8F, 0xC9, 0xAB, 0xE0, 0x6A, 0x74, 0xCF, 0x02
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 77);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_24\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 77);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_24\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 77);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_24\n");


} 

void SHA256_Xcompare_25(){
	unsigned char input[28] = { 120 ,54 ,200 ,126 ,152 ,183 ,39 ,51 ,96 ,178 ,20 ,197 ,241 ,144 ,41 ,175 ,124 ,143 ,21 ,195 ,101 ,185 ,209 ,16 ,82 ,236 ,62 ,6 };
	unsigned char result0[32] = { 0x66, 0x23, 0xED, 0xB0, 0x37, 0xA9, 0xD7, 0xBB, 
0x75, 0xD3, 0x3E, 0xBF, 0x37, 0x99, 0xF3, 0xA1, 
0xBA, 0xCC, 0x91, 0x8D, 0x8A, 0xE5, 0x9E, 0x59, 
0x11, 0x27, 0x2F, 0x4D, 0xF2, 0xB6, 0x58, 0x73
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 28);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_25\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 28);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_25\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 28);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_25\n");


} 

void SHA256_Xcompare_26(){
	unsigned char input[37] = { 100 ,117 ,123 ,73 ,179 ,52 ,142 ,97 ,238 ,112 ,99 ,218 ,92 ,139 ,43 ,253 ,238 ,247 ,225 ,254 ,204 ,209 ,125 ,241 ,24 ,156 ,47 ,37 ,189 ,214 ,165 ,138 ,170 ,38 ,120 ,181 ,216 };
	unsigned char result0[32] = { 0xA6, 0x32, 0x88, 0x38, 0xE6, 0xA8, 0x43, 0x7B, 
0xC4, 0x38, 0xA8, 0x52, 0x5A, 0x10, 0x39, 0x81, 
0xF1, 0x98, 0xBE, 0x6F, 0xEB, 0xCF, 0x6E, 0x56, 
0x26, 0x98, 0x78, 0x9C, 0x84, 0xFC, 0x2F, 0xA9
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 37);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_26\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 37);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_26\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 37);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_26\n");


} 

void SHA256_Xcompare_27(){
	unsigned char input[87] = { 181 ,101 ,177 ,159 ,5 ,210 ,78 ,52 ,147 ,243 ,175 ,230 ,10 ,195 ,129 ,64 ,73 ,230 ,218 ,163 ,131 ,216 ,239 ,182 ,64 ,53 ,237 ,108 ,48 ,226 ,9 ,186 ,119 ,33 ,110 ,111 ,75 ,132 ,198 ,111 ,221 ,121 ,254 ,225 ,167 ,202 ,198 ,117 ,137 ,41 ,1 ,130 ,232 ,188 ,113 ,90 ,151 ,179 ,119 ,202 ,0 ,96 ,202 ,194 ,174 ,153 ,83 ,74 ,77 ,17 ,97 ,93 ,127 ,197 ,198 ,23 ,17 ,66 ,93 ,122 ,197 ,186 ,41 ,126 ,26 ,222 ,169 };
	unsigned char result0[32] = { 0xC2, 0x67, 0x99, 0x37, 0x69, 0x95, 0x76, 0xFA, 
0x88, 0xF9, 0x96, 0x83, 0x0B, 0x64, 0x61, 0xA0, 
0xD5, 0xDF, 0xC6, 0xD7, 0x54, 0x01, 0x56, 0x55, 
0x16, 0x86, 0x1D, 0xC1, 0x26, 0x49, 0x77, 0xC4
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 87);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_27\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 87);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_27\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 87);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_27\n");


} 

void SHA256_Xcompare_28(){
	unsigned char input[23] = { 212 ,38 ,106 ,218 ,124 ,161 ,244 ,34 ,29 ,20 ,18 ,27 ,134 ,191 ,156 ,147 ,142 ,110 ,42 ,76 ,153 ,153 ,149 };
	unsigned char result0[32] = { 0x8B, 0x98, 0xE9, 0x11, 0x75, 0xB5, 0x7D, 0x0A, 
0x90, 0xF0, 0xCE, 0xA3, 0x35, 0xD0, 0x2B, 0xB4, 
0x3F, 0x86, 0x00, 0x60, 0xE4, 0x06, 0xDE, 0xE3, 
0x75, 0xFC, 0xA6, 0x7E, 0x01, 0x6A, 0x44, 0xA0
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 23);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_28\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 23);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_28\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 23);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_28\n");


} 

void SHA256_Xcompare_29(){
	unsigned char input[33] = { 10 ,185 ,24 ,116 ,51 ,86 ,197 ,210 ,151 ,114 ,156 ,213 ,206 ,204 ,233 ,222 ,175 ,43 ,56 ,249 ,8 ,108 ,197 ,156 ,116 ,129 ,69 ,190 ,49 ,228 ,56 ,139 ,67 };
	unsigned char result0[32] = { 0x81, 0x83, 0xCC, 0xD8, 0x6F, 0xD6, 0xB0, 0x43, 
0xC3, 0x41, 0x18, 0x2A, 0x28, 0xB6, 0x72, 0xF1, 
0x64, 0xC1, 0x5C, 0x1D, 0xA7, 0xF1, 0xAE, 0xC9, 
0x26, 0x8E, 0x16, 0x8B, 0x1A, 0xC0, 0xC0, 0xC7
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 33);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_29\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 33);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_29\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 33);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_29\n");


} 

void SHA256_Xcompare_30(){
	unsigned char input[49] = { 201 ,107 ,117 ,166 ,252 ,60 ,187 ,26 ,238 ,202 ,201 ,53 ,142 ,221 ,181 ,157 ,26 ,16 ,62 ,234 ,106 ,207 ,185 ,52 ,166 ,77 ,168 ,87 ,169 ,53 ,6 ,155 ,111 ,31 ,89 ,157 ,65 ,84 ,185 ,222 ,232 ,77 ,226 ,184 ,209 ,45 ,168 ,70 ,35 };
	unsigned char result0[32] = { 0x23, 0xDC, 0xD5, 0x9A, 0x59, 0x42, 0x91, 0xC7, 
0x3E, 0x40, 0x44, 0xE8, 0xED, 0xF4, 0xD1, 0x77, 
0xAB, 0xA2, 0x16, 0xE1, 0x56, 0x3D, 0xFC, 0x5E, 
0x90, 0x32, 0x45, 0xC2, 0x52, 0x4A, 0x02, 0xE6
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 49);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_30\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 49);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_30\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 49);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_30\n");


} 

void SHA256_Xcompare_31(){
	unsigned char input[25] = { 164 ,121 ,60 ,220 ,67 ,39 ,70 ,243 ,251 ,177 ,35 ,45 ,193 ,44 ,221 ,28 ,120 ,23 ,85 ,199 ,167 ,95 ,185 ,168 ,122 };
	unsigned char result0[32] = { 0xFF, 0xE6, 0x32, 0xD4, 0xD7, 0x51, 0x8B, 0x14, 
0x20, 0xDE, 0x4F, 0x19, 0x0A, 0xB2, 0x5B, 0xA8, 
0x85, 0x63, 0x92, 0x6F, 0x8F, 0x8E, 0x00, 0xFB, 
0xF8, 0xEE, 0xC5, 0xE0, 0x1D, 0x74, 0x4E, 0x49
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 25);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_31\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 25);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_31\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 25);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_31\n");


} 

void SHA256_Xcompare_32(){
	unsigned char input[48] = { 33 ,30 ,20 ,136 ,114 ,37 ,198 ,224 ,114 ,136 ,164 ,181 ,159 ,87 ,39 ,23 ,46 ,207 ,192 ,157 ,140 ,110 ,60 ,100 ,222 ,249 ,251 ,201 ,72 ,223 ,102 ,212 ,245 ,200 ,201 ,58 ,50 ,181 ,56 ,50 ,239 ,70 ,134 ,120 ,133 ,57 ,14 ,179 };
	unsigned char result0[32] = { 0xA0, 0xD8, 0x84, 0xB1, 0xE7, 0x53, 0x11, 0xDB, 
0xAB, 0xCB, 0x75, 0xD9, 0x9A, 0xE7, 0x23, 0x63, 
0x06, 0x37, 0xF5, 0x62, 0xB9, 0x83, 0xCB, 0x1B, 
0x3B, 0x42, 0x54, 0x2B, 0xFB, 0x18, 0x9C, 0xFA
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 48);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_32\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 48);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_32\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 48);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_32\n");


} 

void SHA256_Xcompare_33(){
	unsigned char input[9] = { 28 ,63 ,155 ,224 ,100 ,191 ,93 ,185 ,70 };
	unsigned char result0[32] = { 0xDA, 0xC6, 0x06, 0x9F, 0xFB, 0xB6, 0x40, 0x93, 
0x76, 0x14, 0x8C, 0x97, 0x3C, 0x12, 0x2A, 0xE0, 
0x03, 0x9B, 0xFB, 0x3B, 0x9E, 0x5D, 0x59, 0x7B, 
0x16, 0x6A, 0xBD, 0xA0, 0xE5, 0x91, 0x55, 0xE1
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 9);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_33\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 9);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_33\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 9);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_33\n");


} 

void SHA256_Xcompare_34(){
	unsigned char input[31] = { 226 ,50 ,138 ,61 ,30 ,31 ,200 ,138 ,33 ,119 ,171 ,164 ,198 ,29 ,66 ,99 ,154 ,31 ,53 ,120 ,243 ,166 ,132 ,59 ,153 ,181 ,36 ,44 ,205 ,67 ,112 };
	unsigned char result0[32] = { 0xFB, 0x07, 0xE7, 0x99, 0x19, 0x95, 0xE5, 0x97, 
0x86, 0x56, 0xE9, 0x00, 0x13, 0x7F, 0xF9, 0xF5, 
0xE4, 0x75, 0x2E, 0x8C, 0xFD, 0x53, 0x2D, 0x3B, 
0xC4, 0xF0, 0x5B, 0xE7, 0x6E, 0x7B, 0xA7, 0x3B
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 31);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_34\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 31);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_34\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 31);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_34\n");


} 

void SHA256_Xcompare_35(){
	unsigned char input[79] = { 194 ,110 ,162 ,37 ,162 ,113 ,122 ,100 ,202 ,225 ,115 ,149 ,109 ,216 ,92 ,100 ,198 ,68 ,161 ,6 ,100 ,30 ,215 ,228 ,196 ,105 ,118 ,3 ,135 ,97 ,233 ,30 ,47 ,174 ,240 ,122 ,63 ,211 ,185 ,170 ,53 ,195 ,144 ,84 ,157 ,76 ,216 ,215 ,238 ,220 ,5 ,56 ,15 ,111 ,156 ,7 ,254 ,102 ,231 ,129 ,177 ,28 ,68 ,175 ,208 ,174 ,122 ,218 ,176 ,43 ,194 ,187 ,155 ,198 ,215 ,243 ,90 ,170 ,131 };
	unsigned char result0[32] = { 0xA6, 0xAD, 0xB1, 0x28, 0x21, 0x4C, 0xB3, 0xD8, 
0x5C, 0x64, 0x48, 0x8A, 0x3E, 0x2B, 0xA1, 0x46, 
0x95, 0x66, 0xA0, 0x70, 0xB2, 0xAA, 0xA3, 0xF8, 
0x3F, 0xA0, 0xF9, 0x35, 0x00, 0x3F, 0x7B, 0x84
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 79);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_35\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 79);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_35\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 79);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_35\n");


} 

void SHA256_Xcompare_36(){
	unsigned char input[23] = { 196 ,101 ,93 ,29 ,151 ,114 ,56 ,63 ,51 ,187 ,246 ,131 ,162 ,41 ,183 ,134 ,179 ,156 ,227 ,40 ,66 ,180 ,208 };
	unsigned char result0[32] = { 0x07, 0x1B, 0x93, 0xC4, 0x48, 0xAE, 0xB1, 0xED, 
0x07, 0x5B, 0x5E, 0xBD, 0xB3, 0xA7, 0x41, 0x67, 
0x9E, 0x56, 0x31, 0x93, 0xD7, 0xE7, 0x05, 0xF7, 
0xBA, 0xAA, 0xF3, 0x46, 0x72, 0x90, 0x6B, 0x95
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 23);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_36\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 23);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_36\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 23);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_36\n");


} 

void SHA256_Xcompare_37(){
	unsigned char input[83] = { 157 ,178 ,174 ,22 ,243 ,238 ,82 ,159 ,160 ,142 ,67 ,241 ,227 ,141 ,194 ,90 ,183 ,157 ,225 ,16 ,136 ,150 ,156 ,201 ,163 ,90 ,245 ,142 ,230 ,101 ,102 ,253 ,231 ,81 ,245 ,110 ,206 ,41 ,156 ,185 ,157 ,114 ,50 ,16 ,248 ,95 ,79 ,41 ,181 ,126 ,125 ,117 ,118 ,164 ,59 ,153 ,239 ,160 ,80 ,1 ,68 ,44 ,220 ,64 ,13 ,140 ,133 ,141 ,205 ,124 ,224 ,179 ,6 ,70 ,236 ,231 ,142 ,223 ,114 ,12 ,84 ,179 ,160 };
	unsigned char result0[32] = { 0x34, 0x5E, 0x96, 0x40, 0xD6, 0x44, 0xAB, 0x66, 
0x09, 0xE7, 0x92, 0x05, 0xDF, 0x25, 0x14, 0xA2, 
0xD5, 0x13, 0xAE, 0xBA, 0xFC, 0x79, 0x6B, 0x1D, 
0x7F, 0x66, 0x7C, 0x2C, 0xFD, 0xD1, 0x24, 0x7F
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 83);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_37\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 83);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_37\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 83);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_37\n");


} 

void SHA256_Xcompare_38(){
	unsigned char input[98] = { 136 ,105 ,253 ,240 ,80 ,254 ,221 ,186 ,192 ,21 ,186 ,156 ,44 ,186 ,111 ,143 ,201 ,42 ,144 ,114 ,37 ,150 ,204 ,20 ,228 ,99 ,159 ,10 ,192 ,235 ,254 ,48 ,131 ,68 ,175 ,58 ,107 ,9 ,240 ,74 ,138 ,234 ,213 ,22 ,104 ,84 ,146 ,38 ,198 ,151 ,198 ,34 ,34 ,113 ,184 ,240 ,196 ,24 ,243 ,66 ,60 ,211 ,131 ,51 ,45 ,242 ,174 ,184 ,26 ,185 ,90 ,90 ,69 ,211 ,174 ,239 ,198 ,162 ,251 ,28 ,82 ,131 ,243 ,19 ,77 ,218 ,217 ,177 ,236 ,40 ,119 ,40 ,12 ,52 ,129 ,220 ,131 ,181 };
	unsigned char result0[32] = { 0xA2, 0x61, 0xDE, 0x5C, 0xA7, 0x72, 0xA9, 0x92, 
0x19, 0x25, 0xCD, 0x1D, 0x10, 0x6B, 0x21, 0x7C, 
0x02, 0xC1, 0x2F, 0x2F, 0x2B, 0xD7, 0xEA, 0x49, 
0x7E, 0x41, 0x1E, 0xFB, 0xCF, 0x92, 0xA2, 0x5F
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 98);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_38\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 98);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_38\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 98);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_38\n");


} 

void SHA256_Xcompare_39(){
	unsigned char input[80] = { 161 ,60 ,178 ,205 ,204 ,53 ,144 ,61 ,181 ,93 ,147 ,13 ,82 ,96 ,193 ,178 ,100 ,120 ,84 ,149 ,9 ,76 ,224 ,125 ,184 ,118 ,74 ,18 ,5 ,62 ,93 ,184 ,163 ,93 ,62 ,229 ,198 ,59 ,242 ,117 ,172 ,219 ,76 ,102 ,64 ,239 ,110 ,239 ,203 ,134 ,54 ,254 ,17 ,143 ,93 ,79 ,179 ,181 ,159 ,134 ,129 ,21 ,52 ,190 ,32 ,174 ,137 ,174 ,66 ,245 ,133 ,124 ,231 ,144 ,129 ,26 ,13 ,153 ,178 ,249 };
	unsigned char result0[32] = { 0x43, 0x4D, 0x7F, 0xF5, 0x64, 0x64, 0x4A, 0x5B, 
0x27, 0xF6, 0xAF, 0xB9, 0x2D, 0x31, 0x93, 0xBD, 
0xAF, 0x6B, 0x8E, 0xD9, 0x59, 0xDA, 0xF3, 0x14, 
0xE5, 0x9E, 0xAE, 0x43, 0xF9, 0x65, 0x19, 0xCC
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 80);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_39\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 80);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_39\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 80);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_39\n");


} 

void SHA256_Xcompare_40(){
	unsigned char input[12] = { 132 ,227 ,15 ,162 ,142 ,76 ,249 ,147 ,18 ,167 ,83 ,54 };
	unsigned char result0[32] = { 0x5B, 0xB2, 0x61, 0xF9, 0x65, 0x82, 0x7C, 0xDF, 
0xE6, 0x76, 0x9C, 0xE5, 0xB7, 0x91, 0x7A, 0x4B, 
0x55, 0xFB, 0x38, 0x6F, 0xC3, 0xA7, 0xEB, 0xE6, 
0x6E, 0xE2, 0x13, 0xBE, 0x65, 0x68, 0xF5, 0xFD
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 12);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_40\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 12);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_40\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 12);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_40\n");


} 

void SHA256_Xcompare_41(){
	unsigned char input[3] = { 148 ,57 ,224 };
	unsigned char result0[32] = { 0x1D, 0xD0, 0x8B, 0x1F, 0xA9, 0xD1, 0x38, 0xDF, 
0x7A, 0xBD, 0xAD, 0x26, 0x68, 0x1E, 0x89, 0x27, 
0x5B, 0x52, 0xBE, 0xDC, 0x1A, 0x20, 0xC0, 0x8A, 
0xFB, 0x66, 0x2C, 0xB9, 0x93, 0xE4, 0x20, 0x8E
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 3);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_41\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 3);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_41\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 3);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_41\n");


} 

void SHA256_Xcompare_42(){
	unsigned char input[6] = { 15 ,238 ,173 ,16 ,189 ,111 };
	unsigned char result0[32] = { 0xBB, 0xE2, 0x53, 0xD4, 0xE4, 0xAD, 0x31, 0x2B, 
0xC8, 0xE7, 0xC7, 0x63, 0x94, 0xE6, 0xFB, 0x17, 
0x17, 0x18, 0x46, 0x62, 0xEE, 0x09, 0x72, 0xC3, 
0xDB, 0x34, 0xB5, 0xD8, 0xFE, 0x8B, 0x23, 0x93
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 6);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_42\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 6);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_42\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 6);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_42\n");


} 

void SHA256_Xcompare_43(){
	unsigned char input[20] = { 24 ,2 ,167 ,66 ,115 ,188 ,140 ,236 ,20 ,248 ,209 ,104 ,83 ,11 ,209 ,58 ,178 ,153 ,244 ,98 };
	unsigned char result0[32] = { 0xDB, 0x6E, 0x28, 0x91, 0x61, 0x6E, 0x53, 0x2C, 
0xAB, 0xEA, 0xA6, 0xC9, 0x50, 0x18, 0x86, 0x55, 
0x3F, 0x5D, 0x0E, 0x36, 0x2C, 0x1E, 0x35, 0xC9, 
0x1E, 0x4A, 0xF9, 0xFE, 0xC7, 0xD6, 0x32, 0x40
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 20);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_43\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 20);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_43\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 20);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_43\n");


} 

void SHA256_Xcompare_44(){
	unsigned char input[74] = { 231 ,53 ,154 ,143 ,199 ,113 ,142 ,131 ,84 ,236 ,168 ,66 ,130 ,144 ,218 ,149 ,221 ,175 ,168 ,0 ,218 ,60 ,124 ,132 ,231 ,61 ,41 ,208 ,11 ,86 ,37 ,33 ,63 ,223 ,72 ,149 ,108 ,181 ,244 ,52 ,248 ,162 ,110 ,33 ,193 ,79 ,42 ,8 ,202 ,48 ,197 ,46 ,200 ,36 ,50 ,96 ,171 ,159 ,126 ,70 ,41 ,254 ,183 ,212 ,197 ,190 ,149 ,235 ,42 ,7 ,210 ,39 ,239 ,65 };
	unsigned char result0[32] = { 0x27, 0x89, 0x84, 0xD9, 0x64, 0x8D, 0xB8, 0xEC, 
0x2D, 0x35, 0xF9, 0xD7, 0x40, 0x97, 0x99, 0x04, 
0x1B, 0xAC, 0x3A, 0x2B, 0xDC, 0x0E, 0x88, 0xE3, 
0xEF, 0x77, 0x97, 0xA9, 0x15, 0x58, 0xB3, 0xB3
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 74);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_44\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 74);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_44\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 74);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_44\n");


} 

void SHA256_Xcompare_45(){
	unsigned char input[7] = { 84 ,24 ,248 ,77 ,128 ,98 ,250 };
	unsigned char result0[32] = { 0x81, 0xA5, 0x2D, 0xBD, 0x19, 0xAA, 0xB5, 0x9C, 
0x18, 0x26, 0xE6, 0x4D, 0xA5, 0xB3, 0x1E, 0xF4, 
0x9E, 0x3C, 0x39, 0x14, 0xE3, 0xB4, 0x5A, 0xD7, 
0x6D, 0x2E, 0x98, 0x0C, 0xDE, 0xEF, 0x43, 0xEF
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 7);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_45\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 7);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_45\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 7);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_45\n");


} 

void SHA256_Xcompare_46(){
	unsigned char input[49] = { 198 ,28 ,182 ,61 ,14 ,170 ,107 ,109 ,117 ,69 ,183 ,84 ,216 ,59 ,177 ,110 ,11 ,237 ,9 ,19 ,205 ,155 ,51 ,48 ,170 ,178 ,2 ,241 ,167 ,217 ,14 ,253 ,173 ,153 ,108 ,27 ,198 ,55 ,184 ,250 ,70 ,124 ,73 ,166 ,132 ,252 ,228 ,4 ,206 };
	unsigned char result0[32] = { 0xE0, 0x7E, 0xD1, 0x82, 0x84, 0x32, 0x0D, 0x22, 
0xEE, 0x3C, 0xE7, 0x8B, 0x40, 0xCB, 0x83, 0x0C, 
0xC7, 0x8B, 0x05, 0xB9, 0x9B, 0xDC, 0x66, 0x16, 
0x10, 0x46, 0x50, 0x23, 0x38, 0xEA, 0x17, 0x03
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 49);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_46\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 49);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_46\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 49);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_46\n");


} 

void SHA256_Xcompare_47(){
	unsigned char input[96] = { 176 ,211 ,99 ,9 ,35 ,126 ,49 ,93 ,15 ,190 ,29 ,35 ,40 ,78 ,147 ,34 ,155 ,145 ,32 ,84 ,123 ,91 ,93 ,210 ,50 ,92 ,159 ,85 ,237 ,121 ,105 ,173 ,66 ,122 ,238 ,82 ,186 ,221 ,83 ,81 ,0 ,125 ,158 ,85 ,136 ,1 ,90 ,188 ,244 ,1 ,31 ,85 ,120 ,222 ,46 ,210 ,109 ,91 ,240 ,119 ,215 ,160 ,130 ,230 ,211 ,85 ,242 ,10 ,46 ,155 ,230 ,191 ,249 ,75 ,36 ,179 ,202 ,194 ,214 ,252 ,216 ,172 ,84 ,89 ,233 ,203 ,102 ,94 ,88 ,31 ,212 ,14 ,53 ,217 ,40 ,207 };
	unsigned char result0[32] = { 0x9E, 0x92, 0x93, 0x1D, 0x89, 0xA9, 0xBA, 0x85, 
0x14, 0xBD, 0x27, 0xAD, 0x6E, 0xAC, 0xCE, 0xC2, 
0x31, 0x10, 0x87, 0x24, 0x7F, 0x65, 0xC4, 0xAE, 
0x8F, 0x52, 0xB5, 0x4C, 0xB1, 0xD6, 0xBB, 0x3C
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 96);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_47\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 96);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_47\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 96);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_47\n");


} 

void SHA256_Xcompare_48(){
	unsigned char input[0] = {};
	unsigned char result0[32] = { 0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14, 
0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F, 0xB9, 0x24, 
0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C, 
0xA4, 0x95, 0x99, 0x1B, 0x78, 0x52, 0xB8, 0x55
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 0);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_48\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 0);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_48\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 0);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_48\n");


} 

void SHA256_Xcompare_49(){
	unsigned char input[69] = { 85 ,139 ,197 ,12 ,231 ,221 ,208 ,93 ,78 ,177 ,190 ,235 ,112 ,13 ,215 ,52 ,242 ,189 ,62 ,13 ,252 ,80 ,17 ,107 ,145 ,218 ,111 ,168 ,8 ,61 ,141 ,27 ,212 ,126 ,110 ,97 ,111 ,72 ,157 ,95 ,100 ,90 ,118 ,84 ,100 ,226 ,139 ,243 ,221 ,130 ,234 ,97 ,243 ,100 ,183 ,176 ,248 ,208 ,87 ,55 ,187 ,88 ,45 ,59 ,26 ,214 ,76 ,106 ,2 };
	unsigned char result0[32] = { 0xE5, 0xC5, 0xEA, 0xFF, 0x14, 0xAE, 0x1F, 0x06, 
0xB6, 0xDB, 0x0F, 0xEB, 0x1E, 0x8F, 0x27, 0xAE, 
0x18, 0x83, 0x61, 0x5F, 0xAD, 0x68, 0x63, 0x18, 
0x40, 0xF4, 0x4B, 0xC5, 0x08, 0x98, 0xF0, 0x72
 };
	unsigned char result1[32];

	memset(result1, 0, 32);
	SHA256_VST(input, result1, 69);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_VST in SHA256_Xcompare_49\n");

	memset(result1, 0, 32);
	SHA256_NSS(input, result1, 69);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_NSS in SHA256_Xcompare_49\n");

	memset(result1, 0, 32);
	SHA256_sodium(input, result1, 69);
	check_test(result0, result1, 32, "Disagreement between given answer and SHA256_sodium in SHA256_Xcompare_49\n");


} 
