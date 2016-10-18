/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2016 University of Luxembourg
 *
 * Written in 2016 by Daniel Dinu <dumitru-daniel.dinu@uni.lu>
 *
 * This file is part of FELICS.
 *
 * FELICS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * FELICS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdint.h>

#include "test_vectors.h"


/*
 *
 * Test vectors
 *
 */
/*const uint8_t expectedKey[KEY_SIZE] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const uint8_t expectedIV[IV_SIZE] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const uint8_t expectedPlaintext[TEST_STREAM_SIZE] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const uint8_t expectedCiphertext[TEST_STREAM_SIZE] = {
	0x89, 0x67, 0x09, 0x52, 0x60, 0x83, 0x64, 0xfd, 
	0x00, 0xb2, 0xf9, 0x09, 0x36, 0xf0, 0x31, 0xc8, 
	0xe7, 0x56, 0xe1, 0x5d, 0xba, 0x04, 0xb8, 0x49,
	0x3d, 0x00, 0x42, 0x92, 0x59, 0xb2, 0x0f, 0x46,
	0xcc, 0x04, 0xf1, 0x11, 0x24, 0x6b, 0x6c, 0x2c,
	0xe0, 0x66, 0xbe, 0x3b, 0xfb, 0x32, 0xd9, 0xaa,
	0x0f, 0xdd, 0xfb, 0xc1, 0x21, 0x23, 0xd4, 0xb9,
	0xe4, 0x4f, 0x34, 0xdc, 0xa0, 0x5a, 0x10, 0x3f};*/

/*const uint8_t expectedKey[KEY_SIZE] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
const uint8_t expectedIV[IV_SIZE] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
const uint8_t expectedPlaintext[TEST_STREAM_SIZE] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const uint8_t expectedCiphertext[TEST_STREAM_SIZE] = {
	0x99, 0x29, 0x47, 0xc3, 0x96, 0x61, 0x26, 0xa0, 
	0xe6, 0x60, 0xa3, 0xe9, 0x5d, 0xb0, 0x48, 0xde, 
	0x09, 0x1f, 0xb9, 0xe0, 0x18, 0x5b, 0x1e, 0x41, 
	0xe4, 0x10, 0x15, 0xbb, 0x7e, 0xe5, 0x01, 0x50, 
	0x39, 0x9e, 0x47, 0x60, 0xb2, 0x62, 0xf9, 0xd5,
	0x3f, 0x26, 0xd8, 0xdd, 0x19, 0xe5, 0x6f, 0x5c, 
	0x50, 0x6a, 0xe0, 0xc3, 0x61, 0x9f, 0xa6, 0x7f, 
	0xb0, 0xc4, 0x08, 0x10, 0x6d, 0x02, 0x03, 0xee};*/

/*const uint8_t expectedKey[KEY_SIZE] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
const uint8_t expectedIV[IV_SIZE] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const uint8_t expectedPlaintext[TEST_STREAM_SIZE] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const uint8_t expectedCiphertext[TEST_STREAM_SIZE] = {
	0x3b, 0x91, 0xca, 0x82, 0x95, 0xfd, 0x46, 0x65, 
	0x44, 0x14, 0x9b, 0x7c, 0xc0, 0x71, 0x68, 0x56, 
	0x2a, 0xbd, 0xf6, 0x08, 0x68, 0x30, 0x8d, 0xb0, 
	0xda, 0xa0, 0xe8, 0xc4, 0x18, 0xe3, 0x2d, 0x24, 
	0x0d, 0x00, 0x45, 0x09, 0x44, 0x76, 0x08, 0x5d, 
	0x8f, 0x1b, 0x60, 0x8d, 0xd2, 0xa7, 0x36, 0xe2, 
	0xf7, 0xdf, 0x19, 0xe2, 0x1d, 0x18, 0x3e, 0x78, 
	0x72, 0x00, 0x4e, 0xa6, 0x6c, 0xfc, 0xa8, 0x5a};*/

/*const uint8_t expectedKey[KEY_SIZE] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const uint8_t expectedIV[IV_SIZE] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
const uint8_t expectedPlaintext[TEST_STREAM_SIZE] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const uint8_t expectedCiphertext[TEST_STREAM_SIZE] = {
	0x26, 0x9d, 0x73, 0x6d, 0x22, 0xcd, 0x77, 0xf7, 
	0xb8, 0x6d, 0x9f, 0x66, 0x9e, 0x75, 0x52, 0xb2, 
	0x2e, 0xf0, 0x67, 0xcb, 0xb1, 0x40, 0xdf, 0xd4, 
	0x54, 0x05, 0x9f, 0x55, 0x49, 0xda, 0x8d, 0x0f, 
	0x1d, 0x7e, 0xb4, 0xfc, 0xa1, 0x13, 0x77, 0xb6, 
	0xb6, 0xa1, 0xdc, 0x34, 0xb6, 0x0b, 0x26, 0x66, 
	0x6b, 0x56, 0x12, 0x60, 0x6a, 0x0b, 0xf3, 0xfd, 
	0x19, 0x71, 0x0f, 0x40, 0x7f, 0xeb, 0xbb, 0x6e};*/

/*const uint8_t expectedKey[KEY_SIZE] = {
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
const uint8_t expectedIV[IV_SIZE] = {
	0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00};
const uint8_t expectedPlaintext[TEST_STREAM_SIZE] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const uint8_t expectedCiphertext[TEST_STREAM_SIZE] = {
	0x3c, 0xe1, 0xa8, 0x16, 0x66, 0xeb, 0x97, 0x6a, 
	0x21, 0xd6, 0x64, 0x86, 0x67, 0xbb, 0x3d, 0x97, 
	0xb0, 0x51, 0x28, 0x3d, 0x8f, 0xa8, 0x70, 0x10, 
	0x78, 0x6a, 0x01, 0x4b, 0x50, 0xd0, 0x1b, 0xf8, 
	0x59, 0x78, 0xd6, 0xad, 0x25, 0xf7, 0xca, 0x3e, 
	0x28, 0x74, 0xb3, 0xea, 0x4a, 0xe0, 0x48, 0x41, 
	0xc2, 0xb0, 0x0f, 0x7b, 0x5b, 0x98, 0x15, 0x94, 
	0x45, 0x6a, 0x0b, 0xad, 0x57, 0x8b, 0xb9, 0xed};*/

const uint8_t expectedKey[KEY_SIZE] = {
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
const uint8_t expectedIV[IV_SIZE] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
const uint8_t expectedPlaintext[TEST_STREAM_SIZE] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const uint8_t expectedCiphertext[TEST_STREAM_SIZE] = {
	0x65, 0x1b, 0x2f, 0x39, 0x5a, 0x38, 0xfa, 0x5c, 
	0xbb, 0xb1, 0xc3, 0x30, 0xb4, 0x8a, 0xb2, 0x3a, 
	0x27, 0x05, 0x55, 0xa8, 0x85, 0x46, 0x0b, 0xed, 
	0x99, 0xef, 0xa7, 0xcc, 0xec, 0xee, 0x6e, 0x41, 
	0x97, 0xda, 0x6e, 0x9d, 0x1b, 0x55, 0x50, 0xa0, 
	0x68, 0x81, 0x08, 0xe0, 0x48, 0x09, 0x00, 0x4f, 
	0x29, 0x05, 0xba, 0x49, 0x02, 0x4d, 0x06, 0xcd, 
	0xfa, 0xf1, 0xb4, 0x33, 0x5d, 0x0c, 0xac, 0x9a};
