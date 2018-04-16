#include "LUOV.h"

uint64_t expandTable(unsigned char a)
{
	static const uint64_t eT[256] =
	{
		0x0000000000000000,		0x00000000000000ff,		0x000000000000ff00,		0x000000000000ffff,
		0x0000000000ff0000,		0x0000000000ff00ff,		0x0000000000ffff00,		0x0000000000ffffff,
		0x00000000ff000000,		0x00000000ff0000ff,		0x00000000ff00ff00,		0x00000000ff00ffff,
		0x00000000ffff0000,		0x00000000ffff00ff,		0x00000000ffffff00,		0x00000000ffffffff,
		0x000000ff00000000,		0x000000ff000000ff,		0x000000ff0000ff00,		0x000000ff0000ffff,
		0x000000ff00ff0000,		0x000000ff00ff00ff,		0x000000ff00ffff00,		0x000000ff00ffffff,
		0x000000ffff000000,		0x000000ffff0000ff,		0x000000ffff00ff00,		0x000000ffff00ffff,
		0x000000ffffff0000,		0x000000ffffff00ff,		0x000000ffffffff00,		0x000000ffffffffff,
		0x0000ff0000000000,		0x0000ff00000000ff,		0x0000ff000000ff00,		0x0000ff000000ffff,
		0x0000ff0000ff0000,		0x0000ff0000ff00ff,		0x0000ff0000ffff00,		0x0000ff0000ffffff,
		0x0000ff00ff000000,		0x0000ff00ff0000ff,		0x0000ff00ff00ff00,		0x0000ff00ff00ffff,
		0x0000ff00ffff0000,		0x0000ff00ffff00ff,		0x0000ff00ffffff00,		0x0000ff00ffffffff,
		0x0000ffff00000000,		0x0000ffff000000ff,		0x0000ffff0000ff00,		0x0000ffff0000ffff,
		0x0000ffff00ff0000,		0x0000ffff00ff00ff,		0x0000ffff00ffff00,		0x0000ffff00ffffff,
		0x0000ffffff000000,		0x0000ffffff0000ff,		0x0000ffffff00ff00,		0x0000ffffff00ffff,
		0x0000ffffffff0000,		0x0000ffffffff00ff,		0x0000ffffffffff00,		0x0000ffffffffffff,
		0x00ff000000000000,		0x00ff0000000000ff,		0x00ff00000000ff00,		0x00ff00000000ffff,
		0x00ff000000ff0000,		0x00ff000000ff00ff,		0x00ff000000ffff00,		0x00ff000000ffffff,
		0x00ff0000ff000000,		0x00ff0000ff0000ff,		0x00ff0000ff00ff00,		0x00ff0000ff00ffff,
		0x00ff0000ffff0000,		0x00ff0000ffff00ff,		0x00ff0000ffffff00,		0x00ff0000ffffffff,
		0x00ff00ff00000000,		0x00ff00ff000000ff,		0x00ff00ff0000ff00,		0x00ff00ff0000ffff,
		0x00ff00ff00ff0000,		0x00ff00ff00ff00ff,		0x00ff00ff00ffff00,		0x00ff00ff00ffffff,
		0x00ff00ffff000000,		0x00ff00ffff0000ff,		0x00ff00ffff00ff00,		0x00ff00ffff00ffff,
		0x00ff00ffffff0000,		0x00ff00ffffff00ff,		0x00ff00ffffffff00,		0x00ff00ffffffffff,
		0x00ffff0000000000,		0x00ffff00000000ff,		0x00ffff000000ff00,		0x00ffff000000ffff,
		0x00ffff0000ff0000,		0x00ffff0000ff00ff,		0x00ffff0000ffff00,		0x00ffff0000ffffff,
		0x00ffff00ff000000,		0x00ffff00ff0000ff,		0x00ffff00ff00ff00,		0x00ffff00ff00ffff,
		0x00ffff00ffff0000,		0x00ffff00ffff00ff,		0x00ffff00ffffff00,		0x00ffff00ffffffff,
		0x00ffffff00000000,		0x00ffffff000000ff,		0x00ffffff0000ff00,		0x00ffffff0000ffff,
		0x00ffffff00ff0000,		0x00ffffff00ff00ff,		0x00ffffff00ffff00,		0x00ffffff00ffffff,
		0x00ffffffff000000,		0x00ffffffff0000ff,		0x00ffffffff00ff00,		0x00ffffffff00ffff,
		0x00ffffffffff0000,		0x00ffffffffff00ff,		0x00ffffffffffff00,		0x00ffffffffffffff,
		0xff00000000000000,		0xff000000000000ff,		0xff0000000000ff00,		0xff0000000000ffff,
		0xff00000000ff0000,		0xff00000000ff00ff,		0xff00000000ffff00,		0xff00000000ffffff,
		0xff000000ff000000,		0xff000000ff0000ff,		0xff000000ff00ff00,		0xff000000ff00ffff,
		0xff000000ffff0000,		0xff000000ffff00ff,		0xff000000ffffff00,		0xff000000ffffffff,
		0xff0000ff00000000,		0xff0000ff000000ff,		0xff0000ff0000ff00,		0xff0000ff0000ffff,
		0xff0000ff00ff0000,		0xff0000ff00ff00ff,		0xff0000ff00ffff00,		0xff0000ff00ffffff,
		0xff0000ffff000000,		0xff0000ffff0000ff,		0xff0000ffff00ff00,		0xff0000ffff00ffff,
		0xff0000ffffff0000,		0xff0000ffffff00ff,		0xff0000ffffffff00,		0xff0000ffffffffff,
		0xff00ff0000000000,		0xff00ff00000000ff,		0xff00ff000000ff00,		0xff00ff000000ffff,
		0xff00ff0000ff0000,		0xff00ff0000ff00ff,		0xff00ff0000ffff00,		0xff00ff0000ffffff,
		0xff00ff00ff000000,		0xff00ff00ff0000ff,		0xff00ff00ff00ff00,		0xff00ff00ff00ffff,
		0xff00ff00ffff0000,		0xff00ff00ffff00ff,		0xff00ff00ffffff00,		0xff00ff00ffffffff,
		0xff00ffff00000000,		0xff00ffff000000ff,		0xff00ffff0000ff00,		0xff00ffff0000ffff,
		0xff00ffff00ff0000,		0xff00ffff00ff00ff,		0xff00ffff00ffff00,		0xff00ffff00ffffff,
		0xff00ffffff000000,		0xff00ffffff0000ff,		0xff00ffffff00ff00,		0xff00ffffff00ffff,
		0xff00ffffffff0000,		0xff00ffffffff00ff,		0xff00ffffffffff00,		0xff00ffffffffffff,
		0xffff000000000000,		0xffff0000000000ff,		0xffff00000000ff00,		0xffff00000000ffff,
		0xffff000000ff0000,		0xffff000000ff00ff,		0xffff000000ffff00,		0xffff000000ffffff,
		0xffff0000ff000000,		0xffff0000ff0000ff,		0xffff0000ff00ff00,		0xffff0000ff00ffff,
		0xffff0000ffff0000,		0xffff0000ffff00ff,		0xffff0000ffffff00,		0xffff0000ffffffff,
		0xffff00ff00000000,		0xffff00ff000000ff,		0xffff00ff0000ff00,		0xffff00ff0000ffff,
		0xffff00ff00ff0000,		0xffff00ff00ff00ff,		0xffff00ff00ffff00,		0xffff00ff00ffffff,
		0xffff00ffff000000,		0xffff00ffff0000ff,		0xffff00ffff00ff00,		0xffff00ffff00ffff,
		0xffff00ffffff0000,		0xffff00ffffff00ff,		0xffff00ffffffff00,		0xffff00ffffffffff,
		0xffffff0000000000,		0xffffff00000000ff,		0xffffff000000ff00,		0xffffff000000ffff,
		0xffffff0000ff0000,		0xffffff0000ff00ff,		0xffffff0000ffff00,		0xffffff0000ffffff,
		0xffffff00ff000000,		0xffffff00ff0000ff,		0xffffff00ff00ff00,		0xffffff00ff00ffff,
		0xffffff00ffff0000,		0xffffff00ffff00ff,		0xffffff00ffffff00,		0xffffff00ffffffff,
		0xffffffff00000000,		0xffffffff000000ff,		0xffffffff0000ff00,		0xffffffff0000ffff,
		0xffffffff00ff0000,		0xffffffff00ff00ff,		0xffffffff00ffff00,		0xffffffff00ffffff,
		0xffffffffff000000,		0xffffffffff0000ff,		0xffffffffff00ff00,		0xffffffffff00ffff,
		0xffffffffffff0000,		0xffffffffffff00ff,		0xffffffffffffff00,		0xffffffffffffffff
	};
	return eT[a];
}

uint64_t repeatTable(unsigned char a)
{
	static const uint64_t rT[256] =
	{
		0x0000000000000000,		0x0101010101010101,		0x0202020202020202,		0x0303030303030303,
		0x0404040404040404,		0x0505050505050505,		0x0606060606060606,		0x0707070707070707,
		0x0808080808080808,		0x0909090909090909,		0x0a0a0a0a0a0a0a0a,		0x0b0b0b0b0b0b0b0b,
		0x0c0c0c0c0c0c0c0c,		0x0d0d0d0d0d0d0d0d,		0x0e0e0e0e0e0e0e0e,		0x0f0f0f0f0f0f0f0f,
		0x1010101010101010,		0x1111111111111111,		0x1212121212121212,		0x1313131313131313,
		0x1414141414141414,		0x1515151515151515,		0x1616161616161616,		0x1717171717171717,
		0x1818181818181818,		0x1919191919191919,		0x1a1a1a1a1a1a1a1a,		0x1b1b1b1b1b1b1b1b,
		0x1c1c1c1c1c1c1c1c,		0x1d1d1d1d1d1d1d1d,		0x1e1e1e1e1e1e1e1e,		0x1f1f1f1f1f1f1f1f,
		0x2020202020202020,		0x2121212121212121,		0x2222222222222222,		0x2323232323232323,
		0x2424242424242424,		0x2525252525252525,		0x2626262626262626,		0x2727272727272727,
		0x2828282828282828,		0x2929292929292929,		0x2a2a2a2a2a2a2a2a,		0x2b2b2b2b2b2b2b2b,
		0x2c2c2c2c2c2c2c2c,		0x2d2d2d2d2d2d2d2d,		0x2e2e2e2e2e2e2e2e,		0x2f2f2f2f2f2f2f2f,
		0x3030303030303030,		0x3131313131313131,		0x3232323232323232,		0x3333333333333333,
		0x3434343434343434,		0x3535353535353535,		0x3636363636363636,		0x3737373737373737,
		0x3838383838383838,		0x3939393939393939,		0x3a3a3a3a3a3a3a3a,		0x3b3b3b3b3b3b3b3b,
		0x3c3c3c3c3c3c3c3c,		0x3d3d3d3d3d3d3d3d,		0x3e3e3e3e3e3e3e3e,		0x3f3f3f3f3f3f3f3f,
		0x4040404040404040,		0x4141414141414141,		0x4242424242424242,		0x4343434343434343,
		0x4444444444444444,		0x4545454545454545,		0x4646464646464646,		0x4747474747474747,
		0x4848484848484848,		0x4949494949494949,		0x4a4a4a4a4a4a4a4a,		0x4b4b4b4b4b4b4b4b,
		0x4c4c4c4c4c4c4c4c,		0x4d4d4d4d4d4d4d4d,		0x4e4e4e4e4e4e4e4e,		0x4f4f4f4f4f4f4f4f,
		0x5050505050505050,		0x5151515151515151,		0x5252525252525252,		0x5353535353535353,
		0x5454545454545454,		0x5555555555555555,		0x5656565656565656,		0x5757575757575757,
		0x5858585858585858,		0x5959595959595959,		0x5a5a5a5a5a5a5a5a,		0x5b5b5b5b5b5b5b5b,
		0x5c5c5c5c5c5c5c5c,		0x5d5d5d5d5d5d5d5d,		0x5e5e5e5e5e5e5e5e,		0x5f5f5f5f5f5f5f5f,
		0x6060606060606060,		0x6161616161616161,		0x6262626262626262,		0x6363636363636363,
		0x6464646464646464,		0x6565656565656565,		0x6666666666666666,		0x6767676767676767,
		0x6868686868686868,		0x6969696969696969,		0x6a6a6a6a6a6a6a6a,		0x6b6b6b6b6b6b6b6b,
		0x6c6c6c6c6c6c6c6c,		0x6d6d6d6d6d6d6d6d,		0x6e6e6e6e6e6e6e6e,		0x6f6f6f6f6f6f6f6f,
		0x7070707070707070,		0x7171717171717171,		0x7272727272727272,		0x7373737373737373,
		0x7474747474747474,		0x7575757575757575,		0x7676767676767676,		0x7777777777777777,
		0x7878787878787878,		0x7979797979797979,		0x7a7a7a7a7a7a7a7a,		0x7b7b7b7b7b7b7b7b,
		0x7c7c7c7c7c7c7c7c,		0x7d7d7d7d7d7d7d7d,		0x7e7e7e7e7e7e7e7e,		0x7f7f7f7f7f7f7f7f,
		0x8080808080808080,		0x8181818181818181,		0x8282828282828282,		0x8383838383838383,
		0x8484848484848484,		0x8585858585858585,		0x8686868686868686,		0x8787878787878787,
		0x8888888888888888,		0x8989898989898989,		0x8a8a8a8a8a8a8a8a,		0x8b8b8b8b8b8b8b8b,
		0x8c8c8c8c8c8c8c8c,		0x8d8d8d8d8d8d8d8d,		0x8e8e8e8e8e8e8e8e,		0x8f8f8f8f8f8f8f8f,
		0x9090909090909090,		0x9191919191919191,		0x9292929292929292,		0x9393939393939393,
		0x9494949494949494,		0x9595959595959595,		0x9696969696969696,		0x9797979797979797,
		0x9898989898989898,		0x9999999999999999,		0x9a9a9a9a9a9a9a9a,		0x9b9b9b9b9b9b9b9b,
		0x9c9c9c9c9c9c9c9c,		0x9d9d9d9d9d9d9d9d,		0x9e9e9e9e9e9e9e9e,		0x9f9f9f9f9f9f9f9f,
		0xa0a0a0a0a0a0a0a0,		0xa1a1a1a1a1a1a1a1,		0xa2a2a2a2a2a2a2a2,		0xa3a3a3a3a3a3a3a3,
		0xa4a4a4a4a4a4a4a4,		0xa5a5a5a5a5a5a5a5,		0xa6a6a6a6a6a6a6a6,		0xa7a7a7a7a7a7a7a7,
		0xa8a8a8a8a8a8a8a8,		0xa9a9a9a9a9a9a9a9,		0xaaaaaaaaaaaaaaaa,		0xabababababababab,
		0xacacacacacacacac,		0xadadadadadadadad,		0xaeaeaeaeaeaeaeae,		0xafafafafafafafaf,
		0xb0b0b0b0b0b0b0b0,		0xb1b1b1b1b1b1b1b1,		0xb2b2b2b2b2b2b2b2,		0xb3b3b3b3b3b3b3b3,
		0xb4b4b4b4b4b4b4b4,		0xb5b5b5b5b5b5b5b5,		0xb6b6b6b6b6b6b6b6,		0xb7b7b7b7b7b7b7b7,
		0xb8b8b8b8b8b8b8b8,		0xb9b9b9b9b9b9b9b9,		0xbabababababababa,		0xbbbbbbbbbbbbbbbb,
		0xbcbcbcbcbcbcbcbc,		0xbdbdbdbdbdbdbdbd,		0xbebebebebebebebe,		0xbfbfbfbfbfbfbfbf,
		0xc0c0c0c0c0c0c0c0,		0xc1c1c1c1c1c1c1c1,		0xc2c2c2c2c2c2c2c2,		0xc3c3c3c3c3c3c3c3,
		0xc4c4c4c4c4c4c4c4,		0xc5c5c5c5c5c5c5c5,		0xc6c6c6c6c6c6c6c6,		0xc7c7c7c7c7c7c7c7,
		0xc8c8c8c8c8c8c8c8,		0xc9c9c9c9c9c9c9c9,		0xcacacacacacacaca,		0xcbcbcbcbcbcbcbcb,
		0xcccccccccccccccc,		0xcdcdcdcdcdcdcdcd,		0xcececececececece,		0xcfcfcfcfcfcfcfcf,
		0xd0d0d0d0d0d0d0d0,		0xd1d1d1d1d1d1d1d1,		0xd2d2d2d2d2d2d2d2,		0xd3d3d3d3d3d3d3d3,
		0xd4d4d4d4d4d4d4d4,		0xd5d5d5d5d5d5d5d5,		0xd6d6d6d6d6d6d6d6,		0xd7d7d7d7d7d7d7d7,
		0xd8d8d8d8d8d8d8d8,		0xd9d9d9d9d9d9d9d9,		0xdadadadadadadada,		0xdbdbdbdbdbdbdbdb,
		0xdcdcdcdcdcdcdcdc,		0xdddddddddddddddd,		0xdededededededede,		0xdfdfdfdfdfdfdfdf,
		0xe0e0e0e0e0e0e0e0,		0xe1e1e1e1e1e1e1e1,		0xe2e2e2e2e2e2e2e2,		0xe3e3e3e3e3e3e3e3,
		0xe4e4e4e4e4e4e4e4,		0xe5e5e5e5e5e5e5e5,		0xe6e6e6e6e6e6e6e6,		0xe7e7e7e7e7e7e7e7,
		0xe8e8e8e8e8e8e8e8,		0xe9e9e9e9e9e9e9e9,		0xeaeaeaeaeaeaeaea,		0xebebebebebebebeb,
		0xecececececececec,		0xedededededededed,		0xeeeeeeeeeeeeeeee,		0xefefefefefefefef,
		0xf0f0f0f0f0f0f0f0,		0xf1f1f1f1f1f1f1f1,		0xf2f2f2f2f2f2f2f2,		0xf3f3f3f3f3f3f3f3,
		0xf4f4f4f4f4f4f4f4,		0xf5f5f5f5f5f5f5f5,		0xf6f6f6f6f6f6f6f6,		0xf7f7f7f7f7f7f7f7,
		0xf8f8f8f8f8f8f8f8,		0xf9f9f9f9f9f9f9f9,		0xfafafafafafafafa,		0xfbfbfbfbfbfbfbfb,
		0xfcfcfcfcfcfcfcfc,		0xfdfdfdfdfdfdfdfd,		0xfefefefefefefefe,		0xffffffffffffffff
	};
	return rT[a];
}

#define STRIDE 4

#define operation1(counter ,out, ct) xor(&(out)[counter] , &ct);

#define operation2(counter ,out, ct) addInPlace(&(out)[counter],&ct);

#define operation2x3(counter ,out1, ct1,out2, ct2,out3, ct3) \
	operation2(counter ,out1, ct1); \
	operation2(counter ,out2, ct2); \
	operation2(counter ,out3, ct3);

#define operation3(counter,temp,temp2,i,j,T,prod) \
	addInPlace(&temp2[counter],&prod); \
	xor(&temp[j][counter],&T[i]); \
	xor(&temp[i][counter],&T[j]);

#define operation4(counter , out , bit)	flipBit(&out[counter],bit);

#define switch4(in , counter , op, args...) \
switch(in&15){ \
	case 0 :   \
		break; \
	case 1 : \
		op(counter,args); \
		break; \
	case 2 :   \
		op(counter+1,args); \
		break; \
	case 3:    \
		op(counter,args); \
		op(counter+1,args); \
		break; \
	case 4 :   \
		op(counter+2,args); \
		break; \
	case 5 :   \
		op(counter,args); \
		op(counter+2,args); \
		break; \
	case 6 :   \
		op(counter+1,args); \
		op(counter+2,args); \
		break; \
	case 7:    \
		op(counter,args); \
		op(counter+1,args); \
		op(counter+2,args); \
		break; \
	case 8 : \
		op(counter+3,args); \
		break; \
	case 9 :  \
		op(counter,args); \
		op(counter+3,args); \
		break; \
	case 10 : \
		op(counter+1,args); \
		op(counter+3,args); \
		break; \
	case 11: \
		op(counter,args); \
		op(counter+1,args); \
		op(counter+3,args); \
		break; \
	case 12 :  \
		op(counter+2,args); \
		op(counter+3,args); \
		break; \
	case 13 :  \
		op(counter,args); \
		op(counter+2,args); \
		op(counter+3,args); \
		break; \
	case 14 : \
		op(counter+1,args); \
		op(counter+2,args); \
		op(counter+3,args); \
		break; \
	case 15: \
		op(counter,args); \
		op(counter+1,args); \
		op(counter+2,args); \
		op(counter+3,args); \
		break; \
} 

#if FIELD_SIZE == 8
	void _addScalarProduct1(FELT *V, FELT a, uint64_t b, int bits) {
		int i; 
		for (i = 0; i < (bits+7)/8; i++) { 
			((uint64_t*)V)[i] ^= expandTable(b & 255 ) & repeatTable(a); 
			b >>= 8; 
		}
	}
#else 
	void _addScalarProduct1(FELT *V, FELT a, uint64_t b, int bits) {
		int i; 
		for (i = 0; i < bits ; i+= STRIDE) { 
			switch4(b,i,operation2,V,a);
			b >>= STRIDE; 
		}
	}
#endif

#if FIELD_SIZE == 8
	void _addScalarProduct3(FELT *V1, FELT a1, FELT *V2, FELT a2, FELT *V3, FELT a3, uint64_t b, int bits) {
		int i; 
		for (i = 0; i < (bits+7)/8 ; i++) { 
			((uint64_t*)V1)[i] ^= expandTable(b & 255 ) & repeatTable(a1); 
			((uint64_t*)V2)[i] ^= expandTable(b & 255 ) & repeatTable(a2); 
			((uint64_t*)V3)[i] ^= expandTable(b & 255 ) & repeatTable(a3); 
			b >>= 8;
		}
	}
#else
	void _addScalarProduct3(FELT *V1, FELT a1, FELT *V2, FELT a2, FELT *V3, FELT a3, uint64_t b, int bits) {
		int i; 
		for (i = 0; i < bits ; i+= STRIDE) { 
			switch4(b,i,operation2x3,V1,a1,V2,a2,V3,a3);
			b >>= STRIDE; 
		}
	}
#endif

/*
	Given a vector V, a field element a, and a vector OIL_VARS bits b (i.e. a bitcontainer)
	compute the scalar product of b by a ans add it to V
*/
void addScalarProduct(FELT *V, FELT a, bitcontainer b) {
	#if OIL_VARS <= 64
		_addScalarProduct1(V,a,b,OIL_VARS);
	#elif OIL_VARS <= 128
		_addScalarProduct1(V     ,a,b.components[0],64); 
		_addScalarProduct1(&V[64],a,b.components[1],OIL_VARS-64);
	#endif
}

/*
	Given a vector V, a field element a, and a vector OIL_VARS bits b (i.e. a bitcontainer)
	compute the scalar product of b by a ans add it to V
*/
void addScalarProduct3(FELT* V1, FELT a1, FELT *V2, FELT a2, FELT *V3, FELT a3, bitcontainer b) {
	#if OIL_VARS <= 64
		_addScalarProduct3(V1,a1,V2,a2,V3,a3,b,OIL_VARS);
	#elif OIL_VARS <= 128
		_addScalarProduct3(V1     ,a1,V2     ,a2,V3     ,a3,b.components[0],64); 
		_addScalarProduct3(&V1[64],a1,&V2[64],a2,&V3[64],a3,b.components[1],OIL_VARS-64);
	#endif
}

/*
	Writes the seed for the secret key to a char array

	W  : A writer object
	sk : a secret key
*/
void serialize_SecretKey(writer *W, SecretKey *sk) {
	reader R = newReader(sk->privateseed);
	// write the 32-byte seed  
	transcribe(W, &R, 32);
}

/*
	Reads the seed for a secret key from a char array and recompute the public seed and T

	R : A reader object
	sk : receives the secret key
*/
void deserialize_SecretKey(reader *R, SecretKey *sk) {
	writer W = newWriter(sk->privateseed);
	// read the 32-byte seed
	transcribe(&W, R, 32);

	// compute the public seed
	Sponge sponge;
	initializeAndAbsorb(&sponge , sk->privateseed , 32);
	unsigned char publicseed[32];
	squeezeBytes(&sponge , publicseed , 32);

	// compute the matrix T
	sk->T[0] = empty; // this makes the linear map T linear, picking the first row of T random would make T an affine transformation
	squeezeBitcontainerArray(&sponge, &(sk->T[1]) , VINEGAR_VARS);
}

/*
	Frees the memory allocated by a secret key
*/
void destroy_SecretKey(SecretKey *sk) {
}

/*
	Writes a public key to a char array

	W : A writer object
	pk : the public key
*/
void serialize_PublicKey(writer* W, PublicKey* pk) {
	int i;

	// Write the public seed
	reader R = newReader(pk->publicseed);
	transcribe(W,&R,32);

	// Write Q_2
	for (i = 0; i < STORED_COLS_OF_P ; i++) {
		serialize_bitcontainer(W, pk->Q2[i]);
	}
	return;
}

/*
	Reads a public key from a char array

	R : A reader object
	pk : receives the public key
*/
void deserialize_PublicKey(reader* R, PublicKey* pk) {
	int i;

	// Read the public seed
	writer W = newWriter(pk->publicseed);
	transcribe(&W,R,32);

	// Allocate memory and read Q_2
	pk->Q2 = malloc(sizeof(bitcontainer)*STORED_COLS_OF_P);
	for (i = 0; i < STORED_COLS_OF_P ; i++) {
		pk->Q2[i] = deserialize_bitcontainer(R);
	}
}

/*
	Frees the memory allocated by a public key
*/
void destroy_PublicKey(PublicKey *pk) {
	free(pk->Q2);
}

/*
	Writes a signature to a char array

	W : A writer object
	S : the signature
*/
void serialize_signature(writer* W, Signature* S) {
	int i;

	// writes all the entries of the vector s, except the first entry, 
	// which corresponds to a homogenizing variable and is always equal to 1
	for(i=1 ; i<=VARS ; i++){
		serialize_FELT(W,S->s[i]);
	}
}

/*
	Reads a signature from a char array

	R : A reader object
	S : receives the signature
*/
void deserialize_signature(reader* R, Signature* S) {
	int i;
	// sets the first variable, which is a homogenizing variable to 1
	S->s[0] = ONE;

	// read the remaining variables
	for(i=1; i<=VARS; i++){
		S->s[i] = deserialize_FELT(R);
	}
}

/*
	Frees the memory allocated by a signature
*/
void destroy_signature(Signature *S) {
}

/*
	Calculates Q_2, the last OIL_VARS*(OIL_VARS+1)/2 columns of the macaulay matrix of the public system

	sk : the secret key
	pk : the public key
*/
void calculateQ2(SecretKey *sk , PublicKey *pk) {
	int i, j, k, col;
	bitcontainer **TempMat = malloc(sizeof(bitcontainer*) * (VINEGAR_VARS+1));
	bitcontainer r;
	uint64_t t;

	// Absorb the public seed in a sponge object
	Sponge sponge;
	initializeAndAbsorb(&sponge, pk->publicseed , 32);

	// Allocate memory for temporary matrices that will store the values P_i,1 T + P_i,2 for i from 1 to OIL_VARS.
	// These OIL_VARS matrices are bitsliced into one OIL_VARS by OIL_VARS array of bitcontainers.
	// All entries of the matrices are initialized to zero.
	for (i = 0; i <= VINEGAR_VARS; i++) {
		TempMat[i] = malloc(sizeof(bitcontainer)*((OIL_VARS)+3/4)*4);
		for (j = 0; j < OIL_VARS; j++) {
			TempMat[i][j] = empty;
		}
	}

	// Simultaneously calculate P_i,1*T + P_i,2 for all i from 1 to OIL_VARS
	for (i = 0; i <= VINEGAR_VARS; i++) {
		// Calculates P_i,1*T
		for (j = i; j <= VINEGAR_VARS; j++) {
			randomBitcontainer(&sponge,&r);
			
			#if (OIL_VARS <= 64) 
				t = sk->T[j];// & 0x7fffffffffffffff;
				for (k = 0; k < OIL_VARS; k+=STRIDE) {
					switch4(t,k,operation1,TempMat[i],r);
					t >>=STRIDE;
				}
			# elif (OIL_VARS <= 128) 
				t = sk->T[j].components[0];
				for (k = 0; k < 64; k+=STRIDE) {
					switch4(t,k,operation1,TempMat[i],r);
					t >>=STRIDE;
				}
				t = sk->T[j].components[1];
				for (k = 64; k < OIL_VARS; k+=STRIDE) {
					switch4(t,k,operation1,TempMat[i],r);
					t >>=STRIDE;
				}
			#endif
		}
		// Add P_i,2
		for (j = 0; j < OIL_VARS; j++) {
			randomBitcontainer(&sponge,&r);
			xor(&TempMat[i][j],&r);
		}
	}

	// Calculate P_i,3 = Transpose(T)*TempMat_i, and store the result in Q_2
	/*col = 0;
	pk->Q2 = malloc(STORED_COLS_OF_P * sizeof(bitcontainer));
	for (i = 0; i < OIL_VARS; i++) {
		for (j = i; j < OIL_VARS; j++) {
			pk->Q2[col] = empty;
			for (k = 0; k <= VINEGAR_VARS; k++) {
				if (getBit(sk->T[k] , i ) ) {
					xor(&pk->Q2[col], &TempMat[k][j]);
				}f80add
			}
			if (j != i){
				for (k = 0; k <= VINEGAR_VARS; k++) {
					if (getBit(sk->T[k] , j ) ) {
						xor(&pk->Q2[col], &TempMat[k][i]);
					}
				}
			}
			col ++ ;
		}
	}*/

	// Calculate P_i,3 = Transpose(T)*TempMat_i, and store the result in Q_2
	bitcontainer **temp;
	temp = malloc(sizeof(bitcontainer*)*OIL_VARS);
	for(i=0 ; i<OIL_VARS ; i++){
		temp[i] = calloc(((OIL_VARS+3)/4)*4,sizeof(bitcontainer));
	}
	for (i = 0; i < OIL_VARS; i++) {
		for (j = 0; j <= VINEGAR_VARS; j++) {
			r = sk->T[j];
			#if OIL_VARS <= 64
				for (k = 0; k < OIL_VARS; k+= STRIDE) {
					switch4(r,k,operation1,temp[i],TempMat[j][i]);
					r >>= STRIDE;
				}
			#elif OIL_VARS <= 128
				t = r.components[0];
				for (k = 0; k < 64; k+= STRIDE) {
					switch4(t,k,operation1,temp[i],TempMat[j][i]);
					t >>= STRIDE;
				}
				t = r.components[1];
				for (k = 64; k < OIL_VARS; k+= STRIDE) {
					switch4(t,k,operation1,temp[i],TempMat[j][i]);
					t >>= STRIDE;
				}
			#endif
		}
	}
	col = 0;
	pk->Q2 = malloc(STORED_COLS_OF_P * sizeof(bitcontainer));
	for (i = 0; i < OIL_VARS; i++) {
		for (j = i; j < OIL_VARS; j++) {
			pk->Q2[col] = temp[i][j];
			if (j != i){
				xor(&pk->Q2[col],&temp[j][i]);
			}
			col ++ ;
		}
	}

	for(i=0 ; i<OIL_VARS ; i++) free(temp[i]);
	free(temp);
	
	// Free the memory occupied by TempMat
	for (i = 0; i <= VINEGAR_VARS; i++) {
		free(TempMat[i]);	}
	free(TempMat);
}

/*
	Generates a key pair

	pk : receives the public key
	sk : receives the secret key
*/
void generateKeyPair(PublicKey *pk, SecretKey *sk) {
	randombytes(sk->privateseed , 32);

	// Calculate public seed
	Sponge sponge;
	initializeAndAbsorb(&sponge , sk->privateseed, 32);
	squeezeBytes(&sponge, pk->publicseed , 32);

	// Calculate T
	sk->T[0]=empty;/* makes T linear instead of affine*/
	squeezeBitcontainerArray(&sponge , &(sk->T[1]) , VINEGAR_VARS);

	// Calculates Q_2, the part of the public map P that cannot be generated from the public seed
	calculateQ2( sk , pk );
}

/*
	Builds the augmented matrix for the system F(x) = target , after fixing the vinegar variables

	A                 : Receives the augmented matrix, should be initialized to zero the zero matrix
	vinegar_variables : An assignment to the vinegar variables
	target            : The target vector to find a solution for
	T                 : The V-by-M matrix that determines the linear transformation T
	sponge            : The sponge object used to generate the first part of the public map P
*/
#if FIELD_SIZE == 8
void BuildAugmentedMatrix(Matrix *A, FELT *vinegar_variables , FELT *target, bitcontainer *T, Sponge *sponge) {
	int i, j, k;
	bitcontainer r;
	FELT prod,swap;
	FELT **temp = malloc(sizeof(FELT*)*(VINEGAR_VARS+1));
	FELT temp2[((OIL_VARS+7)/8)*8];
	for (k = 0; k < OIL_VARS; k++) {
		temp2[k] = target[k];
	}

	#if FIELD_SIZE == 8
		uint16_t logvin[VINEGAR_VARS+1];
		for (i = 0; i <= VINEGAR_VARS; i++)
		{
			logvin[i] = f8log(vinegar_variables[i]);
		}
	#endif

	for( k = 0 ; k<= VINEGAR_VARS ; k++){
		temp[k] = calloc(((OIL_VARS+7)/8)*8,sizeof(FELT));
	}


	for (i = 0; i <= VINEGAR_VARS; i++) {
		for (j = i; j <= VINEGAR_VARS; j++) {
			randomBitcontainer(sponge,&r);
			#if FIELD_SIZE == 8
				prod = f8antilog(logvin[i]+logvin[j]);
			#else
				prod = multiply(vinegar_variables[i],vinegar_variables[j]);
			#endif
			addScalarProduct3(temp2,prod,temp[j],vinegar_variables[i],temp[i],vinegar_variables[j],r);
		}
		for (j = 0; j < OIL_VARS; j++) {
			randomBitcontainer(sponge,&r);
			addScalarProduct(A->array[j],vinegar_variables[i],r);
		}
	}

	for(i = 0 ; i< OIL_VARS ; i++){
		for(j = i+1 ; j<OIL_VARS ; j++){
			swap = A->array[i][j];
			A->array[i][j] = A->array[j][i];
			A->array[j][i] = swap;
		}
	}

	for (k = 0; k < OIL_VARS; k++)	{
		for (i = 0; i <= VINEGAR_VARS; i++) {
			addScalarProduct(A->array[k],temp[i][k],T[i]);
		}
	}

	for(i=0 ; i<OIL_VARS ; i++){
		A->array[i][OIL_VARS] = temp2[i];
	}

	for(k=0 ; k<=VINEGAR_VARS ; k++){
		free(temp[k]);
	}
	free(temp);

	A->cols = OIL_VARS+1;
}
#else
void BuildAugmentedMatrix(Matrix *A, FELT *vinegar_variables , FELT *target, bitcontainer *T, Sponge *sponge) {
	int i, j, k;
	bitcontainer r;
	FELT prod;
	bitcontainer **temp = malloc(sizeof(bitcontainer*)*(VINEGAR_VARS+1));

	FELT temp2[((OIL_VARS+7)/8)*8];
	for (k = 0; k < OIL_VARS; k++) {
		temp2[k] = target[k];
	}

	#if FIELD_SIZE == 8
		uint16_t logvin[VINEGAR_VARS+1];
		for (i = 0; i <= VINEGAR_VARS; i++)
		{
			logvin[i] = f8log(vinegar_variables[i]);
		}
	#endif

	for( k = 0 ; k<= VINEGAR_VARS ; k++){
		temp[k] = calloc(((OIL_VARS+3)/4)*4,sizeof(bitcontainer));
	}


	for (i = 0; i <= VINEGAR_VARS; i++) {
		for (j = i; j <= VINEGAR_VARS; j++) {
			randomBitcontainer(sponge,&r);
			#if FIELD_SIZE == 8
				prod = f8antilog(logvin[i]+logvin[j]);
			#else
				prod = multiply(vinegar_variables[i],vinegar_variables[j]);
			#endif
			
			#if OIL_VARS <= 64 
				for (k = 0; k < OIL_VARS; k+=STRIDE)	{
					switch4(r,k,operation3,temp,temp2,i,j,T,prod);
					r >>= STRIDE;
				}
			#elif OIL_VARS <= 128
				uint64_t t = r.components[0];
				for (k = 0; k < 64 ; k+=STRIDE)	{
					switch4(t,k,operation3,temp,temp2,i,j,T,prod);
					t >>= STRIDE;
				}
				t = r.components[1];
				for (k = 64; k < OIL_VARS ; k+=STRIDE)	{
					switch4(t,k,operation3,temp,temp2,i,j,T,prod);
					t >>= STRIDE;
				}
			#endif
		}
		for (j = 0; j < OIL_VARS; j++) {
			randomBitcontainer(sponge,&r);
			#if OIL_VARS <= 64 
				for (k = 0; k < OIL_VARS; k+=STRIDE)	{
					switch4(r,k,operation4,temp[i],j);
					r >>= STRIDE;
				}
			#elif OIL_VARS <= 128
				uint64_t t = r.components[0];
				for (k = 0; k < 64 ; k+=STRIDE)	{
					switch4(t,k,operation4,temp[i],j);
					t >>= STRIDE;
				}
				t = r.components[1];
				for (k = 64; k < OIL_VARS ; k+=STRIDE)	{
					switch4(t,k,operation4,temp[i],j);
					t >>= STRIDE;
				}
			#endif
		}
	}

	for (k = 0; k < OIL_VARS; k++)	{
		for (i = 0; i <= VINEGAR_VARS; i++) {
			#if OIL_VARS <= 64 
				uint64_t r = temp[i][k];
				for (j = 0; j < OIL_VARS; j+=STRIDE)	{
					switch4(r,j,operation2,A->array[k],vinegar_variables[i]);
					r >>= STRIDE;
				}
			#elif OIL_VARS <= 128
				uint64_t r = temp[i][k].components[0];
				for (j = 0; j < 64 ; j+=STRIDE)	{
					switch4(r,j,operation2,A->array[k],vinegar_variables[i]);
					r >>= STRIDE;
				}
				r = temp[i][k].components[1];
				for (j = 64; j < OIL_VARS ; j+=STRIDE)	{
					switch4(r,j,operation2,A->array[k],vinegar_variables[i]);
					r >>= STRIDE;
				}
			#endif
		}
	}

	for(i=0 ; i<OIL_VARS ; i++){
		A->array[i][OIL_VARS] = temp2[i];
	}

	for(k=0 ; k<=VINEGAR_VARS ; k++){
		free(temp[k]);
	}
	free(temp);

	A->cols = OIL_VARS+1;
}
#endif

/*
	Solves the system F(x) = target for x

	sk : The secret key
	target : The target vector to find a solution for
	vinegar_sponge : The sponge object used to generate the assignment to the vinegar variables
	signature : A signature object, used to store the solution x 
*/
void solvePrivateUOVSystem(SecretKey sk, FELT *target , Sponge *vinegar_sponge , Signature *signature) {
	Matrix A;
	int solution_found = 0;

	// calculate public seed from private seed 
	Sponge seedsponge;
	initializeAndAbsorb(&seedsponge, sk.privateseed , 32);
	unsigned char publicseed[32];
	squeezeBytes(&seedsponge, publicseed , 32);

    // Repeatedly try an assignment to the vinegar variables until a unique solution is found
	Sponge sponge;
	while (solution_found == 0) {
		// Initialize sponge for squeezin the public map P
		initializeAndAbsorb(&sponge, publicseed , 32);
		
		// Set homogenizing variable to one and squeeze an assignment to the vinegar variables from the vinegar sponge
		signature->s[0] = ONE;
		squeezeVector(vinegar_sponge , &(signature->s[1]) , VINEGAR_VARS);

		// Print vinegar values if KAT is defined
		printVinegarValues(&(signature->s[1]));

		// Build the augmented matrix for the linear system
		A = zeroMatrix(OIL_VARS, (((OIL_VARS+7)/8)*8) + 1);
		BuildAugmentedMatrix(&A, signature->s , target, sk.T , &sponge);

		// Print augmented matrix if KAT is defined
		printAugmentedMatrix(A);

		// Try to find a unique solution to the linear system
		solution_found = getUniqueSolution(A,&(signature->s[1+VINEGAR_VARS]));

		// Report whether a solution is found if KAT is defined
		reportSolutionFound(solution_found);

		// Free the memory occupied by the augmented matrix
		destroy_matrix(A);
	}
}

#ifndef MESSAGE_RECOVERY

/*
	Computes the target vector by hashing the document, after padding it with a 0x00 byte
	(Only used in appended signature mode)

	document : The document that is being signed
	len : The number of bytes of the document being signed
	target : receives the target vector
 */
void computeTarget(const unsigned char* document , uint64_t len, FELT *target){
	Sponge sponge;
	unsigned char pad = 0;

	Keccak_HashInitialize_SHAKE(&sponge);
	Keccak_HashUpdate(&sponge,document , len*8);
	Keccak_HashUpdate(&sponge,&pad , 8);
	Keccak_HashFinal(&sponge , 0);
	squeezeVector(&sponge  , target , OIL_VARS);
}
#else

/*
	Computes the target vector. 
	The document is hashed, after padding it with a 0x01 byte, to get the first part of the target.
	Then, the first part is hashed again and xored with the last part of the padded document to get the second part of the target.
	(Only used in message recovery mode)

	document : The document that is being signed
	len : The number of bytes of the document being signed
	target : receives the target vector
 */
void computeTarget(const unsigned char* document , uint64_t len, FELT *target){
	int i,start_recovery;
	Sponge sponge;
	unsigned char buf[FIRST_PART_TARGET + SECOND_PART_TARGET];
	unsigned char pad = 1;

	// Compute first part of the target and put in the first part of the buffer 
	Keccak_HashInitialize_SHAKE(&sponge);
	Keccak_HashUpdate(&sponge,document , len*8);
	Keccak_HashUpdate(&sponge,&pad , 8);
	Keccak_HashFinal(&sponge , 0);
	squeezeBytes(&sponge  , buf , FIRST_PART_TARGET );

	// Absorb first part of target into a Sponge object and squeeze into the second part of the buffer
	initializeAndAbsorb(&sponge, buf , FIRST_PART_TARGET);
	squeezeBytes(&sponge  , &(buf[FIRST_PART_TARGET]) , SECOND_PART_TARGET );

	// If not the entire document can be covered from a signature, we xor the last part of the message 
	// into the second part of the buffer and we xor the last byte with a 0x01.
	// Otherwise, we xor the entire document into the second part of the buffer, and we xor the next byte with a 0x01
	if(len > RECOVERED_PART_MESSAGE){
		start_recovery = len- RECOVERED_PART_MESSAGE;
		buf[FIRST_PART_TARGET + SECOND_PART_TARGET - 1] ^= 1;
	}
	else{
		start_recovery = 0;
		buf[FIRST_PART_TARGET + len] ^= 1;
	}
	for(i = start_recovery ; i<len ; i++){
		buf[FIRST_PART_TARGET + i-start_recovery] ^= document[i];
	}

	// Interpret the contents of the buffer as a list of fied elements.
	reader R = newReader(buf);
	for (i = 0; i < OIL_VARS ; i++)
	{
		target[i] = deserialize_FELT(&R);
	}
}
#endif

/*
	If message recovery is enabled, this function extracts the last part of the document from the evaluated signature and appends it to the first part of document

	document : Initially this contains the first part of the document, after the call to this function this contains the entire original document
	len      : pointer to the length of document, which is altered appropriately
	evaluation : The evaluation of the public map in the signature
*/
void extractMessage(unsigned char *document ,unsigned long long *len , FELT *evaluation){
	#ifdef MESSAGE_RECOVERY
	int i, reading;
	unsigned char buf[FIRST_PART_TARGET+SECOND_PART_TARGET];
	unsigned char buf2[SECOND_PART_TARGET];
	Sponge sponge;

	// Interpret the evaluation of P as an array of bytes
	writer W = newWriter(buf);
	for(i = 0 ; i<OIL_VARS ; i++){
		serialize_FELT(&W,evaluation[i]);
	}

	// Absorb the first part of the buffer into a Sponge object and squeeze into buffer 2
	initializeAndAbsorb(&sponge, buf , FIRST_PART_TARGET );
	squeezeBytes(&sponge  , buf2 , SECOND_PART_TARGET );

	// Xor the secon part of the evaluation into buffer 2
	for(i = 0 ; i<SECOND_PART_TARGET ; i++ ){
		buf2[i] ^= buf[FIRST_PART_TARGET + i];
	}

	// Start searching from the left for the first byte equal to 0x01
	// All bytes before this byte are appended to the document and len is increased
	reading = 0;
	unsigned long long oldlen = *len; 
	for (i = SECOND_PART_TARGET-1; i >= 0 ; i--)
	{
		if(reading){
			document[oldlen + i] = buf2[i];
		}
		else{
			if(buf2[i] == 1){
				reading = 1;
				*len += i;
			}
		}
	}

	#endif
}

/*
	Generates a signature for a document

	sk : the secret key
	document : a char array containing the document to be signed
	len : the length of the document

	returns : A signature for the document
*/
Signature signDocument(SecretKey sk,const unsigned char *document , uint64_t len) {
	int i, j;
	Signature signature;
	FELT target[OIL_VARS];

	// Define the appropriate padding, based on wheter we are in message recovery mode or not
	unsigned char pad = 0;
	#ifdef MESSAGE_RECOVERY
		pad = 1;
	#endif

	// compute the target for the public map P
	computeTarget(document, len , target);

	// Initialize the vinegar sponge from the padded document and the private key
	Sponge vinegar_sponge;
	Keccak_HashInitialize_SHAKE(&vinegar_sponge);
	Keccak_HashUpdate(&vinegar_sponge, document, len*8 );
	Keccak_HashUpdate(&vinegar_sponge, &pad , 8);
	Keccak_HashUpdate(&vinegar_sponge, sk.privateseed , 32*8);
	Keccak_HashFinal(&vinegar_sponge, 0 );

	// Generate a solution to F(x) = target
	solvePrivateUOVSystem(sk, target, &vinegar_sponge , &signature);

	// Print solution to the equation F(x) = target if KAT is defined
	printPrivateSolution(signature.s);

	// Convert into a solution for P(x) = target
	for (i = 0; i <= VINEGAR_VARS; i++) {
		for (j = 0; j < OIL_VARS; j++) {
			if ( getBit(sk.T[i] , j )) {
				signature.s[i] = subtract(signature.s[i],signature.s[VINEGAR_VARS +1+ j]);
			}
		}
	}

	return signature;
}

/* 
	Evaluated the public map P in a signature

	pk : The public key
	signature : The point that P is evaluated in
	evaluation : Receives the vector P(signature)
*/
void evaluatePublicMap(PublicKey *pk, Signature *signature , FELT* evaluation){
	int i,j,col;
	FELT prod;
	bitcontainer r;
	Sponge sponge;

	// Precomputes the logarithms of the elements in the signature
	#if FIELD_SIZE == 8
		uint16_t logsig[VARS+1];
		for (i = 0; i <= VARS; i++)
		{
			logsig[i] = f8log(signature->s[i]);
		}
	#endif

	// initialize evaluation to zero
	for(i = 0 ; i<OIL_VARS ; i++){
		evaluation[i] = ZERO;
	}
	initializeAndAbsorb(&sponge , pk->publicseed , 4);  
	
	// Prepare a sponge for squeezing the first part of the public map P
	initializeAndAbsorb(&sponge , pk->publicseed , 32);

	// Evaluate the part of P that is generated from the public seed
	for (i = 0; i <= VINEGAR_VARS; i++) {
		for (j = i; j <= VARS ; j++) {
			randomBitcontainer(&sponge,&r);
			#if FIELD_SIZE == 8
				prod = f8antilog(logsig[i]+logsig[j]);
			#else
				prod = multiply(signature->s[i],signature->s[j]);
			#endif
			addScalarProduct(evaluation,prod,r);
		}
	}

	// Evaluate the part of P that is stored in the public key
	col = 0;
	for (i = VINEGAR_VARS +1 ; i <= VARS; i++) {
		for (j = i; j <= VARS; j++) {
			#if FIELD_SIZE == 8
				prod = f8antilog(logsig[i]+logsig[j]);
			#else
				prod = multiply(signature->s[i],signature->s[j]);
			#endif
			r = pk->Q2[col];
			addScalarProduct(evaluation,prod,r);
			col++;
		}
	}

	// prints the evaluation of the public map if KAT is defined
	printEvaluation(evaluation);
}

/*
	Verifies a signature for a document

	Remark : If we are in message recovery mode, this function does more work than strictly necessary 

	pk : the public key
	signature : a signature
	document : a char array containing a document
	len : the length of the document

	returns : 0 if the signature is valid, -1 otherwise
*/
int verify(PublicKey *pk, Signature *signature, unsigned char *document , unsigned long long *len) {
	int i;
	FELT evaluation[((OIL_VARS+7)/8)*8];
	FELT target[OIL_VARS];

	// Evaluate the public map P at the signature
	evaluatePublicMap(pk, signature , evaluation);

	// If we are in message recovery mode, we extracts a part of the document from the signature
	extractMessage(document , len , evaluation);

	// We compute the target based on the full document
	computeTarget(document, *len, target);
	
	// Output 0 if the evaluation of the public map is equal to the target, otherwise output -1
	for(i=0 ; i<OIL_VARS ; i++){
		if (! isEqual(target[i], evaluation[i])){
			return -1;
		}
	}
	return 0;
}
