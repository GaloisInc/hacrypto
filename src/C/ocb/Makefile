
CC=gcc

all: pmac128 pmac192 pmac256 ocb128 ocb192 ocb256

pmac128: ocb.c pmac_main.c ocb.h rijndael-alg-fst.c rijndael-alg-fst.h
	${CC} -DAES_KEY_BITLEN=128 ocb.c pmac_main.c rijndael-alg-fst.c -o pmac128

pmac192: ocb.c pmac_main.c ocb.h rijndael-alg-fst.c rijndael-alg-fst.h
	${CC} -DAES_KEY_BITLEN=192 ocb.c pmac_main.c rijndael-alg-fst.c -o pmac192

pmac256: ocb.c pmac_main.c ocb.h rijndael-alg-fst.c rijndael-alg-fst.h
	${CC} -DAES_KEY_BITLEN=256 ocb.c pmac_main.c rijndael-alg-fst.c -o pmac256

ocb128: ocb.c ocb_main.c ocb.h rijndael-alg-fst.c rijndael-alg-fst.h
	${CC} -DAES_KEY_BITLEN=128 ocb.c ocb_main.c rijndael-alg-fst.c -o ocb128

ocb192: ocb.c ocb_main.c ocb.h rijndael-alg-fst.c rijndael-alg-fst.h
	${CC} -DAES_KEY_BITLEN=192 ocb.c ocb_main.c rijndael-alg-fst.c -o ocb192

ocb256: ocb.c ocb_main.c ocb.h rijndael-alg-fst.c rijndael-alg-fst.h
	${CC} -DAES_KEY_BITLEN=256 ocb.c ocb_main.c rijndael-alg-fst.c -o ocb256
