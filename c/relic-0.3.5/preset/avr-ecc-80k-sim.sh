#!/bin/bash 
cmake -DWORD=8 -DOPSYS=NONE -DSEED=LIBC -DSHLIB=ON -DSTBIN=ON -DTIMER=NONE -DWITH="ALL" -DBENCH=20 -DTESTS=20 -DCHECK=off -DVERBS=off -DSTRIP=on -DQUIET=off -DARITH=easy -DFB_POLYN=163 -DFB_METHD="INTEG;INTEG;QUICK;QUICK;QUICK;QUICK;EXGCD;BASIC;BASIC" -DEC_METHD="CHAR2" -DPC_METHD="CHAR2" -DEC_KBLTZ=on $1
