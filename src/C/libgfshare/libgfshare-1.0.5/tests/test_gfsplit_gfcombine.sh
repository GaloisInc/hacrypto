#!/bin/sh

HERE=$(pwd)
mkdir TOOL-TEST
cd TOOL-TEST

cleanup ()
{
  cd $HERE
  rm -rf TOOL-TEST
}

trap cleanup 0

cp ../libtool plaintext
../gfsplit -n 3 -m 5 plaintext cyphertext

SHARES=$(ls cyphertext.* | wc -l)

if [ "$SHARES" != 5 ]; then
  echo "Share count created was not five"
  exit 1
fi

SHARES=$(ls cyphertext.* | xargs)

to_test ()
{
  RESULT=$1
  SUBSHARES=$(echo $SHARES | cut -d\  -f$2)
  WHOWHAT="$3"
  ../gfcombine $SUBSHARES
  cmp -s plaintext cyphertext
  if [ "$?" != "$RESULT" ]; then
    echo $WHOWHAT
    exit 1
  fi
}

to_test 1 1-2 "Two shares didn't fail"
to_test 0 1-3 "Three shares didn't succeed"
to_test 0 2-4 "Three shares didn't succeed"
to_test 0 3-5 "Three shares didn't succeed"

exit 0

