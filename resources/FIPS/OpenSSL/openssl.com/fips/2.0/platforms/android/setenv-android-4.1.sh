#!/bin/sh
# Cross-compile environment for Android on ARMv7
#
# This script assumes the Android NDK and the OpenSSL FIPS
# tarballs have been unpacked in the same directory

#android-sdk-linux/platforms Edit this to wherever you unpacked the NDK

if [ -d android-ndk-r8b ]; then
  export ANDROID_NDK=$PWD/android-ndk-r8b
fi
if [ -d android-ndk-r8c ]; then
  export ANDROID_NDK=$PWD/android-ndk-r8c
fi

# Edit to reference the incore script (usually in ./util/)
export FIPS_SIG=$PWD/openssl-fips-2.0.2/util/incore

for i in linux darwin
do
  if [ -d $ANDROID_NDK/toolchains/arm-linux-androideabi-4.6/prebuilt/$i-x86/bin ]; then
    PATH=$ANDROID_NDK/toolchains/arm-linux-androideabi-4.6/prebuilt/$i-x86/bin:$PATH
  fi
done

export PATH

#
# Shouldn't need to edit anything past here.
#

export MACHINE=armv7l
export RELEASE=2.6.37
export SYSTEM=android
export ARCH=arm
export CROSS_COMPILE="arm-linux-androideabi-"
export ANDROID_DEV="$ANDROID_NDK/platforms/android-14/arch-arm/usr"
export HOSTCC=gcc


