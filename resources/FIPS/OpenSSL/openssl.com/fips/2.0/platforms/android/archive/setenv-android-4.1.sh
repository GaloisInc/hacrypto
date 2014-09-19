#!/bin/sh
# Cross-compile environment for Android on ARMv7
#
# This script assumes the Android NDK and the OpenSSL FIPS
# tarballs have been unpacked in the same directory

#ndroid-sdk-linux/platforms Edit this to wherever you unpacked the NDK
export ANDROID_NDK=$PWD/android-ndk-r8b
# Edit to reference the incore script (usually in ./util/)
export FIPS_SIG=$PWD/openssl-fips-2.0.2/util/incore

# Shouldn't need to edit anything past here.

PATH=$ANDROID_NDK/toolchains/arm-linux-androideabi-4.6/prebuilt/linux-x86/bin:$PATH
export PATH

export MACHINE=armv7l
export RELEASE=2.6.37
export SYSTEM=android
export ARCH=arm
export CROSS_COMPILE="arm-linux-androideabi-"
export ANDROID_DEV="$ANDROID_NDK/platforms/android-14/arch-arm/usr"
export HOSTCC=gcc

