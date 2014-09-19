Download http://www.opensslfoundation.com/fips/2.0/platforms/android/android-build.tgz which contains the current versions of the required files.

Building the OpenSSL FIPS module and the OpenSSL FIPS capable distribution 
for Android on Linux and/or MacOS (Darwin) platforms

The Makefile target will download what is required for linux
The darwin script sets the correct variables to use the makefile on macos

The Makefile assumes the Android SDK and NDK have been installed in the
current working directory. If this is not correct then either edit the scripts
or place an appropriate symlink to the correct location in your environment

The Makefile will download the correct (current) version of both the
OpenSSL FIPS module and the OpenSSL FIPS capable distribution.

The Makefile builds the two packages and then a simple test program which 
can be loaded onto the target android platform.

The "test" target in the makefile assumes the device is connected locally
and that "adb" is configured and working for the target device.

./linux 
./linux test

./darwin
./darwin test


The output from test should be something like:

./android-sdk-macosx/platform-tools/adb push fips_hmac /data/local/tmp/
1167 KB/s (6872 bytes in 0.005s)
./android-sdk-macosx/platform-tools/adb push openssl-1.0.1c/libcrypto.so.1.0.0 /data/local/tmp/
3494 KB/s (2155464 bytes in 0.602s)
./android-sdk-macosx/platform-tools/adb shell 'cd /data/local/tmp; LD_LIBRARY_PATH=. ./fips_hmac -v fips_hmac'
FIPS mode enabled
6cf28ad433f5dcacc14553a9c4200a4b008d86f2

