#
# for:
#	openssl-fips-2.0.2
#	openssl-1.0.1c
#	android-ndk-r8b
#	android-sdk-linux


all:	fips_hmac

openssl-fips-2.0.2.tar.gz:
	wget http://www.openssl.org/source/openssl-fips-2.0.2.tar.gz

openssl-1.0.1c.tar.gz:
	wget http://www.openssl.org/source/openssl-1.0.1c.tar.gz

fips/:	
	mkdir fips

fips/.done:	fips/ openssl-fips-2.0.2.tar.gz
	gunzip -c openssl-fips-2.0.2.tar.gz | tar xf -
	. ./setenv-android-4.1.sh; \
	cd openssl-fips-2.0.2; \
	./config; \
	make; \
	make install INSTALLTOP=$$PWD/../fips; \
	cd ..; touch $@

openssl-1.0.1c/.done:	fips/.done openssl-1.0.1c.tar.gz
	gunzip -c openssl-1.0.1c.tar.gz | tar xf -
	. ./setenv-android-4.1.sh; \
	cd openssl-1.0.1c/; \
	./config fips shared --with-fipsdir=$$PWD/../fips; \
	make depend; \
	make; \
	touch .done

fips_hmac:	openssl-1.0.1c/.done fips_hmac.c
	. ./setenv-android-4.1.sh; \
	arm-linux-androideabi-gcc -o fips_hmac fips_hmac.c -Iopenssl-1.0.1c/include/ -Lopenssl-1.0.1c/ -lcrypto -Iopenssl-1.0.1c -Iandroid-ndk-r8b/platforms/android-14/arch-arm/usr/include -Bandroid-ndk-r8b/platforms/android-14/arch-arm/usr/lib

test:	fips_hmac
	./android-sdk-linux/platform-tools/adb push fips_hmac /data/local/tmp/
	./android-sdk-linux/platform-tools/adb push openssl-1.0.1c/libcrypto.so.1.0.0 /data/local/tmp/
	./android-sdk-linux/platform-tools/adb shell 'cd /data/local/tmp; LD_LIBRARY_PATH=. ./fips_hmac -v fips_hmac'

realclean:
	rm -rf fips openssl-fips-2.0.2 openssl-1.0.1c fips_hmac
