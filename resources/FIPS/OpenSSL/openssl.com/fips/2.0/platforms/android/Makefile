#
# Makefile for building Android based configurations for Linux 
# and/or MacOS hosted build environments
#
# See http://www.opensslfoundation.com/fips/2.0/platforms/android/
#

#
# if you get a build error in the openssl-1.0.1c area you can re-run just
# the make portion using the 'remake' target
#

#
# for linux based building:
#	openssl-fips-2.0.2
#	openssl-1.0.1c
#	android-ndk-r8b
#	android-sdk-linux

#
# for macos based building:
#	openssl-fips-2.0.2
#	openssl-1.0.1c
#	android-ndk-r8c
#	android-sdk-macosx
#
# Note: the makefile depends on wget which you can install a version
#       from macports.org or simply use curl rather than wget as curl
#       is installed by default
#
#       WGET="curl -O" ANDK=android-ndk-r8c ASDK=android-sdk-macosx make 
#

#
# for cygwin based build:
#	openssl-fips-2.0.2
#	openssl-1.0.1c
# 	TODO
#

# change these versions as required ...
OPENSSL_FIPS_VERSION=2.0.2
OPENSSL_VERSION=1.0.1c

# Android SDK version
ASDK?=android-sdk-linux
# Android NDK version
ANDK?=android-ndk-r8b
# Android Platform
APLATFORM?=android-14

ADB?=./$(ASDK)/platform-tools/adb 

# WGET command
WGET?=wget

all:	fips_hmac

#
# note: this script has not yet be placed in this location 
#
fipsld-crosscompile-fix:
	$(WGET) http://www.opensslfoundation.com/fips/2.0/platforms/android/fipsld-crosscompile-fix

fips_hmac.c:
	$(WGET) http://www.opensslfoundation.com/fips/2.0/platforms/android/fips_hmac.c

setenv-android-4.1.sh:
	$(WGET) http://www.opensslfoundation.com/fips/2.0/platforms/android/setenv-android-4.1.sh

openssl-fips-$(OPENSSL_FIPS_VERSION).tar.gz:
	$(WGET) http://www.openssl.org/source/openssl-fips-$(OPENSSL_FIPS_VERSION).tar.gz

openssl-$(OPENSSL_VERSION).tar.gz:
	$(WGET) http://www.openssl.org/source/openssl-$(OPENSSL_VERSION).tar.gz

fips/:	
	mkdir fips

fips/.done:	fips/ fipsld-crosscompile-fix openssl-fips-$(OPENSSL_FIPS_VERSION).tar.gz
	gunzip -c openssl-fips-$(OPENSSL_FIPS_VERSION).tar.gz | tar xf -
	. ./setenv-android-4.1.sh; \
	cd openssl-fips-$(OPENSSL_FIPS_VERSION); \
	./config; \
	make; \
	make install INSTALLTOP=$$PWD/../fips; \
	cd ..; touch $@
	# keep a backup copy of the original fipsld
	if [ ! -f fips/bin/fipsld-original ]; then \
	  cp fips/bin/fipsld fips/bin/fipsld-original; \
	fi
	# copy in the fixed fipsld which handles cross-compile environments
	cp fipsld-crosscompile-fix fips/bin/fipsld

openssl-$(OPENSSL_VERSION)/.done:	fips/.done openssl-$(OPENSSL_VERSION).tar.gz setenv-android-4.1.sh
	gunzip -c openssl-$(OPENSSL_VERSION).tar.gz | tar xf -
	. ./setenv-android-4.1.sh; \
	cd openssl-$(OPENSSL_VERSION)/; \
	./config fips shared --with-fipsdir=$$PWD/../fips; \
	make depend; \
	make; \
	touch .done

remake: openssl-$(OPENSSL_VERSION)/.done
	. ./setenv-android-4.1.sh; \
	cd openssl-$(OPENSSL_VERSION)/; \
	make; \
	touch .done

libclean: openssl-$(OPENSSL_VERSION)/.done
	. ./setenv-android-4.1.sh; \
	cd openssl-$(OPENSSL_VERSION)/; \
	make libclean; \
	touch .done

fips_hmac:	openssl-$(OPENSSL_VERSION)/.done fips_hmac.c
	. ./setenv-android-4.1.sh; \
	arm-linux-androideabi-gcc -o fips_hmac fips_hmac.c -Iopenssl-$(OPENSSL_VERSION)/include/ -Lopenssl-$(OPENSSL_VERSION)/ -lcrypto -Iopenssl-$(OPENSSL_VERSION) -I$(ANDK)/platforms/$(APLATFORM)/arch-arm/usr/include -B$(ANDK)/platforms/$(APLATFORM)/arch-arm/usr/lib

test:	fips_hmac
	@echo "Copy executable"
	$(ADB) push fips_hmac /data/local/tmp/
	@echo "Copy shared library"
	$(ADB) push openssl-$(OPENSSL_VERSION)/libcrypto.so.1.0.0 /data/local/tmp/
	@echo "Run executable"
	$(ADB) shell 'cd /data/local/tmp; LD_LIBRARY_PATH=. ./fips_hmac -v fips_hmac'

realclean:
	rm -rf fips openssl-fips-$(OPENSSL_FIPS_VERSION) openssl-$(OPENSSL_VERSION) fips_hmac


#
# note: these files should all end up being downloadable from 
# 	http://www.opensslfoundation.com/fips/2.0/platforms/android/
archive:
	tar zcvf android-build.tgz \
		readme.txt darwin linux \
		fipsld-crosscompile-fix  \
		Makefile fips_hmac.c setenv-android-4.1.sh

