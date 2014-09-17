#
all:	test

openssl-fips-2.0.1.tar.gz:
	wget http://www.openssl.org/source/openssl-fips-2.0.1.tar.gz

openssl-1.0.1c.tar.gz:
	wget http://www.openssl.org/source/openssl-1.0.1c.tar.gz

ssl/:	
	mkdir ssl

openssl-fips-2.0.1/.built:	openssl-fips-2.0.1.tar.gz ssl/
	gunzip -c ../openssl-fips-2.0.1.tar.gz | tar xf -
	cd openssl-fips-2.0.1; \
	export FIPSDIR=$$PWD/../ssl/fips2.0; \
	./config; \
	make; \
	make install; \
	touch .built

openssl-1.0.1c/.built:	openssl-fips-2.0.1/.built openssl-1.0.1c.tar.gz
	gunzip  -c openssl-1.0.1c.tar.gz | tar xf -
	cd openssl-1.0.1c; \
	./config fips shared --openssldir=$$PWD/../ssl --with-fipsdir=$$PWD/../ssl/fips2.0; \
	make depend; \
	make; \
	make install; \
	touch .built

test:	openssl-1.0.1c/.built
	OPENSSL_FIPS=1 LD_LIBRARY_PATH=ssl/lib ssl/bin/openssl version
	# this should work:
	LD_LIBRARY_PATH=ssl/lib ssl/bin/openssl md5 Makefile
	# should get errors for this:
	OPENSSL_FIPS=1 LD_LIBRARY_PATH=ssl/lib ssl/bin/openssl md5 Makefile

clean:
	rm -rf openssl-fips-2.0.1 openssl-1.0.1c ssl

