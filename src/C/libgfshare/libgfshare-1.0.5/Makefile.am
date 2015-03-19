# Copyright Daniel Silverstone <dsilvers@digital-scurf.org> 2006-2011

# ensure our m4 can be found.
ACLOCAL_AMFLAGS = -I m4

# Ensure the pc.in is included in the dist tar
EXTRA_DIST = libgfshare.pc.in README COPYRIGHT tests/test_gfsplit_gfcombine.sh
EXTRA_DIST += doc/theory.tex AUTHORS

# Useful maketable binary
noinst_PROGRAMS = gfshare_maketable
gfshare_maketable_SOURCES = src/gfshare_maketable.c

# Assemble the library
lib_LTLIBRARIES = libgfshare.la
libgfshare_la_SOURCES = include/libgfshare.h src/libgfshare.c \
                        libgfshare_tables.h
libgfshare_la_LDFLAGS = -version-info @LTLIBVER@
include_HEADERS = include/libgfshare.h

$(top_srcdir)/src/libgfshare.c: libgfshare_tables.h
libgfshare_tables.h: gfshare_maketable$(EXEEXT)
	./gfshare_maketable$(EXEEXT) > libgfshare_tables.h

# And provide for the pkgconfigness
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libgfshare.pc

# Ensure the C files can find the headers
AM_CFLAGS = -I$(srcdir)/include

# Our programs come next...

bin_PROGRAMS = gfsplit gfcombine

gfsplit_SOURCES = tools/gfsplit.c
gfsplit_LDADD = libgfshare.la

gfcombine_SOURCES = tools/gfcombine.c
gfcombine_LDADD = libgfshare.la

# Manual pages are useful for teaching people how to do stuff

man_MANS = man/gfshare.7 man/gfsplit.1 man/gfcombine.1 man/libgfshare.5

# Ensure our tests get run...
C_TESTS = test_gfshare_isfield test_gfshare_blockwise_simple
TESTS = $(C_TESTS) tests/test_gfsplit_gfcombine.sh

check_PROGRAMS = $(C_TESTS)

test_gfshare_isfield_SOURCES = tests/test_gfshare_isfield.c libgfshare_tables.h

test_gfshare_blockwise_simple_SOURCES = tests/test_gfshare_blockwise_simple.c
test_gfshare_blockwise_simple_LDADD = libgfshare.la
test_gfshare_blockwise_simple_LDFLAGS = -static

# When cleaning up, ensure we remove any coverage results and the tables
clean-local: libgfshare-clean-local libgfshare-clean-local-coverage
libgfshare-clean-local:
	rm -f libgfshare_tables.h

libgfshare-clean-local-coverage:
	rm -f src/*.gcno src/*.gcda src/*.bb src/*.bbg src/*.da
	rm -f tests/*.gcno tests/*.gcda tests/*.bb tests/*.bbg tests/*.da
	rm -f tools/*.gcno tools/*.gcda tools/*.bb tools/*.bbg tools/*.da

maintainer-clean-local: libgfshare-maintainer-clean-local
libgfshare-maintainer-clean-local:
	rm -f src/*.gcov tests/*.gcov tools/*.gcov
