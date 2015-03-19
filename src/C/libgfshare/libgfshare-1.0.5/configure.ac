# Copyright (c) Daniel Silverstone <dsilvers@digital-scurf.org> 2006-2011


AC_PREREQ(2.57)
AC_INIT(libgfshare, [1.0.5], [dsilvers@digital-scurf.org])
AC_SUBST(LTLIBVER, 1:5:0)

AC_CONFIG_MACRO_DIR(m4)

AC_CONFIG_SRCDIR([include/libgfshare.h])

AM_INIT_AUTOMAKE([1.9 foreign dist-bzip2 tar-ustar subdir-objects])
AM_MAINTAINER_MODE

AC_PROG_CPP
AC_PROG_CC
AC_PROG_CXX
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET

AC_PROG_LIBTOOL

COMPILER_COVERAGE
LINKER_OPTIMISATIONS
COMPILER_WARNINGS
COMPILER_OPTIMISATIONS


AC_CONFIG_FILES([
Makefile
libgfshare.pc
man/gfsplit.1
man/gfcombine.1
man/gfshare.7
man/libgfshare.5
])

AC_CONFIG_HEADERS([config.h])

AC_OUTPUT
