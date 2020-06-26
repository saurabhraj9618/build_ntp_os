dnl Process this file with autoconf to produce a configure script
dnl ------------------------------------------------------------------------
dnl configure.ac
dnl ------------------------------------------------------------------------
dnl Copyright (C) 2012-2017 Carnegie Mellon University. All Rights Reserved.
dnl ------------------------------------------------------------------------
dnl Authors: CERT Network Situational Awareness <netsa-help@cert.org>
dnl ------------------------------------------------------------------------
dnl GNU General Public License (GPL) Rights pursuant to Version 2, June 1991
dnl Government Purpose License Rights (GPLR) pursuant to DFARS 252.227-7013
dnl ------------------------------------------------------------------------

dnl RCSIDENT("$Id: configure.in 14363 2009-05-27 16:27:40Z tonyc $")

AC_PREREQ(2.59)
AC_INIT([super_mediator], [1.5.3], [netsa-help@cert.org],[super_mediator])
AC_CONFIG_SRCDIR([.])
AC_CONFIG_HEADERS(include/mediator/config.h)
AC_COPYRIGHT([Copyright (C) 2012-2017 by Carnegie Mellon University
GNU Public License (GPL) Rights pursuant to Version 2, June 1991
Government Purpose License Rights (GPLR) pursuant to DFARS 252.227-7013])
AC_REVISION([$Id:  $])
AC_CONFIG_AUX_DIR([autoconf])
AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_CANONICAL_TARGET
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.9 foreign check-news subdir-objects])

AC_PROG_CC
AM_PROG_LEX
AC_PROG_YACC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_HEADER_STDC
AC_LANG_C

AC_SUBST(AM_CPPFLAGS)
AC_SUBST(AM_CFLAGS)
AC_SUBST(AM_LDFLAGS)
LT_INIT

RPM_CONFIG_FLAGS=""
CPPFLAGS='-I$(top_builddir)/include -I$(top_srcdir)/include'" $CPPFLAGS"


AC_CHECK_HEADERS([glob.h errno.h pthread.h stdarg.h stdint.h stddef.h stdio.h stdlib.h string.h])
dnl ----------------------------------------------------------------------
dnl for some reason prefix doesn't get set here - so this is a nice hack
dnl ----------------------------------------------------------------------

if test "x$prefix" = "xNONE"; then
   prefix=/usr/local
fi

dnl ----------------------------------------------------------------------
dnl Modify PKG_CONFIG_PATH based on prefix
dnl ----------------------------------------------------------------------

if test "x$PKG_CONFIG_PATH" != "x"; then
    PKG_CONFIG_PATH="$PKG_CONFIG_PATH:$prefix/lib/pkgconfig"
    export PKG_CONFIG_PATH
else
    PKG_CONFIG_PATH="$prefix/lib/pkgconfig"
    export PKG_CONFIG_PATH
fi

dnl ----------------------------------------------------------------------
dnl Check for a suitable glib
dnl ----------------------------------------------------------------------

GLIB_PRESENT=NO
GLIB_LDADD=

AM_PATH_GLIB_2_0([2.12.0],[GLIB_PRESENT=YES], [GLIB_PRESENT=NO], [gthread])

AC_ARG_WITH(glib-static,
AC_HELP_STRING([--with-glib-static=prefix],[use static glib tree (prefix is REQUIRED)]),[
GLIB_STATIC_LIBGLIB2_A="${withval}/lib/libglib-2.0.a"
GLIB_STATIC_INCLUDE="${withval}/include/glib-2.0"
GLIB_STATIC_LIBINCLUDE="${withval}/lib/glib-2.0/include"
if test -f ${GLIB_STATIC_LIBGLIB2_A}; then
   if test -f "${GLIB_STATIC_INCLUDE}/glib.h"; then
        GLIB_LDADD=${GLIB_STATIC_LIBGLIB2_A}
        GLIB_CFLAGS="-I${GLIB_STATIC_INCLUDE} -I${GLIB_STATIC_LIBINCLUDE}"
        AC_SUBST(GLIB_LIBS)
        AC_SUBST(GLIB_CFLAGS)
        GLIB_PRESENT=YES
        AC_MSG_NOTICE([assuming static glib in ${withval} is good...])
    fi
fi
])

if test x"$GLIB_PRESENT" != "xYES"; then
  AC_MSG_ERROR([Cannot find a suitable glib2 (>= 2.12.0)])
fi

AC_SUBST(GLIB_LDADD)

AC_DEFUN([YF_PKGCONFIG_VERSION],[
        AC_REQUIRE([PKG_PROG_PKG_CONFIG])
        yfpkg_ver=`$PKG_CONFIG --modversion $1`
])

AC_DEFUN([YF_PKGCONFIG_LPATH],[
        AC_REQUIRE([PKG_PROG_PKG_CONFIG])
        yfpkg_lpath=`$PKG_CONFIG --libs-only-L $1 | cut -d' ' -f 1`
])

AC_DEFUN([YF_LIBSTR_STRIP],[
#       _resultString=[`echo $1 | sed 's/-L\([^ ]*\).*/\1/pg'`]
#       yf_libstr=${_resultString}
        yf_libstr=$1
])

dnl ----------------------------------------------------------------------
dnl Check for libfixbuf
dnl when changing the version number required, do both the subst, and
dnl package lines!
dnl ----------------------------------------------------------------------
AC_SUBST(YAF_REQ_FIXBUF_VER, [1.7.0])
PKG_CHECK_MODULES(libfixbuf, [libfixbuf >= 1.7.0],
                  [
                    YF_PKGCONFIG_VERSION(libfixbuf)
                    YF_PKGCONFIG_LPATH(libfixbuf)
                    OPTION_CONFIG_STRING=${OPTION_CONFIG_STRING}"fixbuf "${yfpkg_ver}" "${yfpkg_lpath}"|"
                  ],
                  [AC_MSG_ERROR([Cannot find a suitable libfixbuf (>= 1.7.0) (Try setting PKG_CONFIG_PATH): $libfixbuf_PKG_ERRORS])
])

YF_PKGCONFIG_VERSION(libfixbuf)
fixbuf_install_loc=`$PKG_CONFIG --variable=prefix libfixbuf`
AC_MSG_NOTICE([libfixbuf version: $yfpkg_ver])
AC_MSG_NOTICE([Using libfixbuf installed in: $fixbuf_install_loc])
AC_DEFINE_UNQUOTED([FIXBUF_VERSION], ["$yfpkg_ver"], [fixbuf version])

dnl ----------------------------------------------------------------------
dnl check for disabling export of type information via (RFC 5610) and
dnl template metadata information
dnl ----------------------------------------------------------------------

AC_MSG_NOTICE($yfpkg_ver)
AX_COMPARE_VERSION($yfpkg_ver, [ge], [1.8.0],
[
    AC_ARG_ENABLE(type-export,
        AC_HELP_STRING([--disable-type-export], [disable exporting of options records for enterprise-specific information elements]),
        [
            if test "x$enableval" = "xno"; then
                AC_DEFINE(SM_ENABLE_METADATA_EXPORT, 0, [Define to 1 to enable sm metadata export])
                type_export=false
                RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --disable-type-export"
                AC_MSG_NOTICE([type export is disabled])
                OPTION_CONFIG_STRING=${OPTION_CONFIG_STRING}"no type export|"
            else
                AC_MSG_NOTICE([type export is not disabled])
                type_export=true
                AC_DEFINE(SM_ENABLE_METADATA_EXPORT, 1, [Define to 1 to enable sm metadata export])
                OPTION_CONFIG_STRING=${OPTION_CONFIG_STRING}"type export|"
            fi
        ],
        [
            AC_DEFINE(SM_ENABLE_METADATA_EXPORT, 1, [Define to 1 to enable sm metadata export])
            AC_MSG_NOTICE([Metadata export is enabled by default])
            type_export=true
            OPTION_CONFIG_STRING=${OPTION_CONFIG_STRING}"type export|"
        ]
    )
],[
    AC_DEFINE(SM_ENABLE_METADATA_EXPORT, 0, [Define to 1 to enable sm metadata export])
    AC_MSG_NOTICE([Metadata export is disabled due to lack of fixbuf >= 1.8.0])
    type_export=false
    OPTION_CONFIG_STRING=${OPTION_CONFIG_STRING}"type export|"
])

dnl ----------------------------------------------------------------------
dnl Check for Spread Support
dnl ----------------------------------------------------------------------

AC_PATH_SPREAD([4.1])
if test "x$ac_cv_header_spread_sp_h" == "xyes"; then
   AC_SUBST(SM_REQ_LIBSPREAD, [1])
fi

dnl---------------------------------------------------------------------
dnl Check fo MySQL support
dnl --------------------------------------------------------------------
AX_LIB_MYSQL([5.0])

dnl--------------------------------------------------------------------
dnl Check for OpenSSL support
dnl--------------------------------------------------------------------
AC_ARG_WITH(openssl,
AC_HELP_STRING([--with-openssl=prefix], [Use OpenSSL for Hashing support]),[
if test -d ${withval}; then
    LDFLAGS="-L${withval}/lib ${LDFLAGS}"
    CFLAGS="-I${withval}/include ${CFLAGS}"
    RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --with-openssl=${withval}"
else
    RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --with-openssl"
fi


dnl look for libssl
    AC_CHECK_LIB(crypto,MD5,[
    AC_DEFINE(HAVE_OPENSSL, 1, [Define to 1 to enable OpenSSL support])
        LIBS="-lssl -lcrypto ${LIBS}"
    ],[
        AC_MSG_ERROR([--with-openssl given but cannot find MD5()])
    ])

    AC_CHECK_LIB(crypto,SHA1,[
    AC_DEFINE(HAVE_OPENSSL, 1, [Define to 1 to enable OpenSSL support])
    ],[
        AC_MSG_ERROR([--with-openssl given but cannot find SHA1()])
    ])

    AC_CHECK_HEADERS(openssl/sha.h openssl/md5.h,[],
    [
       AC_MSG_ERROR([--with-openssl given but cannot find sha, md5 headers.])
    ])

])


AC_SUBST(RPM_CONFIG_FLAGS)

AC_SUBST([abs_top_srcdir])
AC_SUBST([abs_top_builddir])

dnl----------------------------------------------------------------------
dnl Check for silk-ipset library
dnl----------------------------------------------------------------------

AX_LIB_SKIPSET([3.0])

dnl ----------------------------------------------------------------------      
dnl Check for Unix vs. Linux privdrop (EWW EWW HACK EWW)                        
dnl ----------------------------------------------------------------------      
if test "x$target_os" = "xlinux" -o \
        "x$target_os" = "xlinux-gnu"; then
    AC_MSG_NOTICE([Enabling Linux privilege drop hack])
    AC_DEFINE([LINUX_PRIVHACK], 1,
              [Define to 1 on Linux for privilege drop hack])
else
    AC_MSG_NOTICE([Normal privilege drop (target os is $target_os)])
fi

dnl ----------------------------------------------------------------------
dnl Set up pod2man
dnl ----------------------------------------------------------------------
AC_CHECK_PROGS(POD2MAN, [pod2man true])

SM_POD2MAN_ARGS="--center='ipfix mediator' --release='"${PACKAGE_VERSION}"' --date='"`date +"%v"`"'"

AC_SUBST(SM_POD2MAN_ARGS)

dnl ----------------------------------------------------------------------
dnl Set up pod2html
dnl ----------------------------------------------------------------------
AC_CHECK_PROGS(POD2HTML,pod2html)


dnl ---------------------------------------------------------------------
dnl Check for decompression support
dnl ---------------------------------------------------------------------
AX_CHECK_LIBZ

dnl ----------------------------------------------------------------------
dnl Check for pandoc
dnl ----------------------------------------------------------------------
AC_CHECK_PROGS(PANDOC,pandoc)

SM_AC_WRITE_SUMMARY

AC_CONFIG_FILES([
    Makefile
    src/Makefile
    include/Makefile
    etc/Makefile
    doc/Makefile
    etc/init.d/super_mediator
    super_mediator.spec
])

dnl ----------------------------------------------------------------------
dnl Do output
dnl ----------------------------------------------------------------------

AC_OUTPUT
