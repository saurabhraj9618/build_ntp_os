dnl Process this file with autoconf to produce a configure script
dnl ------------------------------------------------------------------------
dnl yafconfig.m4
dnl write summary of configure to a file (stolen from SiLK)
dnl ------------------------------------------------------------------------
dnl Copyright (C) 2014 Carnegie Mellon University. All Rights Reserved.
dnl ------------------------------------------------------------------------
dnl Authors: Emily Sarneso
dnl ------------------------------------------------------------------------
dnl GNU General Public License (GPL) Rights pursuant to Version 2, June 1991
dnl Government Purpose License Rights (GPLR) pursuant to DFARS 252.227-7013
dnl ------------------------------------------------------------------------

AC_DEFUN([SM_AC_WRITE_SUMMARY],[
    AC_SUBST(SM_SUMMARY_FILE)
    SM_SUMMARY_FILE=sm-summary.txt

    SM_FINAL_MSG="
    * Configured package:           ${PACKAGE_STRING}
    * pkg-config path:              ${PKG_CONFIG_PATH}
    * Host type:                    ${build}
    * Source files (\$top_srcdir):   $srcdir
    * Install directory:            $prefix"


    YF_LIBSTR_STRIP($GLIB_LIBS)
    SM_FINAL_MSG="$SM_FINAL_MSG
    * GLIB:                         $yf_libstr"

    if test "x$ENABLE_LOCALTIME" = "x1"
    then
        SM_BUILD_CONF="
    * Timezone support:             local"
    else
        SM_BUILD_CONF="
    * Timezone support:             UTC"
    fi

    YF_PKGCONFIG_VERSION(libfixbuf)
    YF_PKGCONFIG_LPATH(libfixbuf)
    yf_msg_ldflags=`echo "$yfpkg_lpath" | sed 's/^ *//' | sed 's/ *$//'`
    SM_BUILD_CONF="$SM_BUILD_CONF
    * Libfixbuf version:            ${yfpkg_ver}"


    yfpkg_spread=`$PKG_CONFIG --cflags libfixbuf | grep 'SPREAD'`
    if test "x$yfpkg_spread" = "x"
    then
      SM_BUILD_CONF="$SM_BUILD_CONF
    * Spread Support:               NO"
    else
      SM_BUILD_CONF="$SM_BUILD_CONF
    * Spread Support:               YES"
    fi

    if test "$found_mysql" = "yes"
    then
	SM_BUILD_CONF="$SM_BUILD_CONF
    * MySQL Support:                YES (v. $MYSQL_VERSION)"
    else
        SM_BUILD_CONF="$SM_BUILD_CONF
    * MySQL Support:		    NO"
    fi

    if test "x$ENABLE_SKIPSET" = "x1"
    then
	SM_BUILD_CONF="$SM_BUILD_CONF
    * SiLK IPset Support:           YES"
    else
        SM_BUILD_CONF="$SM_BUILD_CONF
    * SiLK IPset Support:           NO"
    fi

    # Remove leading whitespace
    yf_msg_cflags="$CPPFLAGS $CFLAGS"
    yf_msg_cflags=`echo "$yf_msg_cflags" | sed 's/^ *//' | sed 's/  */ /g'`

    yf_msg_ldflags="$SM_LDFLAGS $LDFLAGS"
    yf_msg_ldflags=`echo "$yf_msg_ldflags" | sed 's/^ *//' | sed 's/  */ /g'`

    yf_msg_libs="$LIBS"
    yf_msg_libs=`echo "$yf_msg_libs" | sed 's/^ *//' | sed 's/  */ /g'`

    SM_FINAL_MSG="$SM_FINAL_MSG $SM_BUILD_CONF
    * Compiler (CC):                $CC
    * Compiler flags (CFLAGS):      $yf_msg_cflags
    * Linker flags (LDFLAGS):       $yf_msg_ldflags
    * Libraries (LIBS):             $yf_msg_libs
"

    echo "$SM_FINAL_MSG" > $SM_SUMMARY_FILE

    AC_CONFIG_COMMANDS([sm_summary],[
        if test -f $SM_SUMMARY_FILE
        then
            cat $SM_SUMMARY_FILE
        fi],[SM_SUMMARY_FILE=$SM_SUMMARY_FILE])

  #Put config info into the version output of yaf
  SM_BUILD_CONF=${SM_BUILD_CONF}"\n"
  #AC_DEFINE_UNQUOTED([SM_BCONF_STRING_STR], ["${SM_BUILD_CONF}"], [configure script options])
])