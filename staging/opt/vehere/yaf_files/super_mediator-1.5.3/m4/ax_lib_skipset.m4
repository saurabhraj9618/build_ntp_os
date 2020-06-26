dnl Copyright (C) 2004-2012 by Carnegie Mellon University.
dnl
dnl @OPENSOURCE_HEADER_START@
dnl
dnl Use of the SILK system and related source code is subject to the terms
dnl of the following licenses:
dnl
dnl GNU Public License (GPL) Rights pursuant to Version 2, June 1991
dnl Government Purpose License Rights (GPLR) pursuant to DFARS 252.227.7013
dnl
dnl NO WARRANTY
dnl
dnl ANY INFORMATION, MATERIALS, SERVICES, INTELLECTUAL PROPERTY OR OTHER
dnl PROPERTY OR RIGHTS GRANTED OR PROVIDED BY CARNEGIE MELLON UNIVERSITY
dnl PURSUANT TO THIS LICENSE (HEREINAFTER THE "DELIVERABLES") ARE ON AN
dnl "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY
dnl KIND, EITHER EXPRESS OR IMPLIED AS TO ANY MATTER INCLUDING, BUT NOT
dnl LIMITED TO, WARRANTY OF FITNESS FOR A PARTICULAR PURPOSE,
dnl MERCHANTABILITY, INFORMATIONAL CONTENT, NONINFRINGEMENT, OR ERROR-FREE
dnl OPERATION. CARNEGIE MELLON UNIVERSITY SHALL NOT BE LIABLE FOR INDIRECT,
dnl SPECIAL OR CONSEQUENTIAL DAMAGES, SUCH AS LOSS OF PROFITS OR INABILITY
dnl TO USE SAID INTELLECTUAL PROPERTY, UNDER THIS LICENSE, REGARDLESS OF
dnl WHETHER SUCH PARTY WAS AWARE OF THE POSSIBILITY OF SUCH DAMAGES.
dnl LICENSEE AGREES THAT IT WILL NOT MAKE ANY WARRANTY ON BEHALF OF
dnl CARNEGIE MELLON UNIVERSITY, EXPRESS OR IMPLIED, TO ANY PERSON
dnl CONCERNING THE APPLICATION OF OR THE RESULTS TO BE OBTAINED WITH THE
dnl DELIVERABLES UNDER THIS LICENSE.
dnl
dnl Licensee hereby agrees to defend, indemnify, and hold harmless Carnegie
dnl Mellon University, its trustees, officers, employees, and agents from
dnl all claims or demands made against them (and any related losses,
dnl expenses, or attorney's fees) arising out of, or relating to Licensee's
dnl and/or its sub licensees' negligent use or willful misuse of or
dnl negligent conduct or willful misconduct regarding the Software,
dnl facilities, or other rights or assistance granted by Carnegie Mellon
dnl University under this License, including, but not limited to, any
dnl claims of product liability, personal injury, death, damage to
dnl property, or violation of any laws or regulations.
dnl
dnl Carnegie Mellon University Software Engineering Institute authored
dnl documents are sponsored by the U.S. Department of Defense under
dnl Contract FA8721-05-C-0003. Carnegie Mellon University retains
dnl copyrights in all material produced under this contract. The U.S.
dnl Government retains a non-exclusive, royalty-free license to publish or
dnl reproduce these documents, or allow others to do so, for U.S.
dnl Government purposes only pursuant to the copyright license under the
dnl contract clause at 252.227.7013.
dnl
dnl @OPENSOURCE_HEADER_END@

dnl RCSIDENT("$Id$")


# ---------------------------------------------------------------------------
# AX_LIB_SKIPSET
#
#    Determine how to use skipset.  Output variable: SKIPSET_LDFLAGS
#    Output definition: HAVE_SKIPSET
#
AC_DEFUN([AX_LIB_SKIPSET],[
	AC_SUBST(SKIPSET_LDFLAGS)

	silk_header_names="silk/skipset.h silk-ipset/skipset.h"
	silk_library_names="silk skipset"	

	AC_ARG_WITH([skipset],[AS_HELP_STRING([--with-skipset=SKIPSET_DIR],
	[specify location of SiLK or SiLK IPSet Library; find "silk-ipset/skipset.h" or "silk/silk.h" in SKIPSET_DIR/include/; find "libskipset.so" or "libsilk.so" in SKIPSET_DIR/lib/
	])],[
	   if test "x$withval" != "xyes"
           then 
	      skipset_dir="$withval"
              skipset_includes="$skipset_dir/include"
	      skipset_libs="$skipset_dir/lib"
           fi
        ])


	ENABLE_SKIPSET=0;


	if test "x$skipset_dir" != "xno"
	then
	    skip_save_LDFLAGS="$LDFLAGS"
	    skip_save_LIBS="$LIBS"
	    skip_save_CFLAGS="$CFLAGS"
	    skip_save_CPPFLAGS="$CPPFLAGS"

	    if test "x$skipset_libs" != "x"
	    then
	      SKIPSET_LDFLAGS="-L$skipset_libs"
	      LDFLAGS="$SKIPSET_LDFLAGS $skip_save_LDFLAGS"
	    fi

	    if test "x$skipset_includes" != "x"
  	    then
		SKIPSET_CFLAGS="-I$skipset_includes"
		CPPFLAGS="$SKIPSET_CFLAGS $skip_save_CPPFLAGS"
	    fi
	    
	    for sk_ip_hdr in $silk_header_names
	    do
		AC_CHECK_HEADER([$sk_ip_hdr], [
		    sk_ip_hdr="<$sk_ip_hdr>"
		    ENABLE_SKIPSET=1
		    break])
	    done	    

	    if test "x$ENABLE_SKIPSET" = "x1"
	    then
	        AC_CHECK_HEADERS([silk/skipaddr.h silk/utils.h])

	    	AC_SEARCH_LIBS([skIPSetLoad],[$silk_library_names],[ENABLE_SKIPSET=1],[ENABLE_SKIPSET=0])

	    	if test "x$ENABLE_SKIPSET" = "x1"
	    	then
			case "(X$ac_cv_search_skIPSetLoad" in *X-l*)
		     	SKIPSET_LDFLAGS="$SKIPSET_LDFLAGS $ac_cv_search_skIPSetLoad" ;;
			esac
            	fi
	    fi
	    		
	     # Restore cached values		                     
             LDFLAGS="$skip_save_LDFLAGS"
             LIBS="$skip_save_LIBS"
             CFLAGS="$skip_save_CFLAGS"
             CPPFLAGS="$skip_save_CPPFLAGS"	    

	fi
    
        if test "x$ENABLE_SKIPSET" != "x1"
	   then
	       AC_MSG_NOTICE([Not building IPSET support due to missing skipset headers or libraries])
	       SKIPSET_LDFLAGS=
               SKIPSET_CLAGS=
           else
	      AC_DEFINE_UNQUOTED([SKIPSET_HEADER_NAME],[$sk_ip_hdr],
	          [When ENABLE_SKIPSET is set, this is the path to the skipset.h header file])
	fi

	AM_CONDITIONAL(HAVE_SKIPSET, [test "x$ENABLE_SKIPSET" = "x1"])
	if test "x$ENABLE_SKIPSET" = "x1"
	then
	    AC_DEFINE(ENABLE_SKIPSET, [1],	
                      [Define to 1 if SiLK IPSet libraries are available])
            RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --with-skipset"
	    AC_SUBST(SM_REQ_SKIPSET, [1])
	fi
])
