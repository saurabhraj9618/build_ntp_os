## Process this file with automake to produce Makefile.in
## ------------------------------------------------------------------------
## Makefile.am (toplevel)
## autotools build system for dns_pipeline
## ------------------------------------------------------------------------
## Copyright (C) 2012-2017 Carnegie Mellon University. All Rights Reserved.
## ------------------------------------------------------------------------
## Authors: CERT Network Situational Awareness <netsa-help@cert.org>
## ------------------------------------------------------------------------
## GNU General Public License (GPL) Rights pursuant to Version 2, June 1991
## Government Purpose License Rights (GPLR) pursuant to DFARS 252.227-7013
## ------------------------------------------------------------------------


ACLOCAL_AMFLAGS = -I m4

# Avoid picking up MacOS X resource forks in "make dist"
am__tar = COPY_EXTENDED_ATTRIBUTES_DISABLE=1 COPYFILE_DISABLE=1 ${AMTAR} cof - "$$tardir"

SUBDIRS = include src etc doc

utils-doc:
	(cd $(top_builddir)/src && $(MAKE) docs)
	(cd $(top_builddir)/doc && $(MAKE) docs)

release-note-doc: NEWS
	$(top_srcdir)/doc/news2xhtml.pl super_mediator gpl 10 < $(top_srcdir)/NEWS > doc/releases.xml

make-doc-path:
	mkdir -p $(top_builddir)/doc/html

distclean-local:
	rm -f $(top_builddir)/doc/releases.xml

docs: make-doc-path utils-doc release-note-doc

DISTCLEANFILES = $(SM_SUMMARY_FILE)

EXTRA_DIST = CMakeLists.txt \
	src/CMakeLists.txt \
	include/mediator/config.h.cmake \
	README \
	doc/add-header.pl \
	doc/add-header-md.pl \
	doc/news2xhtml.pl \
	doc/LICENSE.txt
