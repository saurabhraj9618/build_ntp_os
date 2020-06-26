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


TUTORIALS = quick_setup.md sm_guide.md sm_dedup.md sm_ssl_dedup.md
HTMLFILES = quick_setup.html sm_guide.html sm_dedup.html sm_ssl_dedup.html

.md.html:
	$(PANDOC) -f markdown -t html --columns=1000 "$<" -o "$@"
	$(top_srcdir)/doc/add-header-md.pl "$@"

copy-html-pages: $(HTMLFILES)
	mkdir -p $(top_builddir)/doc/html
	cp $(HTMLFILES) $(top_builddir)/doc/html

docs: copy-html-pages

clean-docs:
	rm -f $(HTMLFILES)
	rm -f -r $(top_srcdir)/doc/html

CLEANFILES = $(HTMLFILES)

EXTRA_DIST = $(TUTORIALS)
