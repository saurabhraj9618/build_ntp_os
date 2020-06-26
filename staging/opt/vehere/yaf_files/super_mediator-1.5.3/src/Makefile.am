## Process this file with automake to produce Makefile.in
## ------------------------------------------------------------------------
## Makefile.am (source)
## autotools build system for super-mediator
## ------------------------------------------------------------------------
## Copyright (C) 2012-2016 Carnegie Mellon University. All Rights Reserved.
## ------------------------------------------------------------------------
## Authors: Emily Sarneso
## ------------------------------------------------------------------------
## GNU General Public License (GPL) Rights pursuant to Version 2, June 1991
## Government Purpose License Rights (GPLR) pursuant to DFARS 252.227-7013
## ------------------------------------------------------------------------


bin_PROGRAMS = super_mediator

if MYSQLENABLE
bin_PROGRAMS += super_table_creator
endif

WARN_CFLAGS = -g -DDEBUG -Wall

AM_CFLAGS = $(WARN_CFLAGS)

PODFILES = super_mediator.pod super_mediator.conf.pod super_table_creator.pod
man1_MANS = super_mediator.1 super_mediator.conf.1 super_table_creator.1
HTMLFILES = super_mediator.html super_mediator.conf.html super_table_creator.html

.pod.1:
	$(POD2MAN) $(SM_POD2MAN_ARGS) --section=1 $< $@

.pod.html:
	$(POD2HTML) --noindex --infile="$<" --outfile="$@"
	$(top_srcdir)/doc/add-header.pl "$@"

copy-html-pages: $(HTMLFILES)
	mkdir -p $(top_builddir)/doc/html
	cp $(HTMLFILES) $(top_builddir)/doc/html

docs: $(man1_MANS) copy-html-pages

clean-docs:
	rm -f $(man1_MANS) $(HTMLFILES)

clean-local:
	rm -f pod2htm*.tmp

CLEANFILES = $(man1_MANS) $(HTMLFILES)

EXTRA_DIST = $(PODFILES) lookup3.c

super_mediator_LDADD = @GLIB_LDADD@
super_mediator_SOURCES = mediator.c mediator_core.c mediator_export.c mediator_open.c mediator_dns.c mediator_filter.c mediator_stat.c mediator_config_parse.y mediator_config_lex.l mediator_log.c mediator_util.c mediator_print.c mediator_json.c mediator_dedup.c mediator_ssl.c
super_mediator_LDFLAGS = @GLIB_LIBS@ @libfixbuf_LIBS@ @SPREAD_LDFLAGS@ @SPREAD_LIBS@ @MYSQL_LDFLAGS@ @SKIPSET_LDFLAGS@
super_mediator_CFLAGS = $(WARN_CFLAGS) @GLIB_CFLAGS@ @libfixbuf_CFLAGS@ @SPREAD_CFLAGS@ @MYSQL_CFLAGS@

super_table_creator_LDADD = @GLIB_LDADD@
super_table_creator_SOURCES = mediator_mysql.c
super_table_creator_LDFLAGS = @GLIB_LIBS@ @MYSQL_LDFLAGS@
super_table_creator_CFLAGS = @GLIB_CFLAGS@ @MYSQL_CFLAGS@


noinst_HEADERS = mediator_dns.h mediator_stat.h mediator_log.h mediator_print.h mediator_json.h mediator_dedup.h mediator_ssl.h

AM_YFLAGS = -d
mediator_config_lex.$(OBJEXT) mediator_config_lex.lo: mediator_config_parse.h

