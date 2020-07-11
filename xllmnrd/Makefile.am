## Process this file with automake to produce Makefile.in.

AM_CPPFLAGS = -DLOCALEDIR=\"$(localedir)\" -I$(top_srcdir)/libxllmnrd \
-I$(top_builddir)/libgnu -I$(top_srcdir)/libgnu

sbin_PROGRAMS = xllmnrd
man_MANS = xllmnrd.8

noinst_SCRIPTS = xllmnrd.init
noinst_HEADERS = responder.h llmnr_packet.h

xllmnrd_SOURCES = xllmnrd.cpp responder.cpp llmnr.c
xllmnrd_LDADD = ../libxllmnrd/libxllmnrd.a ../libgnu/libgnu.a

EXTRA_DIST = xllmnrd.8.in xllmnrd.init.in

MOSTLYCLEANFILES = xllmnrd.8-t
CLEANFILES = xllmnrd.8 xllmnrd.init

xllmnrd.8: $(srcdir)/xllmnrd.8.in $(top_builddir)/config.status
	cd $(top_builddir) && $(SHELL) ./config.status --file=$(subdir)/$@

xllmnrd.init: $(srcdir)/xllmnrd.init.in $(top_builddir)/config.status
	cd $(top_builddir) && $(SHELL) ./config.status --file=$(subdir)/$@
	chmod +x $@
