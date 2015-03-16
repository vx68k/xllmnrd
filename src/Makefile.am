## Process this file with automake to produce a Makefile.in.

AM_CPPFLAGS = -I$(top_builddir)/libgnu -I$(top_srcdir)/libgnu \
-DLOCALEDIR=\"$(localedir)\"

LDADD = ../libgnu/libgnu.a

sbin_PROGRAMS = xllmnrd
noinst_LIBRARIES = libxllmnrd.a
man_MANS = xllmnrd.8

xllmnrd_LDADD = libxllmnrd.a $(LDADD)
xllmnrd_SOURCES = main.cpp

libxllmnrd_a_SOURCES = responder.c llmnr.c ifaddr.c

noinst_HEADERS = responder.h llmnr.h llmnr_packet.h ascii.h ifaddr.h
EXTRA_DIST = xllmnrd.8.in

CLEANFILES = xllmnrd.8

xllmnrd.8: $(srcdir)/xllmnrd.8.in Makefile
	@rm -f $@-t $@
	sed -e 's,[@]PACKAGE_NAME[@],$(PACKAGE_NAME),g' \
	  -e 's,[@]PACKAGE_VERSION[@],$(PACKAGE_VERSION),g' \
	  -e 's,[@]PACKAGE_STRING[@],$(PACKAGE_STRING),g' \
	  < $(srcdir)/xllmnrd.8.in > $@-t
	mv -f $@-t $@
