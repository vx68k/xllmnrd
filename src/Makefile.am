## Process this file with automake to produce Makefile.in.

AM_CPPFLAGS = -DLOCALEDIR=\"$(localedir)\" -I$(top_srcdir)/libxllmnrd \
-I$(top_builddir)/libgnu -I$(top_srcdir)/libgnu

sbin_PROGRAMS = xllmnrd
man_MANS = xllmnrd.8

noinst_HEADERS = responder.h llmnr.h llmnr_packet.h

xllmnrd_SOURCES = main.cpp responder.cpp llmnr.c
xllmnrd_LDADD = ../libxllmnrd/libxllmnrd.a ../libgnu/libgnu.a

EXTRA_DIST = xllmnrd.8.in

MOSTLYCLEANFILES = xllmnrd.8-t
CLEANFILES = xllmnrd.8

xllmnrd.8: $(srcdir)/xllmnrd.8.in Makefile
	@rm -f $@-t $@
	sed -e 's,[@]PACKAGE_NAME[@],$(PACKAGE_NAME),g' \
	  -e 's,[@]PACKAGE_VERSION[@],$(PACKAGE_VERSION),g' \
	  -e 's,[@]PACKAGE_STRING[@],$(PACKAGE_STRING),g' \
	  < $(srcdir)/xllmnrd.8.in > $@-t
	mv -f $@-t $@
