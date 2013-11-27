## Process this file with automake to produce a Makefile.in.

sbin_PROGRAMS = xllmnrd
man_MANS = xllmnrd.8

xllmnrd_SOURCES = main.c responder.c ifaddr.c

noinst_HEADERS = responder.h llmnr_packet.h ascii.h ifaddr.h
EXTRA_DIST = xllmnrd.8.in

CLEANFILES = xllmnrd.8

xllmnrd.8: xllmnrd.8.in Makefile
	@rm -f $@-t $@
	sed -e 's,[@]PACKAGE_NAME[@],$(PACKAGE_NAME),g' \
	  -e 's,[@]PACKAGE_VERSION[@],$(PACKAGE_VERSION),g' \
	  -e 's,[@]PACKAGE_STRING[@],$(PACKAGE_STRING),g' \
	  < $(srcdir)/xllmnrd.8.in > $@-t
	mv $@-t $@
