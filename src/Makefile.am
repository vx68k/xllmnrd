## Process this file with automake to produce a Makefile.in.

AUTOMAKE_OPTIONS = parallel-tests

AM_CPPFLAGS = -I$(top_builddir)/libgnu -I$(top_srcdir)/libgnu \
-DLOCALEDIR=\"$(localedir)\"
AM_CXXFLAGS = $(CPPUNIT_CFLAGS)

sbin_PROGRAMS = xllmnrd
man_MANS = xllmnrd.8

noinst_LIBRARIES = libxllmnrd.a

check_PROGRAMS = ifaddr.test
check_SCRIPTS = run

xllmnrd_SOURCES = main.c
xllmnrd_LDADD = libxllmnrd.a ../libgnu/libgnu.a

libxllmnrd_a_SOURCES = responder.c llmnr.c ifaddr.c

ifaddr_test_SOURCES = testmain.cpp testifaddr.cpp
ifaddr_test_LDADD = $(xllmnrd_LDADD) $(CPPUNIT_LIBS)

noinst_HEADERS = responder.h llmnr.h llmnr_packet.h ascii.h ifaddr.h
EXTRA_DIST = xllmnrd.8.in run.sh

TESTS = $(check_PROGRAMS)
TEST_LOG_COMPILER = ./run

MOSTLYCLEANFILES = xllmnrd.8-t run-t
CLEANFILES = xllmnrd.8 run *.test.xml

xllmnrd.8: $(srcdir)/xllmnrd.8.in Makefile
	@rm -f $@-t $@
	sed -e 's,[@]PACKAGE_NAME[@],$(PACKAGE_NAME),g' \
	  -e 's,[@]PACKAGE_VERSION[@],$(PACKAGE_VERSION),g' \
	  -e 's,[@]PACKAGE_STRING[@],$(PACKAGE_STRING),g' \
	  < $(srcdir)/xllmnrd.8.in > $@-t
	mv -f $@-t $@

run: run.sh
	cat < $(srcdir)/run.sh > $@-t
	chmod a+x $@-t
	mv -f $@-t $@
