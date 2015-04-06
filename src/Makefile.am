## Process this file with automake to produce a Makefile.in.

AUTOMAKE_OPTIONS = parallel-tests

AM_CPPFLAGS = -I$(top_builddir)/libgnu -I$(top_srcdir)/libgnu \
-DLOCALEDIR=\"$(localedir)\"

sbin_PROGRAMS = xllmnrd
man_MANS = xllmnrd.8

noinst_LIBRARIES = libxllmnrd.a

check_PROGRAMS = runtest
check_DATA = cppunit.test

xllmnrd_SOURCES = main.c
xllmnrd_LDADD = libxllmnrd.a ../libgnu/libgnu.a

libxllmnrd_a_SOURCES = responder.c llmnr.c ifaddr.c

runtest_CXXFLAGS = $(CPPUNIT_CFLAGS)
runtest_SOURCES = testmain.cpp testifaddr.cpp
runtest_LDADD = libxllmnrd.a ../libgnu/libgnu.a $(CPPUNIT_LIBS)

noinst_HEADERS = responder.h llmnr.h llmnr_packet.h ascii.h ifaddr.h
EXTRA_DIST = xllmnrd.8.in

TESTS = cppunit.test
TEST_LOG_COMPILER = ./runtest
AM_TEST_LOG_FLAGS = -x $(@:.log=.xml)

CLEANFILES = xllmnrd.8 cppunit.test $(TEST_LOGS:.log=.xml)

xllmnrd.8: $(srcdir)/xllmnrd.8.in Makefile
	@rm -f $@-t $@
	sed -e 's,[@]PACKAGE_NAME[@],$(PACKAGE_NAME),g' \
	  -e 's,[@]PACKAGE_VERSION[@],$(PACKAGE_VERSION),g' \
	  -e 's,[@]PACKAGE_STRING[@],$(PACKAGE_STRING),g' \
	  < $(srcdir)/xllmnrd.8.in > $@-t
	mv -f $@-t $@

cppunit.test:
	touch $@
