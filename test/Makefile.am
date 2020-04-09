## Process this file with automake to produce a Makefile.in.

AM_CPPFLAGS = -DTEST
AM_CXXFLAGS = $(CPPUNIT_CFLAGS)

check_SCRIPTS =

TESTS =
XFAIL_TESTS =
CLEANFILES = $(check_SCRIPTS) test-reports/*

if CPPUNIT
check_SCRIPTS += run-test
TEST_LOG_COMPILER = ./run-test
endif

run-test: $(srcdir)/run-test.in Makefile
	cat < $(srcdir)/run-test.in > $@
	chmod +x $@
