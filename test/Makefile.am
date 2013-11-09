## Process this file with automake to produce a Makefile.in.

AUTOMAKE_OPTIONS = parallel-tests
AM_CPPFLAGS = -I$(top_builddir)/src -I$(top_srcdir)/src
AM_CXXFLAGS = $(CPPUNIT_CFLAGS)

check_PROGRAMS = runtest
check_DATA = unit.test
CLEANFILES = unit.test

TESTS = unit.test
MOSTLYCLEANFILES = $(TEST_LOGS:.log=.xml)

TEST_LOG_COMPILER = ./runtest
AM_TEST_LOG_FLAGS = -x $(@:.log=.xml)

runtest_LDADD = $(LDADD) $(CPPUNIT_LIBS)
runtest_SOURCES = testmain.cpp testifaddr.cpp $(top_srcdir)/src/ifaddr.c

unit.test:
	touch $@
