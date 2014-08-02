## Process this file with automake to produce a Makefile.in.

AUTOMAKE_OPTIONS = parallel-tests
AM_CPPFLAGS = -I$(top_builddir)/src -I$(top_srcdir)/src
AM_CXXFLAGS = $(CPPUNIT_CFLAGS)

check_PROGRAMS = runtest
check_DATA = unit.test
CLEANFILES = unit.test $(TEST_LOGS:.log=.xml)

TESTS = unit.test

TEST_LOG_COMPILER = ./runtest
AM_TEST_LOG_FLAGS = -x $(@:.log=.xml)

runtest_LDADD = $(top_builddir)/src/libxllmnrd.a $(CPPUNIT_LIBS) $(LDADD)
runtest_SOURCES = testmain.cpp testifaddr.cpp

unit.test:
	touch $@
