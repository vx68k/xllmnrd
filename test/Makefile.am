## Process this file with automake to produce a Makefile.in.

AM_CPPFLAGS = -DTEST -I$(top_srcdir)/libxllmnrd -I$(top_builddir)/libxllmnrd
AM_CXXFLAGS = $(CPPUNIT_CFLAGS)

TEST_EXTENSIONS =
TESTS =
CLEANFILES =

if CPPUNIT
check_PROGRAMS = test_ifaddr.exec
check_SCRIPTS = run-test
EXEC_TEST_LOG_COMPILER = ./run-test

TEST_EXTENSIONS += .exec
TESTS += $(check_PROGRAMS)
CLEANFILES += $(check_SCRIPTS) test-reports/*
endif

noinst_HEADERS = xmlreport.h

test_ifaddr_exec_SOURCES = main.cpp xmlreport.cpp test_ifaddr.cpp
test_ifaddr_exec_LDADD = $(top_builddir)/libxllmnrd/libxllmnrd.a \
$(CPPUNIT_LIBS)

run-test: $(srcdir)/run-test.in Makefile
	cat $(srcdir)/run-test.in > $@
	chmod +x $@
