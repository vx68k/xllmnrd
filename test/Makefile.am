## Process this file with automake to produce a Makefile.in.

AUTOMAKE_OPTIONS = parallel-tests
AM_CXXFLAGS = $(CPPUNIT_CFLAGS)

check_PROGRAMS = unittest

TESTS = unittest

unittest_LDADD = $(LDADD) $(CPPUNIT_LIBS)
unittest_SOURCES = testmain.cpp
