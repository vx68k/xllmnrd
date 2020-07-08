## Process this file with automake to produce Makefile.in.

AM_CPPFLAGS = -DTEST -I$(top_srcdir)/libxllmnrd -I$(top_builddir)/libxllmnrd
AM_CXXFLAGS = $(CPPUNIT_CFLAGS)

TEST_EXTENSIONS = .exec
TESTS =
CLEANFILES =

if CPPUNIT
check_PROGRAMS = test_rtnetlink.exec
check_SCRIPTS = run-test

EXEC_LOG_COMPILER = $(SHELL) ./run-test
TESTS += $(check_PROGRAMS)
CLEANFILES += $(check_SCRIPTS)
endif

noinst_HEADERS = xmlreport.h

test_rtnetlink_exec_LDADD = $(top_builddir)/libxllmnrd/libxllmnrd.a \
$(CPPUNIT_LIBS)
test_rtnetlink_exec_SOURCES = main.cpp xmlreport.cpp test_rtnetlink.cpp

EXTRA_DIST = run-test.in

run-test: $(srcdir)/run-test.in $(top_builddir)/config.status
	cd $(top_builddir) && $(SHELL) ./config.status --file=$(subdir)/$@
	chmod +x $@

clean-local::
	rm -rf test-reports
