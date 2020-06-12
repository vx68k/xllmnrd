## Process this file with automake to produce Makefile.in.

noinst_SCRIPTS = xllmnrd

EXTRA_DIST = xllmnrd.in

CLEANFILES = xllmnrd

xllmnrd: $(srcdir)/xllmnrd.in $(top_builddir)/config.status
	cd $(top_builddir) && $(SHELL) ./config.status --file=$(subdir)/$@
	chmod +x $@
