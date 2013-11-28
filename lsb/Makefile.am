## Process this file with automake to produce a Makefile.in.

noinst_SCRIPTS = xllmnrd

EXTRA_DIST = xllmnrd.in

CLEANFILES = xllmnrd

xllmnrd: xllmnrd.in Makefile
	@rm -f $@
	sed -e 's,[@]PACKAGE_NAME[@],$(PACKAGE_NAME),g' \
	  -e 's,[@]PACKAGE_VERSION[@],$(PACKAGE_VERSION),g' \
	  -e 's,[@]sbindir[@],$(sbindir),g' \
	  < $(srcdir)/xllmnrd.in > $@
	chmod +x $@
