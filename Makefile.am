## Process this file with automake to produce a Makefile.in.

ACLOCAL_AMFLAGS = -Im4

EXTRA_DIST = README.md m4/gnulib-cache.m4

SUBDIRS = libgnu libxllmnrd src lsb po

dist-hook:
	revision=`cd $(srcdir) && hg identify -i 2> /dev/null`; \
	if test -n "$$revision"; then \
	  echo "PACKAGE_REVISION='$$revision'" > $(distdir)/config.revision; \
	fi
	@rm -f SHASUM-dist
	(cd $(distdir) && find . -type f -print | sort | xargs shasum) \
	  > SHASUM-dist
	mv -f SHASUM-dist $(distdir)/SHASUM
	@if test -f $(srcdir)/pgpsign; then \
	  $(SHELL) $(srcdir)/pgpsign $(distdir)/SHASUM; \
	fi
