## Process this file with automake to produce a Makefile.in.

ACLOCAL_AMFLAGS = -Im4

SUBDIRS = src lsb test po

dist-hook:
	revision=`cd $(srcdir) && hg identify -i 2> /dev/null`; \
	if test -n "$$revision"; then \
	  echo "PACKAGE_REVISION='$$revision'" > $(distdir)/config.revision; \
	fi
	@rm -f SHA1SUM-t
	(cd $(distdir) && find . -type f -print | sort | xargs sha1sum) > SHA1SUM-t
	mv SHA1SUM-t $(distdir)/SHA1SUM
	@if test -x pgpsign; then \
	  ./pgpsign $(distdir)/SHA1SUM; \
	fi
