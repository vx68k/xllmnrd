## Process this file with automake to produce a Makefile.in.

SUBDIRS = src test

dist-hook:
	@rm -f SHA1SUM-t $(distdir)/SHA1SUM
	(cd $(distdir) && find . -type f -print | sort | xargs sha1sum) > SHA1SUM-t
	mv SHA1SUM-t $(distdir)/SHA1SUM
	@if test -x pgpsign; then \
	  ./pgpsign $(distdir)/SHA1SUM; \
	fi
