## Process this file with automake to produce a Makefile.in.

SUBDIRS = src

man_MANS = xllmnrd.8

dist-hook:
	(cd $(distdir) && find . -type f -print | sort | xargs sha1sum) >SHA1SUM-dist
	mv -f SHA1SUM-dist $(distdir)/SHA1SUM
