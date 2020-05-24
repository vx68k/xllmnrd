## Process this file with automake to produce Makefile.in.

ACLOCAL_AMFLAGS = -Im4

EXTRA_DIST = README.md m4/gnulib-cache.m4

SUBDIRS = libgnu libxllmnrd src test lsb po

dist-hook: $(distdir)/SHA256SUMS
	if test -n "$$GPG_USERNAME"; then \
	    gpg -ba -u "$$GPG_USERNAME" $(distdir)/SHA256SUMS; \
	fi

$(distdir)/SHA256SUMS:
	cd $(distdir) && \
	find . -type f ! -name \*SUMS -exec sha256sum {} \; > SHA256SUMS
