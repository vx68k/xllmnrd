# -*-Makefile-*- for maintenance jobs
# Copyright (C) 2013  Kaz Nishimura

# Copying and distribution of this file, with or without modification, are
# permitted in any medium without royalty provided the copyright notice and
# this notice are preserved.  This file is offered as-is, without any
# warranty.

# This file SHOULD NOT be contained in the source package.

builddir = build
prefix = /tmp/xllmnrd

AUTORECONF = autoreconf
TAR = tar

CFLAGS = -g -O2 -Wall -Wextra

build: clean check dist
	hg status || true

all check clean: $(builddir)/Makefile
	cd $(builddir) && $(MAKE) CFLAGS='$(CFLAGS)' $@

dist distcheck: $(builddir)/Makefile update-ChangeLog
	rm -f $(builddir)/xllmnrd-*.*
	cd $(builddir) && $(MAKE) CFLAGS='$(CFLAGS)' $@

install: $(builddir)/Makefile
	cd $(builddir) && \
	  $(MAKE) CFLAGS='$(CFLAGS)' DESTDIR=$$(pwd)/root $@

$(builddir)/Makefile: stamp-configure build.makefile
	test -d $(builddir) || mkdir $(builddir)
	srcdir=$$(pwd); \
	cd $(builddir) && $$srcdir/configure --prefix=$(prefix)

update-ChangeLog:
	@rm -f ChangeLog-t
	hg log -C --style=changelog \
	  -r "sort(::. and not merge(), -date)" > ChangeLog-t
	if test -s ChangeLog-t && ! cmp -s ChangeLog-t ChangeLog; then \
	  mv -f ChangeLog-t ChangeLog; \
	else; \
	  rm -f ChangeLog-t; \
	fi

configure: stamp-configure
stamp-configure: configure.ac
	@rm -f $@
	$(AUTORECONF) --install
	touch $@

.PHONY: build all check clean dist distcheck install image
