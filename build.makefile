# -*-Makefile-*- for maintenance jobs
# Copyright (C) 2013  Kaz Nishimura

# Copying and distribution of this file, with or without modification, are
# permitted in any medium without royalty provided the copyright notice and
# this notice are preserved.  This file is offered as-is, without any
# warranty.

# This file SHOULD NOT be contained in the source package.

builddir = build

AUTORECONF = autoreconf
CC = gcc -std=gnu99
CXX = g++ -std=gnu++11

CFLAGS = -g -O2 -Wall -Wextra

export CC CXX

all: $(builddir)/Makefile
	cd $(builddir) && $(MAKE) CFLAGS='$(CFLAGS)' check
	@rm -f $(builddir)/xllmnrd-*.tar.*
	cd $(builddir) && $(MAKE) distcheck

$(builddir)/Makefile: configure
	test -d $(builddir) || mkdir $(builddir)
	srcdir=$$(pwd); \
	cd $(builddir) && $$srcdir/configure

configure: stamp-configure
stamp-configure: configure.ac
	@rm -f $@
	$(AUTORECONF) --install
	touch $@
