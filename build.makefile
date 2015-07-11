# -*-Makefile-*- for maintenance jobs
# Copyright (C) 2013-2015 Kaz Nishimura

# Copying and distribution of this file, with or without modification, are
# permitted in any medium without royalty provided the copyright notice and
# this notice are preserved.  This file is offered as-is, without any
# warranty.

# This file SHOULD NOT be contained in the source package.

topdir := $(if $(WORKSPACE),$(WORKSPACE),$(shell pwd))
srcdir = $(topdir)
builddir = $(topdir)/_build

TAR = tar

CFLAGS = -g -O2 -Wall -Wextra
CXXFLAGS = -g -O2 -Wall -Wextra

build: clean check dist
	hg status || true

all check dist distcheck: $(builddir)/Makefile
	cd $(builddir) && $(MAKE) CFLAGS='$(CFLAGS)' CXXFLAGS='$(CXXFLAGS)' $@

$(builddir)/Makefile: $(builddir)/config.status config.h.in force
	cd $(builddir) && ./config.status

$(builddir)/config.status: configure build.makefile
	mkdir -p $(builddir)
	cd $(builddir) && $(srcdir)/configure --no-create

configure: force
	@mkdir -p m4
	autoreconf --no-recursive

clean:
	rm -fr $(prefix)
	rm -fr $(builddir)

force:

update-ChangeLog:
	@rm -f ChangeLog-t
	hg log -C --style=changelog -X .hg\* -X README.md -X build.makefile \
	  -r "sort(::. and not merge(), -date)" | \
	sed -e 's/`\([^`]*\)`/'\''\1'\''/g' -e 's/NLS-support/NLS/g' > ChangeLog-t
	if test -s ChangeLog-t && ! cmp -s ChangeLog-t ChangeLog; then \
	  mv -f ChangeLog-t ChangeLog; \
	else \
	  rm -f ChangeLog-t; \
	fi

.PHONY: build all check dist distcheck clean force update-ChangeLog
