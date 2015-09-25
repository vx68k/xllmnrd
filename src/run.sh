#!/bin/sh
# run.sh - simple test runner for binary tests
# Copyright (C) 2015 Nishimura Software Studio
#
# Copying and distribution of this file, with or without modification, are
# permitted in any medium without royalty provided the copyright notice and
# this notice are preserved.  This file is offered as-is, without any warranty.

PATH=.:$PATH
exec "$@"
