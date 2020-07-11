## Process this file with automake to produce Makefile.in.

AM_CPPFLAGS = -D_LIBXLLMNRD \
-I$(top_builddir)/libgnu -I$(top_srcdir)/libgnu

noinst_LIBRARIES = libxllmnrd.a
noinst_HEADERS = \
interface.h \
rtnetlink.h \
posix.h \
socket_utility.h \
llmnr.h \
ascii.h

libxllmnrd_a_SOURCES = \
interface.cpp \
rtnetlink.cpp \
posix.cpp
