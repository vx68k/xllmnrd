# Process this file with autoconf to produce a configure script.
AC_PREREQ([2.69])
AC_INIT([Xenium LLMNR Responder], [5-alpha.1],
[https://bitbucket.org/kazssym/xllmnrd/issues/new], [xllmnrd],
[https://www.vx68k.org/xllmnrd])
AC_CONFIG_SRCDIR([xllmnrd/responder.cpp])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIRS([m4])
AM_INIT_AUTOMAKE([foreign no-define tar-ustar])
# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_DEFINE([_POSIX_C_SOURCE], [200809L],
[Define to 200809L to make the symbols required by POSIX.1-2008 visible.])dnl
gl_EARLY
# Checks for libraries.
AC_SEARCH_LIBS([pthread_join], [pthread])
AC_SEARCH_LIBS([atomic_flag_test_and_set], [atomic])
# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h net/if.h syslog.h sys/socket.h])
AC_CHECK_HEADERS([linux/rtnetlink.h])
# Checks for typedefs, structures, and compiler characteristics.
dnl 'AC_C_INLINE' was omitted as 'inline' is now standard in C99 and C++.
dnl Note: on the other hand, 'restrict' is not standard in C++ yet.
AC_C_RESTRICT
AC_TYPE_SSIZE_T
# Checks for library functions.
dnl 'AC_FUNC_MALLOC' and 'AC_FUNC_REALLOC' were omitted as only the standard
dnl behavior is used.
AC_CHECK_FUNCS([daemon gethostname])
gl_INIT
AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION([0.19.3])
PKG_CHECK_MODULES([CPPUNIT], [cppunit],, [no_cppunit=yes])
AM_CONDITIONAL([CPPUNIT], [test "$no_cppunit" != yes])
# Configuration actions.
AC_CONFIG_FILES([Makefile xllmnrd/Makefile libxllmnrd/Makefile libgnu/Makefile
test/Makefile po/Makefile.in])
AC_CONFIG_HEADERS([config.h])
AC_OUTPUT
