# Process this file with autoconf to produce a configure script.
AC_PREREQ([2.67])
AC_INIT([xllmnrd], [1.0.1], [https://bitbucket.org/kazssym/xllmnrd/issues],,
[http://www.vx68k.org/xllmnrd])
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([no-define])
AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION([0.18.1])

# Define the unique package revision if 'config.revision' exists.
if test -f $srcdir/config.revision; then
  PACKAGE_REVISION=
  . $srcdir/config.revision
  AC_DEFINE_UNQUOTED([PACKAGE_REVISION], ["$PACKAGE_REVISION"],
  [Define to the unique revision of this package.])dnl
fi

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_CXX

# Checks for libraries.
AC_SEARCH_LIBS([pthread_create], [pthread])

# Checks for header files.
AC_HEADER_STDBOOL
AC_CHECK_HEADERS([arpa/inet.h linux/rtnetlink.h netinet/in.h net/if.h \
sysexits.h syslog.h sys/socket.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_C_RESTRICT
AC_TYPE_SSIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([basename gethostname socket strchrnul])

AM_PATH_CPPUNIT([1.12.1])
AC_CONFIG_FILES([Makefile src/Makefile test/Makefile po/Makefile.in])
AC_OUTPUT
