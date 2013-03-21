# Process this file with autoconf to produce a configure script.
AC_PREREQ([2.67])
AC_INIT([xllmnrd], [1.0x],,, [https://bitbucket.org/kazssym/xllmnrd])
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_STDC

# Checks for libraries.
AC_SEARCH_LIBS([pthread_create], [pthread])

# Checks for header files.
AC_HEADER_STDBOOL
AC_CHECK_HEADERS([limits.h syslog.h sys/socket.h netinet/in.h arpa/inet.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_C_RESTRICT
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([atexit socket])

AC_CONFIG_FILES([Makefile src/Makefile xllmnrd.8])
AC_OUTPUT
