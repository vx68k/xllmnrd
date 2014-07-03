# _XX_PROG_CXX_STD11
AC_DEFUN([_XX_PROG_CXX_STD11],
[
  AC_LANG_PUSH([C++])dnl
  AC_COMPILE_IFELSE([AC_LANG_SOURCE(
[#if __cplusplus < 201103L
#error Not C++11
#endif
])], [$1], [$2])
  AC_LANG_POP([C++])dnl
])

# XX_PROG_CXX_STD11
# -----------------
# Check whether the C++ compiler supports ISO/IEC 14882:2011 and if not,
# try to add options to enable it.
AC_DEFUN([XX_PROG_CXX_STD11],
[
  AC_MSG_CHECKING([whether $CXX supports C++11])
  _XX_PROG_CXX_STD11([xx_cv_cxx_std11=yes], [xx_cv_cxx_std11=no])
  AC_MSG_RESULT([$xx_cv_cxx_std11])
  if test "$xx_cv_cxx_std11" = no; then
    xx_save_CXX=$CXX
    CXX="$CXX -std=gnu++11"
    AC_MSG_CHECKING([whether $CXX supports C++11])
    _XX_PROG_CXX_STD11([xx_cv_cxx_std11=yes], [CXX=$xx_save_CXX])
    AC_MSG_RESULT([$xx_cv_cxx_std11])
  fi
])
