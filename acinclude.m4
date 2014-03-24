# _XX_PROG_CXX_STD11
AC_DEFUN([_XX_PROG_CXX_STD11],
[AC_REQUIRE([AC_PROG_CXXCPP])dnl
AC_LANG_PUSH([C++])dnl
AC_EGREP_CPP([yes]
[#if __cplusplus >= 201103L
  yes
#endif
], [$1], [$2])
AC_LANG_POP([C++])dnl
])

# XX_PROG_CXX_STD11
# -----------------
# Check whether the C++ compiler supports ISO/IEC 14882:2011 and if not,
# try to add options to enable it.
AC_DEFUN([XX_PROG_CXX_STD11],
[AC_MSG_CHECKING([whether $CXXCPP supports C++11])
_XX_PROG_CXX_STD11([xx_cv_cxx_std11=yes], [xx_cv_cxx_std11=no])
AC_MSG_RESULT([$xx_cv_cxx_std11])
if test "$xx_cv_cxx_std11" = no; then
  xx_save_CXX=$CXX
  xx_save_CXXCPP=$CXXCPP
  CXX="$CXX -std=gnu++11"
  CXXCPP="$CXXCPP -std=gnu++11"
  AC_MSG_CHECKING([whether $CXXCPP supports C++11])
  _XX_PROG_CXX_STD11([xx_cv_cxx_std11=yes],
    [CXX=$xx_save_CXX
    CXXCPP=$xx_save_CXXCPP])
  AC_MSG_RESULT([$xx_cv_cxx_std11])
fi
])
