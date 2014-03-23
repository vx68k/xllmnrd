AC_DEFUN([XX_PROG_CXX11],
[AC_REQUIRE([AC_PROG_CXXCPP])dnl
AC_LANG_PUSH([C++])dnl
AC_MSG_CHECKING([whether $CXX conforms to C++11])
AC_EGREP_CPP([yes],
[#if __cplusplus >= 201103L
  yes
#endif
], xx_cv_cxx11=yes, xx_cv_cxx11=no)
AC_MSG_RESULT([$xx_cv_cxx11])
AC_LANG_POP([C++])dnl
])