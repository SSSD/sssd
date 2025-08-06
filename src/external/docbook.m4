dnl Checks for tools needed to generate manual pages
AC_DEFUN([CHECK_XML_TOOLS],
[
  AC_PATH_PROG([XSLTPROC], [xsltproc])
  if test ! -x "$XSLTPROC"; then
    AC_MSG_ERROR([Could not find xsltproc])
  fi

  AC_PATH_PROG([XMLLINT], [xmllint])
  if test ! -x "$XMLLINT"; then
    AC_MSG_ERROR([Could not find xmllint])
  fi
])

dnl Usage:
dnl   CHECK_STYLESHEET_URI(FILE, URI, [FRIENDLY-NAME], [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
dnl Checks if the XML catalog given by FILE exists and
dnl if a particular URI appears in the XML catalog
AC_DEFUN([CHECK_STYLESHEET],
[
  AS_IF([test -f "$1"], [], [AC_MSG_ERROR([could not find XML catalog])])

  AC_MSG_CHECKING([for ifelse([$3],,[$2],[$3]) in XML catalog])
  if AC_RUN_LOG([$XSLTPROC --catalogs --nonet --noout "$2" >&2]); then
    AC_MSG_RESULT([yes])
    m4_ifval([$4], [$4], [:])
  else
    AC_MSG_RESULT([no])
    m4_ifval([$5], [$5], [:])
  fi
])
