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

  AC_PATH_PROG([XMLCATALOG], [xmlcatalog])
  if test ! -x "$XMLCATALOG"; then
    AC_MSG_ERROR([Could not find xmlcatalog])
  fi
])

dnl Usage:
dnl   CHECK_STYLESHEET_URI(FILE, URI, [FRIENDLY-NAME])
dnl Checks if the XML catalog given by FILE exists and
dnl if a particular URI appears in the XML catalog
AC_DEFUN([CHECK_STYLESHEET],
[
  AC_CHECK_FILE($1, [], [AC_MSG_ERROR([could not find XML catalog])])

  AC_MSG_CHECKING([for ifelse([$3],,[$2],[$3]) in XML catalog])
  if AC_RUN_LOG([$XMLCATALOG --noout "$1" "$2" >&2]); then
    AC_MSG_RESULT([yes])
  else
    AC_MSG_ERROR([could not find ifelse([$3],,[$2],[$3]) in XML catalog])
  fi
])

