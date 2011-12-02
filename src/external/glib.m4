PKG_CHECK_MODULES([GLIB2],[glib-2.0])

if test x$has_glib2 != xno; then
    SAFE_LIBS="$LIBS"
    LIBS="$GLIB2_LIBS"

    AC_CHECK_FUNC([g_utf8_validate],
                  AC_DEFINE([HAVE_G_UTF8_VALIDATE], [1],
                            [Define if g_utf8_validate exists]))
    LIBS="$SAFE_LIBS"
fi