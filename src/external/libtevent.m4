AC_SUBST(TEVENT_CFLAGS)
AC_SUBST(TEVENT_LIBS)

PKG_CHECK_MODULES([TEVENT], [tevent], [found_tevent=yes], [found_tevent=no])

SSS_AC_EXPAND_LIB_DIR()
AS_IF([test x"$found_tevent" != xyes],
    [AC_CHECK_HEADER([tevent.h],
        [AC_CHECK_LIB([tevent],
                      [tevent_context_init],
                      [TEVENT_LIBS="-L$sss_extra_libdir -ltevent -ltalloc"],
                      [AC_MSG_ERROR([libtevent missing tevent_context_init])],
                      [-L$sss_extra_libdir -ltalloc])],
        [AC_MSG_ERROR([tevent header files are not installed])])]
)

SAVE_CFLAGS=$CFLAGS
SAVE_LIBS=$LIBS
CFLAGS="$CFLAGS $TEVENT_CFLAGS"
LIBS="$LIBS $TEVENT_LIBS"
build_chain_id=yes
AC_CHECK_FUNCS([tevent_set_trace_fd_callback \
                tevent_set_trace_signal_callback \
                tevent_set_trace_timer_callback \
                tevent_set_trace_immediate_callback \
                tevent_fd_set_tag \
                tevent_fd_get_tag \
                tevent_signal_set_tag \
                tevent_signal_get_tag \
                tevent_timer_set_tag \
                tevent_timer_get_tag \
                tevent_immediate_set_tag \
                tevent_immediate_get_tag],
               [],
               [build_chain_id=no])
CFLAGS=$SAVE_CFLAGS
LIBS=$SAVE_LIBS

if test x$build_chain_id = xyes
then
    AC_DEFINE(BUILD_CHAIN_ID, 1, [Build chain id])
else
    AC_MSG_NOTICE([Chain id support is disabled due to missing dependencies in tevent])
fi
