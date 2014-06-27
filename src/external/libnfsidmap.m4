AC_SUBST(NFSIDMAP_OBJ)
AC_SUBST(NFSIDMAP_CFLAGS)
AC_SUBST(NFSIDMAP_LIBS)

PKG_CHECK_MODULES([NFSIDMAP], [libnfsidmap], [found_nfsidmap=yes],
		  [found_nfsidmap=no])

SSS_AC_EXPAND_LIB_DIR()
AS_IF([test x"$with_nfs" = xyes -a x"$found_nfsidmap" != xyes],
    [AC_CHECK_HEADER([nfsidmap.h],
        [AC_CHECK_LIB([nfsidmap],
                      [nfs4_init_name_mapping],
                      [NFSIDMAP_LIBS="-L$sss_extra_libdir -lnfsidmap"],
                      [AC_MSG_ERROR([libnfsidmap missing nfs4_init_name_mapping])],
                      [-L$sss_extra_libdir])],
        [AC_MSG_ERROR([libnfsidmap header files are not installed])])]
)
