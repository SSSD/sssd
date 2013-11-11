AC_ARG_ENABLE([cifs-idmap-plugin],
              [AS_HELP_STRING([--disable-cifs-idmap-plugin],
                              [do not build CIFS idmap plugin])],
              [build_cifs_idmap_plugin=$enableval],
              [build_cifs_idmap_plugin=yes])

AS_IF([test x$build_cifs_idmap_plugin = xyes],
      [AC_CHECK_HEADER([cifsidmap.h], [],
                       [AC_MSG_ERROR([
You must have the cifsidmap header installed to build the idmap plugin.
If you want to build sssd withoud cifsidmap plugin then specify
--disable-cifs-idmap-plugin when running configure.])])
      ])

AM_CONDITIONAL([BUILD_CIFS_IDMAP_PLUGIN],
               [test x$build_cifs_idmap_plugin = xyes])

AM_COND_IF([BUILD_CIFS_IDMAP_PLUGIN],
           [AC_DEFINE_UNQUOTED(HAVE_CIFS_IDMAP_PLUGIN, 1, [Build with cifs idmap plugin])])
