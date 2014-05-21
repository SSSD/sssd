AC_SUBST(NDR_NBT_CFLAGS)
AC_SUBST(NDR_NBT_LIBS)
AC_SUBST(SMBCLIENT_CFLAGS)
AC_SUBST(SMBCLIENT_LIBS)

if test x"$with_samba" = xyes; then
    PKG_CHECK_MODULES(NDR_NBT, ndr_nbt, ,
        AC_MSG_ERROR([[Please install Samba 4 development libraries.
Samba 4 libraries are necessary for building ad and ipa provider.
If you do not want to build these providers it is possible to build SSSD
without them. In this case, you will need to execute configure script
with argument --without-samba
    ]]))

    PKG_CHECK_MODULES(SMBCLIENT, smbclient, ,
        AC_MSG_ERROR([[Please install libsmbclient development libraries.
libsmbclient libraries are necessary for building ad and ipa provider.
If you do not want to build these providers it is possible to build SSSD
without them. In this case, you will need to execute configure script
with argument --without-samba
    ]]))

    PKG_CHECK_MODULES(INI_CONFIG, ini_config >= 1.1.0, ,
        AC_MSG_ERROR([[Please install libini_config development libraries.
libini_config libraries are necessary for building ipa provider, as well
as for building gpo-based access control in ad provider.
If you do not want to build these providers it is possible to build SSSD
without them. In this case, you will need to execute configure script
with argument --without-samba
    ]]))
fi
