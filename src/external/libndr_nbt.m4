AC_SUBST(NDR_NBT_CFLAGS)
AC_SUBST(NDR_NBT_LIBS)

PKG_CHECK_MODULES(NDR_NBT, ndr_nbt, ,
                  AC_MSG_ERROR("Please install Samba 4 development libraries"))