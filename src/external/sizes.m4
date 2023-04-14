# Solaris needs HAVE_LONG_LONG defined
AC_CHECK_TYPES(long long)

AC_CHECK_SIZEOF(int)
AC_CHECK_SIZEOF(char)
AC_CHECK_SIZEOF(short)
AC_CHECK_SIZEOF(long)
AC_CHECK_SIZEOF(long long)
AC_CHECK_SIZEOF(uid_t)
AC_CHECK_SIZEOF(gid_t)
AC_CHECK_SIZEOF(id_t)
AC_CHECK_SIZEOF(time_t)

if test $ac_cv_sizeof_long_long -lt 8 ; then
AC_MSG_ERROR([SSSD requires long long of 64-bits])
fi

AC_CHECK_TYPE(uint_t, unsigned int)
AC_CHECK_TYPE(int8_t, char)
AC_CHECK_TYPE(uint8_t, unsigned char)
AC_CHECK_TYPE(int16_t, short)
AC_CHECK_TYPE(uint16_t, unsigned short)

if test $ac_cv_sizeof_int -eq 4 ; then
AC_CHECK_TYPE(int32_t, int)
AC_CHECK_TYPE(uint32_t, unsigned int)
elif test $ac_cv_size_long -eq 4 ; then
AC_CHECK_TYPE(int32_t, long)
AC_CHECK_TYPE(uint32_t, unsigned long)
else
AC_MSG_ERROR([LIBREPLACE no 32-bit type found])
fi

AC_CHECK_TYPE(int64_t, long long)
AC_CHECK_TYPE(uint64_t, unsigned long long)

AC_CHECK_TYPE(size_t, unsigned int)
AC_CHECK_TYPE(ssize_t, int)

AC_CHECK_SIZEOF(off_t)
AC_CHECK_SIZEOF(size_t)
AC_CHECK_SIZEOF(ssize_t)


AC_CHECK_TYPES([intptr_t],
               [],
               [AC_DEFINE_UNQUOTED([intptr_t], [long long],
                                   [Define to `long long'
                                    if <stdint.h> does not define.])])
AC_CHECK_TYPE(uintptr_t, unsigned long long)
AC_CHECK_TYPE(ptrdiff_t, unsigned long long)
