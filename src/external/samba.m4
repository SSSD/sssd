AC_SUBST(NDR_NBT_CFLAGS)
AC_SUBST(NDR_NBT_LIBS)
AC_SUBST(SMBCLIENT_CFLAGS)
AC_SUBST(SMBCLIENT_LIBS)
AC_SUBST(NDR_KRB5PAC_CFLAGS)
AC_SUBST(NDR_KRB5PAC_LIBS)

if test x"$with_samba" = xyes; then
    PKG_CHECK_MODULES(NDR_NBT, ndr_nbt, ,
        AC_MSG_ERROR([[Please install Samba 4 NDR NBT development libraries.
Samba 4 libraries are necessary for building ad and ipa provider.
If you do not want to build these providers it is possible to build SSSD
without them. In this case, you will need to execute configure script
with argument --without-samba
    ]]))

    PKG_CHECK_MODULES(NDR_KRB5PAC, ndr_krb5pac, ,
        AC_MSG_ERROR([[Please install Samba 4 NDR KRB5PAC development libraries.
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

    if test x"$HAVE_LIBINI_CONFIG_V1_1" != x1; then
        AC_MSG_ERROR([[Please install libini_config development libraries
v1.1.0, or newer. libini_config libraries are necessary for building ipa
provider, as well as for building gpo-based access control in ad provider. If
you do not want to build these providers it is possible to build SSSD without
them. In this case, you will need to execute configure script with argument
--without-samba
        ]])
    fi

    AC_ARG_WITH([smb-idmap-interface-version],
                [AC_HELP_STRING([--with-smb-idmap-interface-version=[5|6]],
                                [Idmap interface version of installed Samba]
                               )
                ]
               )

    if test x"$with_smb_idmap_interface_version" != x; then
        if test x"$with_smb_idmap_interface_version" = x5 -o x"$with_smb_idmap_interface_version" = x6; then
            idmap_test_result=$with_smb_idmap_interface_version
        else
            AC_MSG_ERROR([Illegal value -$with_smb_idmap_interface_version- for option --with-smb-idmap-interface-version])
        fi
    else

        AC_MSG_CHECKING([Samba's idmap plugin interface version])
        sambalibdir="`$PKG_CONFIG --variable=libdir smbclient`"/samba
        SAVE_CFLAGS=$CFLAGS
        SAVE_LIBS=$LIBS
        CFLAGS="$CFLAGS $SMBCLIENT_CFLAGS $NDR_NBT_CFLAGS $NDR_KRB5PAC_CFLAGS -I/usr/include/samba-4.0"
        LIBS="$LIBS -L${sambalibdir} -lidmap-samba4 -Wl,-rpath ${sambalibdir}"
        AC_RUN_IFELSE(
            [AC_LANG_SOURCE([
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <tevent.h>
#include <core/ntstatus.h>

struct winbindd_domain;

/* overwrite some winbind internal functions */
struct winbindd_domain *find_domain_from_name(const char *domain_name)
{
    return NULL;
}

bool get_global_winbindd_state_offline(void) {
    return false;
}

struct tevent_context *winbind_event_context(void)
{
    return NULL;
}

struct idmap_methods;

NTSTATUS smb_register_idmap(int version, const char *name, struct idmap_methods *methods);

int main(void)
{
    int v;
    NTSTATUS ret;

    /* Check the versions we know about */
    for (v = 5; v <= 6; v++) {
        ret = smb_register_idmap(v, NULL, NULL);
        if (!NT_STATUS_EQUAL(ret, NT_STATUS_OBJECT_TYPE_MISMATCH)) {
            return v;
        }
    }

    return -1;
}])],
            [AC_MSG_ERROR([idmap version test program is not expected to return 0])],
            [idmap_test_result=$?; AC_MSG_RESULT([idmap test result is: $idmap_test_result])]
        )
    fi

    CFLAGS=$SAVE_CFLAGS
    LIBS=$SAVE_LIBS

    if test $idmap_test_result -eq 5 -o $idmap_test_result -eq 6 ; then
        idmap_version=$idmap_test_result
    else
        AC_MSG_ERROR([Cannot determine Samba's idmap interface version, please use --with-smb-idmap-interface-version])
    fi
    AC_MSG_NOTICE([Samba's idmap interface version: $idmap_version])
    AC_DEFINE_UNQUOTED(SMB_IDMAP_INTERFACE_VERSION, $idmap_version,
                       [Detected version of Samba's idmap plugin interface])
fi
