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

    PKG_CHECK_MODULES(SAMBA_UTIL, samba-util, ,
        AC_MSG_ERROR([[Please install libsamba-util development libraries.
libsamba-util libraries are necessary for building ad and ipa provider.
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
        CFLAGS="$CFLAGS $SMBCLIENT_CFLAGS $NDR_NBT_CFLAGS $NDR_KRB5PAC_CFLAGS"
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

    samba_major_version=`printf '#include <samba/version.h>\nSAMBA_VERSION_MAJOR' | $CPP $SMBCLIENT_CFLAGS -P -`
    samba_minor_version=`printf '#include <samba/version.h>\nSAMBA_VERSION_MINOR' | $CPP $SMBCLIENT_CFLAGS -P -`
    samba_release_version=`printf '#include <samba/version.h>\nSAMBA_VERSION_RELEASE' | $CPP $SMBCLIENT_CFLAGS -P -`
    AC_MSG_NOTICE([Samba version: $samba_major_version $samba_minor_version $samba_release_version])
    if ([[ $samba_major_version -gt 4 ]]) ||
       ([[ $samba_major_version -eq 4 ]] && [[ $samba_minor_version -ge 8 ]]) ||
       ([[ $samba_major_version -eq 4 ]] && [[ $samba_minor_version -eq 7 ]] && [[ $samba_release_version -ge 4 ]]); then
        AC_DEFINE_UNQUOTED(SMB_IDMAP_DOMAIN_HAS_DOM_SID, 1,
                           [Samba's struct idmap_domain has dom_sid member])
        AC_MSG_NOTICE([Samba's struct idmap_domain has dom_sid member])
    else
        AC_MSG_NOTICE([Samba's struct idmap_domain does not have dom_sid member])
    fi

    if ([[ $samba_major_version -gt 4 ]]) ||
       ([[ $samba_major_version -eq 4 ]] && [[ $samba_minor_version -ge 12 ]]); then
        AC_DEFINE_UNQUOTED(SMB_HAS_NEW_NDR_PULL_STEAL_SWITCH, 1,
                           [Samba's new push/pull switch functions])
        AC_MSG_NOTICE([Samba has support for new ndr_push_steal_switch_value and ndr_pull_steal_switch_value functions])
    else
        AC_MSG_NOTICE([Samba supports old ndr_pull_steal_switch_value and ndr_pull_steal_switch_value functions])
    fi
fi

SAVE_CFLAGS=$CFLAGS
CFLAGS="$CFLAGS $SMBCLIENT_CFLAGS $NDR_NBT_CFLAGS $NDR_KRB5PAC_CFLAGS"
AC_CHECK_MEMBERS([struct PAC_LOGON_INFO.resource_groups], , ,
                 [[ #include <ndr.h>
                    #include <gen_ndr/krb5pac.h>
                    #include <gen_ndr/krb5pac.h>]])
AC_CHECK_MEMBERS([struct PAC_UPN_DNS_INFO.ex], ,
                 [AC_MSG_NOTICE([union PAC_UPN_DNS_INFO_EX is not available, PAC checks will be limited])],
                 [[ #include <ndr.h>
                    #include <gen_ndr/krb5pac.h>
                    #include <gen_ndr/krb5pac.h>]])
CFLAGS=$SAVE_CFLAGS
