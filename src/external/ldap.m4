dnl AC_SUBST(LDAP_LIBS)
dnl
dnl AC_CHECK_HEADERS(lber.h ldap.h, , AC_MSG_ERROR("could not locate LDAP header files please install devel package"))
dnl
dnl AC_CHECK_LIB(lber, main, LDAP_LIBS="-llber $LDAP_LIBS")
dnl AC_CHECK_LIB(ldap, main, LDAP_LIBS="-lldap $LDAP_LIBS")
dnl
dnl ---------------------------------------------------------------------------
dnl - Check for Mozilla LDAP or OpenLDAP SDK
dnl ---------------------------------------------------------------------------

for p in /usr/include/openldap24 /usr/local/include; do
    if test -f "${p}/ldap.h"; then
        OPENLDAP_CFLAGS="${OPENLDAP_CFLAGS} -I${p}"
        break;
    fi
done

for p in /usr/lib64/openldap24 /usr/lib/openldap24 /usr/local/lib ; do
    if test -f "${p}/libldap.so"; then
        OPENLDAP_LIBS="${OPENLDAP_LIBS} -L${p}"
        break;
    fi
done

SAVE_CFLAGS=$CFLAGS
SAVE_LIBS=$LIBS
CFLAGS="$CFLAGS $OPENLDAP_CFLAGS"
LIBS="$LIBS $OPENLDAP_LIBS"
AC_CHECK_LIB(ldap, ldap_search, with_ldap=yes)
dnl Check for other libraries we need to link with to get the main routines.
test "$with_ldap" != "yes" && { AC_CHECK_LIB(ldap, ldap_open, [with_ldap=yes with_ldap_lber=yes], , -llber) }
test "$with_ldap" != "yes" && { AC_CHECK_LIB(ldap, ldap_open, [with_ldap=yes with_ldap_lber=yes with_ldap_krb=yes], , -llber -lkrb) }
test "$with_ldap" != "yes" && { AC_CHECK_LIB(ldap, ldap_open, [with_ldap=yes with_ldap_lber=yes with_ldap_krb=yes with_ldap_des=yes], , -llber -lkrb -ldes) }
CFLAGS=$SAVE_CFLAGS
LIBS=$SAVE_LIBS
dnl Recently, we need -lber even though the main routines are elsewhere,
dnl because otherwise we get link errors w.r.t. ber_pvt_opt_on. So just
dnl check for that (it's a variable not a fun but that doesn't seem to
dnl matter in these checks) and stick in -lber if so. Can't hurt (even to
dnl stick it in always shouldn't hurt, I don't think) ... #### Someone who
dnl #### understands LDAP needs to fix this properly.
test "$with_ldap_lber" != "yes" && { AC_CHECK_LIB(lber, ber_pvt_opt_on, with_ldap_lber=yes) }

if test "$with_ldap" = "yes"; then
  if test "$with_ldap_des" = "yes" ; then
    OPENLDAP_LIBS="${OPENLDAP_LIBS} -ldes"
  fi
  if test "$with_ldap_krb" = "yes" ; then
    OPENLDAP_LIBS="${OPENLDAP_LIBS} -lkrb"
  fi
  if test "$with_ldap_lber" = "yes" ; then
    OPENLDAP_LIBS="${OPENLDAP_LIBS} -llber"
  fi
  OPENLDAP_LIBS="${OPENLDAP_LIBS} -lldap"
else
  AC_MSG_ERROR([OpenLDAP not found])
fi

AC_SUBST(OPENLDAP_LIBS)
AC_SUBST(OPENLDAP_CFLAGS)

SAVE_CFLAGS=$CFLAGS
SAVE_LIBS=$LIBS
CFLAGS="$CFLAGS $OPENLDAP_CFLAGS"
LIBS="$LIBS $OPENLDAP_LIBS"
AC_CHECK_FUNCS([ldap_control_create ldap_init_fd \
                ldap_create_deref_control_value  \
                ldap_parse_derefresponse_control \
                ldap_derefresponse_free \
                ldap_is_ldapc_url])
AC_CHECK_MEMBERS([struct ldap_conncb.lc_arg],
                 [AC_RUN_IFELSE(
                   [AC_LANG_PROGRAM(
                     [[ #include <ldap.h> ]],
                     [[
                       struct ldap_conncb cb;
                       return ldap_set_option(NULL, LDAP_OPT_CONNECT_CB, &cb);
                     ]] )],
                   [AC_DEFINE([HAVE_LDAP_CONNCB], [1],
                     [Define if LDAP connection callbacks are available])],
                   [AC_MSG_WARN([Found broken callback implementation])],
                   [])],
                 [], [[#include <ldap.h>]])

AC_CHECK_TYPE([LDAPDerefRes],
              [],
              [AC_MSG_ERROR([The OpenLDAP version found does not contain the required type LDAPDerefRes])],
              [[#include <ldap.h>]])

CFLAGS=$SAVE_CFLAGS
LIBS=$SAVE_LIBS

AC_PATH_PROG([SLAPD], [slapd], ,
             [$PATH$PATH_SEPARATOR/usr/sbin$PATH_SEPARATOR])
AS_IF([test -n "$SLAPD"], [HAVE_SLAPD=yes], [HAVE_SLAPD=no])
AC_CHECK_PROG([HAVE_LDAPMODIFY], [ldapmodify], [yes], [no])
