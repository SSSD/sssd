/* nss_ldb private header file */

#define NSS_LDB_PATH "/var/lib/sss/db/sssd.ldb"

#define NSS_USER_BASE "cn=users,cn=local"
#define NSS_GROUP_BASE "cn=groups,cn=local"

#define NSS_PWNAM_FILTER "(&(objectclass=user)(uid=%s))"
#define NSS_PWUID_FILTER "(&(objectclass=user)(uidNumber=%llu))"
#define NSS_PWENT_FILTER "(objectclass=user)"

#define NSS_GRNAM_FILTER "(&(objectclass=group)(cn=%s))"
#define NSS_GRNA2_FILTER "(&(objectclass=user)(memberof=%s))"
#define NSS_GRGID_FILTER "(&(objectclass=group)(gidNumber=%llu))"
#define NSS_GRENT_FILTER "(objectclass=group)"

#define NSS_INITGR_FILTER "(&(objectclass=group)(gidNumber=*))"

#define NSS_PW_ATTRS {NSS_PW_NAME, NSS_PW_UIDNUM, NSS_PW_GIDNUM, \
                      NSS_PW_FULLNAME, NSS_PW_HOMEDIR, NSS_PW_SHELL, \
                      NULL}
#define NSS_GRNAM_ATTRS {NSS_GR_NAME, NSS_GR_GIDNUM, NULL}
#define NSS_GRPW_ATTRS {NSS_PW_NAME, NULL}

#define NSS_INITGR_SEARCH_ATTR "memberof"
#define NSS_INITGR_ATTRS {NSS_GR_GIDNUM, NULL}
