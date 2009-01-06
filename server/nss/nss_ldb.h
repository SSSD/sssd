/* nss_ldb private header file */

#define NSS_LDB_CONF_SECTION "config/services/nss"

#define NSS_DEF_LDB_FILE "sssd.ldb"

#define NSS_DEF_USER_BASE "cn=users,cn=local"
#define NSS_DEF_GROUP_BASE "cn=groups,cn=local"

#define NSS_DEF_PWNAM_FILTER "(&(objectclass=user)(uid=%s))"
#define NSS_DEF_PWUID_FILTER "(&(objectclass=user)(uidNumber=%llu))"
#define NSS_DEF_PWENT_FILTER "(objectclass=user)"

#define NSS_DEF_GRNAM_FILTER "(&(objectclass=group)(cn=%s))"
#define NSS_DEF_GRNA2_FILTER "(&(objectclass=user)(memberof=%s))"
#define NSS_DEF_GRGID_FILTER "(&(objectclass=group)(gidNumber=%llu))"
#define NSS_DEF_GRENT_FILTER "(objectclass=group)"

#define NSS_DEF_INITGR_FILTER "(&(objectclass=group)(gidNumber=*))"

#define NSS_DEF_PW_NAME "uid"
#define NSS_DEF_PW_UIDNUM "uidNumber"
#define NSS_DEF_PW_GIDNUM "gidNumber"
#define NSS_DEF_PW_FULLNAME "fullName"
#define NSS_DEF_PW_HOMEDIR "homeDirectory"
#define NSS_DEF_PW_SHELL "loginShell"

#define NSS_DEF_GR_NAME "cn"
#define NSS_DEF_GR_GIDNUM "gidNumber"
#define NSS_DEF_GR_MEMBER "member"

#define NSS_DEF_PW_ATTRS {NSS_DEF_PW_NAME, NSS_DEF_PW_UIDNUM, \
                          NSS_DEF_PW_GIDNUM, NSS_DEF_PW_FULLNAME, \
                          NSS_DEF_PW_HOMEDIR, NSS_DEF_PW_SHELL, \
                          NULL}
#define NSS_DEF_GRNAM_ATTRS {NSS_DEF_GR_NAME, NSS_DEF_GR_GIDNUM, NULL}
#define NSS_DEF_GRPW_ATTRS {NSS_DEF_PW_NAME, NULL}

#define NSS_DEF_INITGR_ATTR "memberof"
#define NSS_DEF_INITGR_ATTRS {NSS_DEF_GR_GIDNUM, NULL}

