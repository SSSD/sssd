/* nss_ldb private header file */

#define NSS_LDB_CONF_SECTION "config/services/nss"

#define NSS_DEF_LDB_FILE "sssd.ldb"

#define NSS_DEF_BASE "dc=sssd"
#define NSS_TMPL_USER_BASE "cn=users,cn=%s,dc=sssd"
#define NSS_TMPL_GROUP_BASE "cn=groups,cn=%s,dc=sssd"

#define NSS_PWNAM_FILTER "(&(objectclass=user)(uid=%s))"
#define NSS_PWUID_FILTER "(&(objectclass=user)(uidNumber=%llu))"
#define NSS_PWENT_FILTER "(objectclass=user)"

#define NSS_GRNAM_FILTER "(&(objectclass=group)(cn=%s))"
#define NSS_GRNA2_FILTER "(&(objectclass=user)(memberof=%s))"
#define NSS_GRGID_FILTER "(&(objectclass=group)(gidNumber=%llu))"
#define NSS_GRENT_FILTER "(objectclass=group)"

#define NSS_INITGR_FILTER "(&(objectclass=group)(gidNumber=*))"

#define NSS_PW_NAME "uid"
#define NSS_PW_PWD "userPassword"
#define NSS_PW_UIDNUM "uidNumber"
#define NSS_PW_GIDNUM "gidNumber"
#define NSS_PW_FULLNAME "fullName"
#define NSS_PW_HOMEDIR "homeDirectory"
#define NSS_PW_SHELL "loginShell"

#define NSS_GR_NAME "cn"
#define NSS_GR_GIDNUM "gidNumber"
#define NSS_GR_MEMBER "member"

#define NSS_LAST_UPDATE "lastUpdate"

#define NSS_PW_ATTRS {NSS_PW_NAME, NSS_PW_UIDNUM, \
                      NSS_PW_GIDNUM, NSS_PW_FULLNAME, \
                      NSS_PW_HOMEDIR, NSS_PW_SHELL, \
                      NSS_LAST_UPDATE, NULL}
#define NSS_GRNAM_ATTRS {NSS_GR_NAME, NSS_GR_GIDNUM, NSS_LAST_UPDATE, NULL}
#define NSS_GRPW_ATTRS {NSS_PW_NAME, NSS_LAST_UPDATE, NULL}

#define NSS_INITGR_ATTR "memberof"
#define NSS_INITGR_ATTRS {NSS_GR_GIDNUM, NSS_LAST_UPDATE, NULL}

