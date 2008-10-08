/* nss_ldb private header file */

#define NSS_LDB_PATH "/var/lib/sss/db/sssd.ldb"

#define NSS_USER_BASE "cn=users,cn=local"

#define NSS_PWNAM_FILTER "(&(objectclass=user)(uid=%s))"
#define NSS_PWUID_FILTER "(&(objectclass=user)(uidNumber=%llu))"
#define NSS_PWENT_FILTER "(objectclass=user)"

#define NSS_PW_ATTRS {NSS_PW_NAME, NSS_PW_UIDNUM, NSS_PW_GIDNUM, \
                      NSS_PW_FULLNAME, NSS_PW_HOMEDIR, NSS_PW_SHELL, \
                      NULL}

