
#define CONFDB_BASE_LDIF \
     "dn: @ATTRIBUTES\n" \
     "cn: CASE_INSENSITIVE\n" \
     "dc: CASE_INSENSITIVE\n" \
     "dn: CASE_INSENSITIVE\n" \
     "name: CASE_INSENSITIVE\n" \
     "objectclass: CASE_INSENSITIVE\n" \
     "\n" \
     "dn: @INDEXLIST\n" \
     "@IDXATTR: cn\n" \
     "\n" \
     "dn: @MODULES\n" \
     "@LIST: server_sort\n" \
     "\n" \
     "dn: cn=config\n" \
     "cn: config\n" \
     "version: 0.1\n" \
     "description: base object\n" \
     "\n" \
     "dn: cn=services,cn=config\n" \
     "cn: services\n" \
     "description: Local service configuration\n" \
     "activeServices: dp\n" \
     "activeServices: nss\n" \
     "activeServices: pam\n" \
     "\n" \
     "dn: cn=monitor,cn=services,cn=config\n" \
     "cn: monitor\n" \
     "description: Monitor Configuration\n" \
     "\n" \
     "dn: cn=dp,cn=services,cn=config\n" \
     "cn: dp\n" \
     "description: Data Provider Configuration\n" \
     "\n" \
     "dn: cn=nss,cn=services,cn=config\n" \
     "cn: nss\n" \
     "description: NSS Responder Configuration\n" \
     "\n" \
     "dn: cn=pam,cn=services,cn=config\n" \
     "cn: pam\n" \
     "description: PAM Responder Configuration\n" \
     "\n" \
     "dn: cn=domains,cn=config\n" \
     "cn: domains\n" \
     "description: Domains served by SSSD\n" \
     "domains: LOCAL\n" \
     "\n" \
     "dn: cn=LOCAL,cn=domains,cn=config\n" \
     "cn: LOCAL\n" \
     "description: LOCAL domain\n" \
     "enumerate: 3\n" \
     "magicPrivateGroups: TRUE\n" \
     "\n"
