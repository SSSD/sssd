
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
     "\n"

#define CONFDB_INTERNAL_LDIF \
     "dn: cn=config\n" \
     "version: 1\n" \
     "\n"
