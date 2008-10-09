
#define NSS_PW_NAME "uid"
#define NSS_PW_UIDNUM "uidNumber"
#define NSS_PW_GIDNUM "gidNumber"
#define NSS_PW_FULLNAME "fullName"
#define NSS_PW_HOMEDIR "HomeDirectory"
#define NSS_PW_SHELL "loginShell"

typedef int (*nss_ldb_callback_t)(void *, int, struct ldb_result *);

int nss_ldb_init(TALLOC_CTX *mem_ctx,
                 struct event_context *ev,
                 struct ldb_context **ldb);

int nss_ldb_getpwnam(TALLOC_CTX *mem_ctx,
                     struct event_context *ev,
                     struct ldb_context *ldb,
                     const char *name,
                     nss_ldb_callback_t fn, void *ptr);

int nss_ldb_getpwuid(TALLOC_CTX *mem_ctx,
                     struct event_context *ev,
                     struct ldb_context *ldb,
                     uint64_t uid,
                     nss_ldb_callback_t fn, void *ptr);

int nss_ldb_enumpwent(TALLOC_CTX *mem_ctx,
                      struct event_context *ev,
                      struct ldb_context *ldb,
                      nss_ldb_callback_t fn, void *ptr);
