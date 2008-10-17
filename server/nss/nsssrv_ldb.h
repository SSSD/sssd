
struct nss_ldb_ctx {
    struct ldb_context *ldb;
    const char *ldb_file;

    const char *user_base;
    const char *group_base;

    const char *pwnam_filter;
    const char *pwuid_filter;
    const char *pwent_filter;

    const char *grnam_filter;
    const char *grna2_filter;
    const char *grgid_filter;
    const char *grent_filter;

    const char *initgr_filter;

    const char *pw_name;
    const char *pw_uidnum;
    const char *pw_gidnum;
    const char *pw_fullname;
    const char *pw_homedir;
    const char *pw_shell;

    const char *gr_name;
    const char *gr_gidnum;
    const char *gr_member;

    const char *initgr_attr;

    const char **pw_attrs;
    const char **grnam_attrs;
    const char **grpw_attrs;
    const char **initgr_attrs;
};

struct confdb_ctx;

typedef int (*nss_ldb_callback_t)(void *, int, struct ldb_result *);

int nss_ldb_init(TALLOC_CTX *mem_ctx,
                 struct event_context *ev,
                 struct confdb_ctx *cdb,
                 struct nss_ldb_ctx **nlctx);

int nss_ldb_getpwnam(TALLOC_CTX *mem_ctx,
                     struct event_context *ev,
                     struct nss_ldb_ctx *ctx,
                     const char *name,
                     nss_ldb_callback_t fn, void *ptr);

int nss_ldb_getpwuid(TALLOC_CTX *mem_ctx,
                     struct event_context *ev,
                     struct nss_ldb_ctx *ctx,
                     uint64_t uid,
                     nss_ldb_callback_t fn, void *ptr);

int nss_ldb_enumpwent(TALLOC_CTX *mem_ctx,
                      struct event_context *ev,
                      struct nss_ldb_ctx *ctx,
                      nss_ldb_callback_t fn, void *ptr);

int nss_ldb_getgrnam(TALLOC_CTX *mem_ctx,
                     struct event_context *ev,
                     struct nss_ldb_ctx *ctx,
                     const char *name,
                     nss_ldb_callback_t fn, void *ptr);

int nss_ldb_getgrgid(TALLOC_CTX *mem_ctx,
                     struct event_context *ev,
                     struct nss_ldb_ctx *ctx,
                     uint64_t gid,
                     nss_ldb_callback_t fn, void *ptr);

int nss_ldb_enumgrent(TALLOC_CTX *mem_ctx,
                      struct event_context *ev,
                      struct nss_ldb_ctx *ctx,
                      nss_ldb_callback_t fn, void *ptr);

int nss_ldb_initgroups(TALLOC_CTX *mem_ctx,
                       struct event_context *ev,
                       struct nss_ldb_ctx *ctx,
                       const char *name,
                       nss_ldb_callback_t fn, void *ptr);

