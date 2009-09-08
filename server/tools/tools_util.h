#ifndef __TOOLS_UTIL_H__
#define __TOOLS_UTIL_H__

#include "util/sssd-i18n.h"

#define UID_NOT_SET 0
#define GID_NOT_SET 0

#define APPEND_PARAM(str, param, val) do { \
    if (val) { \
        str = talloc_asprintf_append(str, param, val); \
        if (str == NULL) { \
            return ENOMEM; \
        } \
    } \
} while(0)

#define APPEND_STRING(str, val) do { \
    str = talloc_asprintf_append(str, "%s ", val); \
    if (str == NULL) { \
        return ENOMEM; \
    } \
} while(0)

#define CHECK_ROOT(val, prg_name) do { \
    val = getuid(); \
    if (val != 0) { \
        DEBUG(1, ("Running under %d, must be root\n", val)); \
        ERROR("%s must be run as root\n", prg_name); \
        val = EXIT_FAILURE; \
        goto fini; \
    } \
} while(0)

enum id_domain {
    ID_IN_LOCAL = 0,
    ID_IN_LEGACY_LOCAL,
    ID_IN_OTHER,
    ID_OUTSIDE,
    ID_ERROR
};

struct tools_ctx {
    struct tevent_context *ev;
    struct confdb_ctx *confdb;
    struct sysdb_ctx *sysdb;
    struct sss_names_ctx *snctx;

    struct sss_domain_info *domains;
};

struct ops_ctx {
    struct tools_ctx *ctx;
    struct tevent_context *ev;
    struct sss_domain_info *domain;

    char *name;
    uid_t uid;
    gid_t gid;
    char *gecos;
    char *home;
    char *shell;
    struct sysdb_attrs *attrs;

    char **addgroups;
    char **rmgroups;
    char **groups;
    int cur;

    struct sysdb_handle *handle;
    int error;
    bool done;
};

int init_sss_tools(struct tools_ctx **_ctx);

int setup_db(struct tools_ctx **ctx);

void usage(poptContext pc, const char *error);

int set_locale(void);

int get_domain(struct ops_ctx *octx,
               const char *fullname);

int id_in_range(uint32_t id,
                struct sss_domain_info *dom);

int parse_groups(TALLOC_CTX *mem_ctx,
                 const char *optstr,
                 char ***_out);

#endif  /* __TOOLS_UTIL_H__ */
