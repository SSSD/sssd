#ifndef __TOOLS_UTIL_H__
#define __TOOLS_UTIL_H__

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

    struct sss_domain_info *domains;
};

int setup_db(struct tools_ctx **ctx);

void usage(poptContext pc, const char *error);

int parse_groups(TALLOC_CTX *mem_ctx, const char *optstr, char ***_out);

enum id_domain find_domain_for_id(struct tools_ctx *ctx,
                                  uint32_t id,
                                  struct sss_domain_info **dom_ret);

#endif  /* __TOOLS_UTIL_H__ */
