#ifndef __TOOLS_UTIL_H__
#define __TOOLS_UTIL_H__

#define UID_NOT_SET 0
#define GID_NOT_SET 0

struct tools_ctx {
    struct tevent_context *ev;
    struct confdb_ctx *confdb;
    struct sysdb_ctx *sysdb;

    struct btreemap *domains;
};

int check_user_name_unique(struct tools_ctx *ctx, const char *name);
int check_group_name_unique(struct tools_ctx *ctx, const char *name);
int setup_db(struct tools_ctx **ctx);

void usage(poptContext pc, const char *error);

int parse_groups(TALLOC_CTX *mem_ctx, const char *optstr, char ***_out);

#endif  /* __TOOLS_UTIL_H__ */
