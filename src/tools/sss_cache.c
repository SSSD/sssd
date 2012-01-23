/*
   SSSD

   sss_cache

   Copyright (C) Jan Zeleny <jzeleny@redhat.com>        2011

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <talloc.h>
#include <popt.h>
#include <sys/types.h>

#include "util/util.h"
#include "tools/sss_sync_ops.h"
#include "db/sysdb.h"

#define INVALIDATE_NONE 0
#define INVALIDATE_USERS 1
#define INVALIDATE_GROUPS 2
#define INVALIDATE_NETGROUPS 4

#define TYPE_USER  0
#define TYPE_GROUP 1
#define TYPE_NETGROUP 2
struct entry_type_t {
    const char *type_string;
    int (* search_fn)(TALLOC_CTX *, struct sysdb_ctx *,
               const char *, const char **, size_t *, struct ldb_message ***);
};
static struct entry_type_t entry_types[] = {
    {"user", sysdb_search_users},
    {"group", sysdb_search_groups},
    {"netgroup", sysdb_search_netgroups}
};

struct cache_tool_ctx {
    struct confdb_ctx *confdb;
    struct sss_domain_info *domains;
    struct sysdb_ctx_list *sysdb_list;

    char *user_filter;
    char *group_filter;
    char *netgroup_filter;
};

errno_t init_domains(struct cache_tool_ctx *ctx, const char *domain);
errno_t init_context(int argc, const char *argv[], struct cache_tool_ctx **tctx);
errno_t invalidate_entry(TALLOC_CTX *ctx, struct sysdb_ctx *sysdb,
                         const char *name, int entry_type);
void invalidate_entries(TALLOC_CTX *ctx, struct sysdb_ctx *sysdb,
                        int entry_type, const char *filter);

int main(int argc, const char *argv[])
{
    errno_t ret;
    struct cache_tool_ctx *tctx = NULL;
    struct sysdb_ctx *sysdb;
    int i;

    ret = init_context(argc, argv, &tctx);
    if (ret != EOK) {
        DEBUG(2, ("Error initializing context for the application\n"));
        goto done;
    }

    for (i = 0; i < tctx->sysdb_list->num_dbs; i++) {
        sysdb = tctx->sysdb_list->dbs[i];
        ret = sysdb_transaction_start(sysdb);
        if (ret != EOK) {
            DEBUG(1, ("Could not start the transaction!\n"));
            goto done;
        }

        invalidate_entries(tctx, sysdb, TYPE_USER, tctx->user_filter);
        invalidate_entries(tctx, sysdb, TYPE_GROUP, tctx->group_filter);
        invalidate_entries(tctx, sysdb, TYPE_NETGROUP, tctx->netgroup_filter);

        ret = sysdb_transaction_commit(sysdb);
        if (ret != EOK) {
            DEBUG(1, ("Could not commit the transaction!\n"));
            sysdb_transaction_cancel(sysdb);
        }
    }

done:
    if (tctx) talloc_free(tctx);
    return ret;
}


void invalidate_entries(TALLOC_CTX *ctx, struct sysdb_ctx *sysdb,
                        int entry_type, const char *filter)
{
    const char *attrs[] = {SYSDB_NAME, NULL};
    size_t msg_count;
    struct ldb_message **msgs;
    struct entry_type_t type_rec;
    errno_t ret;
    int i;
    const char *c_name;

    type_rec = entry_types[entry_type];
    if (filter) {
        ret = type_rec.search_fn(ctx, sysdb, filter, attrs,
                                 &msg_count, &msgs);
        if (ret != EOK) {
            DEBUG(3, ("Searching for %s with filter %s failed\n",
                      type_rec.type_string, filter));
            return;
        }

        for (i = 0; i < msg_count; i++) {
            c_name = ldb_msg_find_attr_as_string(msgs[i], SYSDB_NAME, NULL);
            if (c_name == NULL) {
                DEBUG(3, ("Something bad happened, can't find attribute %s",
                            SYSDB_NAME));
                ERROR("Couldn't invalidate %s", type_rec.type_string);
            } else {
                ret = invalidate_entry(ctx, sysdb, c_name, entry_type);
                if (ret != EOK) {
                    DEBUG(3, ("Couldn't invalidate %s %s", type_rec.type_string,
                              c_name));
                    ERROR("Couldn't invalidate %s %s", type_rec.type_string,
                          c_name);
                }
            }
        }
        talloc_zfree(msgs);
    }
}

errno_t invalidate_entry(TALLOC_CTX *ctx, struct sysdb_ctx *sysdb,
                         const char *name, int entry_type)
{
    struct sysdb_attrs *sys_attrs = NULL;
    errno_t ret;

    sys_attrs = sysdb_new_attrs(ctx);
    if (sys_attrs) {
        ret = sysdb_attrs_add_time_t(sys_attrs,
                SYSDB_CACHE_EXPIRE, 1);
        if (ret == EOK) {
            switch (entry_type) {
                case TYPE_USER:
                    ret = sysdb_set_user_attr(sysdb, name, sys_attrs,
                                              SYSDB_MOD_REP);
                    break;
                case TYPE_GROUP:
                    ret = sysdb_set_group_attr(sysdb, name, sys_attrs,
                                               SYSDB_MOD_REP);
                    break;
                case TYPE_NETGROUP:
                    ret = sysdb_set_netgroup_attr(sysdb, name,
                            sys_attrs, SYSDB_MOD_REP);
                    break;
                default:
                    return EINVAL;
            }
            if (ret != EOK) {
                DEBUG(3, ("Could not set entry attributes\n"));
            }
        } else {
            DEBUG(3, ("Could not add expiration time to attributes\n"));
        }
        talloc_zfree(sys_attrs);
    } else {
        DEBUG(3, ("Could not create sysdb attributes\n"));
        ret = ENOMEM;
    }
    return ret;
}

errno_t init_domains(struct cache_tool_ctx *ctx, const char *domain) {
    char *confdb_path;
    int ret;
    struct sysdb_ctx *db_ctx = NULL;

    confdb_path = talloc_asprintf(ctx, "%s/%s", DB_PATH, CONFDB_FILE);
    if (confdb_path == NULL) {
        return ENOMEM;
    }

    /* Connect to the conf db */
    ret = confdb_init(ctx, &ctx->confdb, confdb_path);
    talloc_free(confdb_path);
    if (ret != EOK) {
        DEBUG(1, ("Could not initialize connection to the confdb\n"));
        return ret;
    }

    if (domain) {
        ret = sysdb_init_domain_and_sysdb(ctx, ctx->confdb, domain, DB_PATH,
                                          &ctx->domains, &db_ctx);
        if (ret != EOK) {
            DEBUG(1, ("Could not initialize connection to the sysdb\n"));
            goto fail;
        }

        ret = sysdb_list_init(ctx, DB_PATH, db_ctx, &ctx->sysdb_list);
        if (ret != EOK) {
            DEBUG(1, ("Could not initialize the list of connections\n"));
            goto fail;
        }
    } else {
        ret = sysdb_init(ctx, ctx->confdb, NULL, false, &ctx->sysdb_list);
        if (ret != EOK) {
            DEBUG(1, ("Could not initialize connection to the sysdb\n"));
            goto fail;
        }
    }

    return EOK;
fail:
    if (ctx->confdb) talloc_zfree(ctx->confdb);
    if (ctx->domains) talloc_zfree(ctx->domains);
    if (ctx->sysdb_list) {
        talloc_zfree(ctx->sysdb_list);
    } else {
        if (db_ctx) talloc_free(db_ctx);
    }
    return ret;
}

errno_t init_context(int argc, const char *argv[], struct cache_tool_ctx **tctx)
{
    struct cache_tool_ctx *ctx = NULL;
    int idb = INVALIDATE_NONE;
    char *user = NULL;
    char *group = NULL;
    char *netgroup = NULL;
    char *domain = NULL;
    int debug = SSSDBG_DEFAULT;
    errno_t ret = EOK;

    poptContext pc = NULL;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        { "debug", '\0', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &debug,
            0, _("The debug level to run with"), NULL },
        { "user", 'u', POPT_ARG_STRING, &user, 0,
            _("Invalidate particular user"), NULL },
        { "users", 'U', POPT_ARG_NONE, NULL, 'u',
            _("Invalidate all users"), NULL },
        { "group", 'g', POPT_ARG_STRING, &group, 0,
            _("Invalidate particular group"), NULL },
        { "groups", 'G', POPT_ARG_NONE, NULL, 'g',
            _("Invalidate all groups"), NULL },
        { "netgroup", 'n', POPT_ARG_STRING, &netgroup, 0,
            _("Invalidate particular netgroup"), NULL },
        { "netgroups", 'N', POPT_ARG_NONE, NULL, 'n',
            _("Invalidate all netgroups"), NULL },
        { "domain", 'd', POPT_ARG_STRING, &domain, 0,
            _("Only invalidate entries from a particular domain"), NULL },
        POPT_TABLEEND
    };

    ret = set_locale();
    if (ret != EOK) {
        DEBUG(1, ("set_locale failed (%d): %s\n", ret, strerror(ret)));
        ERROR("Error setting the locale\n");
        goto fini;
    }

    pc = poptGetContext(NULL, argc, argv, long_options, 0);
    while ((ret = poptGetNextOpt(pc)) > 0) {
        switch (ret) {
            case 'u':
                idb |= INVALIDATE_USERS;
                break;
            case 'g':
                idb |= INVALIDATE_GROUPS;
                break;
            case 'n':
                idb |= INVALIDATE_NETGROUPS;
                break;
        }
    }
    if (ret != -1) {
        BAD_POPT_PARAMS(pc, poptStrerror(ret), ret, fini);
    }

    debug_level = debug_convert_old_level(debug);
    debug_prg_name = argv[0];
    CHECK_ROOT(ret, debug_prg_name);

    ctx = talloc_zero(NULL, struct cache_tool_ctx);
    if (ctx == NULL) {
        DEBUG(1, ("Could not allocate memory for tools context\n"));
        ret = ENOMEM;
        goto fini;
    }

    if (idb & INVALIDATE_USERS) {
        ctx->user_filter = talloc_asprintf(ctx, "(%s=*)", SYSDB_NAME);
    } else if (user) {
        ctx->user_filter = talloc_asprintf(ctx, "(%s=%s)", SYSDB_NAME, user);
    }

    if (idb & INVALIDATE_GROUPS) {
        ctx->group_filter = talloc_asprintf(ctx, "(%s=*)", SYSDB_NAME);
    } else if (group) {
        ctx->group_filter = talloc_asprintf(ctx, "(%s=%s)", SYSDB_NAME, group);
    }

    if (idb & INVALIDATE_NETGROUPS) {
        ctx->netgroup_filter = talloc_asprintf(ctx, "(%s=*)", SYSDB_NAME);
    } else if (netgroup) {
        ctx->netgroup_filter = talloc_asprintf(ctx, "(%s=%s)", SYSDB_NAME,
                                               netgroup);
    }
    if (((idb & INVALIDATE_USERS || user) && !ctx->user_filter) ||
        ((idb & INVALIDATE_GROUPS || group) && !ctx->group_filter) ||
        ((idb & INVALIDATE_NETGROUPS || netgroup) && !ctx->netgroup_filter)) {
        DEBUG(1, ("Construction of filters failed\n"));
        ret = ENOMEM;
        goto fini;
    }

    ret = init_domains(ctx, domain);
    if (ret != EOK) {
        DEBUG(3, ("Initialization of sysdb connections failed\n"));
        goto fini;
    }

    ret = EOK;

fini:
    poptFreeContext(pc);
    free(user);
    free(group);
    free(netgroup);
    free(domain);
    if (ret != EOK && ctx) {
        talloc_zfree(ctx);
    }
    if (ret == EOK) {
        *tctx = ctx;
    }
    return ret;
}
