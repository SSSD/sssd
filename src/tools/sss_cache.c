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
#include "db/sysdb_services.h"
#include "db/sysdb_autofs.h"

#define INVALIDATE_NONE 0
#define INVALIDATE_USERS 1
#define INVALIDATE_GROUPS 2
#define INVALIDATE_NETGROUPS 4
#define INVALIDATE_SERVICES 8
#define INVALIDATE_AUTOFSMAPS 16

enum sss_cache_entry {
    TYPE_USER=0,
    TYPE_GROUP,
    TYPE_NETGROUP,
    TYPE_SERVICE,
    TYPE_AUTOFSMAP
};

struct entry_type_t {
    const char *type_string;
    int (* search_fn)(TALLOC_CTX *, struct sysdb_ctx *,
               const char *, const char **, size_t *, struct ldb_message ***);
};

static errno_t search_services(TALLOC_CTX *mem_ctx, struct sysdb_ctx *sysdb,
                              const char *sub_filter, const char **attrs,
                              size_t *msgs_count, struct ldb_message ***msgs);
static errno_t search_autofsmaps(TALLOC_CTX *mem_ctx, struct sysdb_ctx *sysdb,
                                 const char *sub_filter, const char **attrs,
                                 size_t *msgs_count, struct ldb_message ***msgs);

static struct entry_type_t entry_types[] = {
    {"user", sysdb_search_users},
    {"group", sysdb_search_groups},
    {"netgroup", sysdb_search_netgroups},
    {"service", search_services},
    {"autofs map", search_autofsmaps}
};

struct cache_tool_ctx {
    struct confdb_ctx *confdb;
    struct sss_domain_info *domains;
    struct sysdb_ctx_list *sysdb_list;
    struct sss_names_ctx *nctx;

    char *user_filter;
    char *group_filter;
    char *netgroup_filter;
    char *service_filter;
    char *autofs_filter;

    char *user_name;
    char *group_name;
    char *netgroup_name;
    char *service_name;
    char *autofs_name;

    bool update_user_filter;
    bool update_group_filter;
    bool update_netgroup_filter;
    bool update_service_filter;
    bool update_autofs_filter;
};

errno_t init_domains(struct cache_tool_ctx *ctx, const char *domain);
errno_t init_context(int argc, const char *argv[], struct cache_tool_ctx **tctx);
errno_t invalidate_entry(TALLOC_CTX *ctx, struct sysdb_ctx *sysdb,
                         const char *name, int entry_type);
bool invalidate_entries(TALLOC_CTX *ctx, struct sysdb_ctx *sysdb,
                        enum sss_cache_entry entry_type, const char *filter,
                        const char *name);
static errno_t update_all_filters(struct cache_tool_ctx *tctx,
                                  char *domain_name);

int main(int argc, const char *argv[])
{
    errno_t ret;
    struct cache_tool_ctx *tctx = NULL;
    struct sysdb_ctx *sysdb;
    int i;
    bool skipped = true;
    struct sss_domain_info *dinfo;

    ret = init_context(argc, argv, &tctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Error initializing context for the application\n"));
        goto done;
    }

    for (i = 0; i < tctx->sysdb_list->num_dbs; i++) {
        sysdb = tctx->sysdb_list->dbs[i];
        dinfo = sysdb_ctx_get_domain(sysdb);

        /* Update filters for each domain */
        ret = update_all_filters(tctx, dinfo->name);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to update filters.\n"));
            goto done;
        }

        ret = sysdb_transaction_start(sysdb);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Could not start the transaction!\n"));
            goto done;
        }

        skipped &= !invalidate_entries(tctx, sysdb, TYPE_USER,
                                   tctx->user_filter, tctx->user_name);
        skipped &= !invalidate_entries(tctx, sysdb, TYPE_GROUP,
                                   tctx->group_filter, tctx->group_name);
        skipped &= !invalidate_entries(tctx, sysdb, TYPE_NETGROUP,
                                   tctx->netgroup_filter, tctx->netgroup_name);
        skipped &= !invalidate_entries(tctx, sysdb, TYPE_SERVICE,
                                   tctx->service_filter, tctx->service_name);
        skipped &= !invalidate_entries(tctx, sysdb, TYPE_AUTOFSMAP,
                                   tctx->autofs_filter, tctx->autofs_name);

        ret = sysdb_transaction_commit(sysdb);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Could not commit the transaction!\n"));
            ret = sysdb_transaction_cancel(sysdb);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to cancel transaction\n"));
            }
        }
    }

    if (skipped == true) {
        ERROR("No cache object matched the specified search\n");
        ret = ENOENT;
        goto done;
    } else {
        ret = sss_memcache_clear_all();
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to clear memory cache.\n"));
            goto done;
        }
    }

    ret = EOK;
done:
    if (tctx) talloc_free(tctx);
    return ret;
}

static errno_t update_filter(struct cache_tool_ctx *tctx, char *domain_name,
                             char *name, bool update, const char *fmt,
                             char **filter)
{
    errno_t ret;
    char *parsed_domain = NULL;
    char *parsed_name = NULL;

    if (name && update) {
        ret = sss_parse_name(tctx, tctx->nctx, name,
                             &parsed_domain, &parsed_name);
       if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("sss_parse_name failed\n"));
            goto done;
        }

        if (parsed_domain) {
            talloc_free(*filter);
            if (!strcmp(domain_name, parsed_domain)) {
                if (fmt) {
                    *filter = talloc_asprintf(tctx, fmt,
                                              SYSDB_NAME, parsed_name);
                } else {
                    *filter = talloc_strdup(tctx, parsed_name);
                }
                if (*filter == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE, ("Out of memory\n"));
                    ret = ENOMEM;
                    goto done;
                }
            } else {
               /* Set to NULL to indicate that it will not be used
                * in this domain */
                *filter = NULL;
            }
        } else {
            if (fmt) {
                *filter = talloc_asprintf(tctx, fmt, SYSDB_NAME, name);
            } else {
                *filter = talloc_strdup(tctx, name);
            }
            if (*filter == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, ("Out of memory\n"));
                ret = ENOMEM;
                goto done;
            }
        }
    }

    ret = EOK;
done:
    talloc_free(parsed_domain);
    talloc_free(parsed_name);
    return ret;

}

/* This function updates all filters for specified domain using this
 * domains regex to parse string into domain and name (if exists). */
static errno_t update_all_filters(struct cache_tool_ctx *tctx,
                                 char *domain_name)
{
    errno_t ret;

    ret = sss_names_init(tctx, tctx->confdb, domain_name, &tctx->nctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("sss_names_init() failed\n"));
        return ret;
    }

    /* Update user filter */
    ret = update_filter(tctx, domain_name, tctx->user_name,
                        tctx->update_user_filter, "(%s=%s)",
                        &tctx->user_filter);
    if (ret != EOK) {
        return ret;
    }

    /* Update group filter */
    ret = update_filter(tctx, domain_name, tctx->group_name,
                        tctx->update_group_filter, "(%s=%s)",
                        &tctx->group_filter);
    if (ret != EOK) {
        return ret;
    }

    /* Update netgroup filter */
    ret = update_filter(tctx, domain_name, tctx->netgroup_name,
                        tctx->update_netgroup_filter, "(%s=%s)",
                        &tctx->netgroup_filter);
    if (ret != EOK) {
        return ret;
    }

    /* Update service filter */
    ret = update_filter(tctx, domain_name, tctx->service_name,
                        tctx->update_service_filter, NULL,
                        &tctx->service_filter);
    if (ret != EOK) {
        return ret;
    }

    /* Update autofs filter */
    ret = update_filter(tctx, domain_name, tctx->autofs_name,
                        tctx->update_autofs_filter,
                        "(&(objectclass="SYSDB_AUTOFS_MAP_OC")(%s=%s))",
                        &tctx->autofs_filter);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}


bool invalidate_entries(TALLOC_CTX *ctx, struct sysdb_ctx *sysdb,
                        enum sss_cache_entry entry_type, const char *filter,
                        const char *name)
{
    const char *attrs[] = {SYSDB_NAME, NULL};
    size_t msg_count;
    struct ldb_message **msgs;
    struct entry_type_t type_rec;
    errno_t ret;
    int i;
    const char *c_name;
    bool iret;
    struct sss_domain_info *dinfo;

    if (!filter) return false;

    dinfo = sysdb_ctx_get_domain(sysdb);

    type_rec = entry_types[entry_type];
    ret = type_rec.search_fn(ctx, sysdb, filter, attrs,
                                &msg_count, &msgs);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Searching for %s in domain %s with filter %s failed\n",
               type_rec.type_string, dinfo->name, filter));
        if (name) {
            ERROR("No such %1$s named %2$s in domain %3$s, skipping\n",
                  type_rec.type_string, name, dinfo->name);
        } else {
            ERROR("No objects of type %1$s from domain %2$s in the cache, "
                   "skipping\n", type_rec.type_string, dinfo->name);
        }
        return false;
    }

    iret = true;
    for (i = 0; i < msg_count; i++) {
        c_name = ldb_msg_find_attr_as_string(msgs[i], SYSDB_NAME, NULL);
        if (c_name == NULL) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("Something bad happened, can't find attribute %s", SYSDB_NAME));
            ERROR("Couldn't invalidate %1$s", type_rec.type_string);
            iret = false;
        } else {
            ret = invalidate_entry(ctx, sysdb, c_name, entry_type);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      ("Couldn't invalidate %s %s", type_rec.type_string, c_name));
                ERROR("Couldn't invalidate %1$s %2$s", type_rec.type_string, c_name);
                iret = false;
            }
        }
    }
    talloc_zfree(msgs);
    return iret;
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
                case TYPE_SERVICE:
                    ret = sysdb_set_service_attr(sysdb, name,
                                                 sys_attrs, SYSDB_MOD_REP);
                    break;
                case TYPE_AUTOFSMAP:
                    ret = sysdb_set_autofsmap_attr(sysdb, name,
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

errno_t init_domains(struct cache_tool_ctx *ctx, const char *domain)
{
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
            SYSDB_VERSION_ERROR(ret);
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
        SYSDB_VERSION_ERROR(ret);
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
    char *service = NULL;
    char *map = NULL;
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
        { "service", 's', POPT_ARG_STRING, &service, 0,
            _("Invalidate particular service"), NULL },
        { "services", 'S', POPT_ARG_NONE, NULL, 's',
            _("Invalidate all services"), NULL },
#ifdef BUILD_AUTOFS
        { "autofs-map", 'a', POPT_ARG_STRING, &map, 0,
            _("Invalidate particular autofs map"), NULL },
        { "autofs-maps", 'A', POPT_ARG_NONE, NULL, 'a',
            _("Invalidate all autofs maps"), NULL },
#endif /* BUILD_AUTOFS */
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
            case 's':
                idb |= INVALIDATE_SERVICES;
                break;
            case 'a':
                idb |= INVALIDATE_AUTOFSMAPS;
                break;
        }
    }

    if (ret != -1) {
        BAD_POPT_PARAMS(pc, poptStrerror(ret), ret, fini);
    }

    if (idb == INVALIDATE_NONE && !user && !group &&
        !netgroup && !service && !map) {
        BAD_POPT_PARAMS(pc,
                _("Please select at least one object to invalidate\n"),
                ret, fini);
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
        ctx->update_user_filter = false;
    } else if (user) {
        ctx->user_name = talloc_strdup(ctx, user);
        ctx->update_user_filter = true;
    }

    if (idb & INVALIDATE_GROUPS) {
        ctx->group_filter = talloc_asprintf(ctx, "(%s=*)", SYSDB_NAME);
        ctx->update_group_filter = false;
    } else if (group) {
        ctx->group_name = talloc_strdup(ctx, group);
        ctx->update_group_filter = true;
    }

    if (idb & INVALIDATE_NETGROUPS) {
        ctx->netgroup_filter = talloc_asprintf(ctx, "(%s=*)", SYSDB_NAME);
        ctx->update_netgroup_filter = false;
    } else if (netgroup) {
        ctx->netgroup_name = talloc_strdup(ctx, netgroup);
        ctx->update_netgroup_filter = true;
    }

    if (idb & INVALIDATE_SERVICES) {
        ctx->service_filter = talloc_strdup(ctx, "*");
        ctx->update_service_filter = false;
    } else if (service) {
        ctx->service_name = talloc_strdup(ctx, service);
        ctx->update_service_filter = true;
    }

    if (idb & INVALIDATE_AUTOFSMAPS) {
        ctx->autofs_filter = talloc_asprintf(ctx, "(&(objectclass=%s)(%s=*))",
                                             SYSDB_AUTOFS_MAP_OC, SYSDB_NAME);
        ctx->update_autofs_filter = false;
    } else if (map) {
        ctx->autofs_name = talloc_strdup(ctx, map);
        ctx->update_autofs_filter = true;
    }

    if (((idb & INVALIDATE_USERS) && !ctx->user_filter) ||
        ((idb & INVALIDATE_GROUPS) && !ctx->group_filter) ||
        ((idb & INVALIDATE_NETGROUPS) && !ctx->netgroup_filter) ||
        ((idb & INVALIDATE_SERVICES) && !ctx->service_filter) ||
        ((idb & INVALIDATE_AUTOFSMAPS) && !ctx->autofs_filter) ||
         (user && !ctx->user_name) || (group && !ctx->group_name) ||
         (netgroup && !ctx->netgroup_name) || (map && !ctx->autofs_name) ||
         (service && !ctx->service_name)) {
        DEBUG(1, ("Construction of filters failed\n"));
        ret = ENOMEM;
        goto fini;
    }

    ret = init_domains(ctx, domain);
    if (ret != EOK) {
        if (domain) {
            ERROR("Could not open domain %1$s\n", domain);
        } else {
            ERROR("Could not open available domains\n");
        }
        DEBUG(SSSDBG_OP_FAILURE,
              ("Initialization of sysdb connections failed\n"));
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

static errno_t
search_services(TALLOC_CTX *mem_ctx, struct sysdb_ctx *sysdb,
                const char *sub_filter, const char **attrs,
                size_t *msgs_count, struct ldb_message ***msgs)
{
    errno_t ret;
    struct ldb_result *res;

    if (strcmp(sub_filter, "*") == 0) {
        /* All services */
        ret = sysdb_enumservent(mem_ctx, sysdb, &res);
    } else {
        /* Get service by name */
        ret = sysdb_getservbyname(mem_ctx, sysdb, sub_filter,
                                  NULL, &res);
    }

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not get service from sysdb: "
              "[%d]: %s\n", ret, strerror(ret)));
        return ret;
    }

    *msgs_count = res->count;
    *msgs = res->msgs;
    return EOK;
}

static errno_t
search_autofsmaps(TALLOC_CTX *mem_ctx, struct sysdb_ctx *sysdb,
                  const char *sub_filter, const char **attrs,
                  size_t *msgs_count, struct ldb_message ***msgs)
{
#ifdef BUILD_AUTOFS
    return sysdb_search_custom(mem_ctx, sysdb, sub_filter,
                               AUTOFS_MAP_SUBDIR, attrs,
                               msgs_count, msgs);
#else
    return ENOSYS;
#endif  /* BUILD_AUTOFS */
}
