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
#include "tools/tools_util.h"
#include "tools/common/sss_tools.h"
#include "db/sysdb.h"
#include "db/sysdb_services.h"
#include "db/sysdb_autofs.h"
#include "db/sysdb_ssh.h"
#include "db/sysdb_sudo.h"

#define INVALIDATE_NONE 0
#define INVALIDATE_USERS 1
#define INVALIDATE_GROUPS 2
#define INVALIDATE_NETGROUPS 4
#define INVALIDATE_SERVICES 8
#define INVALIDATE_AUTOFSMAPS 16
#define INVALIDATE_SSH_HOSTS 32
#define INVALIDATE_SUDO_RULES 64

#ifdef BUILD_AUTOFS
#ifdef BUILD_SSH
#define INVALIDATE_EVERYTHING (INVALIDATE_USERS | INVALIDATE_GROUPS | \
                               INVALIDATE_NETGROUPS | INVALIDATE_SERVICES | \
                               INVALIDATE_AUTOFSMAPS | INVALIDATE_SSH_HOSTS )
#else  /* BUILD_SSH */
#define INVALIDATE_EVERYTHING (INVALIDATE_USERS | INVALIDATE_GROUPS | \
                               INVALIDATE_NETGROUPS | INVALIDATE_SERVICES | \
                               INVALIDATE_AUTOFSMAPS )
#endif /* BUILD_SSH */
#else  /* BUILD_AUTOFS */
#ifdef BUILD_SSH
#define INVALIDATE_EVERYTHING (INVALIDATE_USERS | INVALIDATE_GROUPS | \
                               INVALIDATE_NETGROUPS | INVALIDATE_SERVICES | \
                               INVALIDATE_SSH_HOSTS )
#else  /* BUILD_SSH */
#define INVALIDATE_EVERYTHING (INVALIDATE_USERS | INVALIDATE_GROUPS | \
                               INVALIDATE_NETGROUPS | INVALIDATE_SERVICES )
#endif /* BUILD_SSH */
#endif /* BUILD_AUTOFS */

enum sss_cache_entry {
    TYPE_USER=0,
    TYPE_GROUP,
    TYPE_NETGROUP,
    TYPE_SERVICE,
    TYPE_AUTOFSMAP,
    TYPE_SSH_HOST,
    TYPE_SUDO_RULE
};

static errno_t search_autofsmaps(TALLOC_CTX *mem_ctx,
                                 struct sss_domain_info *domain,
                                 const char *sub_filter, const char **attrs,
                                 size_t *msgs_count, struct ldb_message ***msgs);

struct input_values {
    char *domain;
    char *group;
    char *map;
    char *netgroup;
    char *service;
    char *ssh_host;
    char *sudo_rule;
    char *user;
};

struct cache_tool_ctx {
    struct confdb_ctx *confdb;
    struct sss_domain_info *domains;

    char *user_filter;
    char *group_filter;
    char *netgroup_filter;
    char *service_filter;
    char *autofs_filter;
    char *ssh_host_filter;
    char *sudo_rule_filter;

    char *user_name;
    char *group_name;
    char *netgroup_name;
    char *service_name;
    char *autofs_name;
    char *ssh_host_name;
    char *sudo_rule_name;

    bool update_user_filter;
    bool update_group_filter;
    bool update_netgroup_filter;
    bool update_service_filter;
    bool update_autofs_filter;
    bool update_ssh_host_filter;
    bool update_sudo_rule_filter;
};

static void free_input_values(struct input_values *values);
static bool is_filter_valid(struct cache_tool_ctx *ctx,
                            struct input_values *values, int idb);
static errno_t init_domains(struct cache_tool_ctx *ctx,
                            const char *domain);
static errno_t init_context(int argc, const char *argv[],
                            struct cache_tool_ctx **tctx);
static errno_t invalidate_entry(TALLOC_CTX *ctx,
                                struct sss_domain_info *domain,
                                const char *name, int entry_type);
static bool invalidate_entries(TALLOC_CTX *ctx,
                               struct sss_domain_info *dinfo,
                               enum sss_cache_entry entry_type,
                               const char *filter, const char *name);
static errno_t update_all_filters(struct cache_tool_ctx *tctx,
                                  struct sss_domain_info *dinfo);
static int sysdb_invalidate_user_cache_entry(struct sss_domain_info *domain,
                                             const char *name);
static int sysdb_invalidate_group_cache_entry(struct sss_domain_info *domain,
                                              const char *name);

int main(int argc, const char *argv[])
{
    errno_t ret;
    struct cache_tool_ctx *tctx = NULL;
    struct sysdb_ctx *sysdb;
    bool skipped = true;
    struct sss_domain_info *dinfo;

    ret = init_context(argc, argv, &tctx);
    if (ret == ERR_NO_DOMAIN_ENABLED) {
        /* nothing to invalidate; no reason to fail */
        ret = EOK;
        goto done;
    } else if (ret == ERR_DOMAIN_NOT_FOUND) {
        /* Cannot find domain specified in the parameter --domain.
         * It might be a typo and therefore we will fail.
         */
        ret = ENOENT;
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Error initializing context for the application\n");
        goto done;
    }

    for (dinfo = tctx->domains; dinfo;
            dinfo = get_next_domain(dinfo, SSS_GND_DESCEND)) {
        if (!IS_SUBDOMAIN(dinfo)) {
            /* Update list of subdomains for this domain */
            ret = sysdb_update_subdomains(dinfo, tctx->confdb);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Failed to update subdomains for domain %s.\n", dinfo->name);
            }
        }

        sysdb = dinfo->sysdb;
        /* Update filters for each domain */
        ret = update_all_filters(tctx, dinfo);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to update filters.\n");
            goto done;
        }

        ret = sysdb_transaction_start(sysdb);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Could not start the transaction!\n");
            goto done;
        }

        skipped &= !invalidate_entries(tctx, dinfo, TYPE_USER,
                                       tctx->user_filter,
                                       tctx->user_name);
        skipped &= !invalidate_entries(tctx, dinfo, TYPE_GROUP,
                                       tctx->group_filter,
                                       tctx->group_name);
        skipped &= !invalidate_entries(tctx, dinfo, TYPE_NETGROUP,
                                       tctx->netgroup_filter,
                                       tctx->netgroup_name);
        skipped &= !invalidate_entries(tctx, dinfo, TYPE_SERVICE,
                                       tctx->service_filter,
                                       tctx->service_name);
        skipped &= !invalidate_entries(tctx, dinfo, TYPE_AUTOFSMAP,
                                       tctx->autofs_filter,
                                       tctx->autofs_name);
        skipped &= !invalidate_entries(tctx, dinfo, TYPE_SSH_HOST,
                                       tctx->ssh_host_filter,
                                       tctx->ssh_host_name);
        skipped &= !invalidate_entries(tctx, dinfo, TYPE_SUDO_RULE,
                                       tctx->sudo_rule_filter,
                                       tctx->sudo_rule_name);

        ret = sysdb_transaction_commit(sysdb);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Could not commit the transaction!\n");
            ret = sysdb_transaction_cancel(sysdb);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Failed to cancel transaction\n");
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
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to clear memory cache.\n");
            goto done;
        }
    }

    ret = EOK;
done:
    if (tctx) talloc_free(tctx);
    return ret;
}

static void free_input_values(struct input_values *values)
{
    free(values->domain);
    free(values->group);
    free(values->map);
    free(values->netgroup);
    free(values->service);
    free(values->ssh_host);
    free(values->sudo_rule);
    free(values->user);
}

static errno_t update_filter(struct cache_tool_ctx *tctx,
                             struct sss_domain_info *dinfo,
                             char *name, bool update, const char *fmt,
                             enum sss_cache_entry entry_type,
                             bool force_case_sensitivity,
                             char **_filter)
{
    errno_t ret;
    char *parsed_domain = NULL;
    char *parsed_name = NULL;
    TALLOC_CTX *tmp_ctx = NULL;
    char *use_name = NULL;
    char *filter;
    char *sanitized;
    char *lc_sanitized;

    if (!name || !update) {
        /* Nothing to do */
        return EOK;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory.\n");
        return ENOMEM;
    }

    ret = sss_parse_name(tmp_ctx, dinfo->names, name,
                         &parsed_domain, &parsed_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sss_parse_name failed\n");
        goto done;
    }

    if (parsed_domain != NULL && strcasecmp(dinfo->name, parsed_domain) != 0) {
        /* We were able to parse the domain from given fqdn, but it
         * does not match with currently processed domain. */
        filter = NULL;
        ret = EOK;
        goto done;
    }

    if (!dinfo->case_sensitive && !force_case_sensitivity) {
        use_name = sss_tc_utf8_str_tolower(tmp_ctx, parsed_name);
        if (!use_name) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory\n");
            ret = ENOMEM;
            goto done;
        }
    } else {
        use_name = parsed_name;
    }

    switch (entry_type) {
        case TYPE_USER:
        case TYPE_GROUP:
            use_name = sss_create_internal_fqname(tmp_ctx, use_name, dinfo->name);
        default:
            break;
    }
    if (!use_name) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_filter_sanitize_for_dom(tmp_ctx, use_name, dinfo,
                                      &sanitized, &lc_sanitized);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to sanitize the given name.\n");
        goto done;
    }

    if (fmt) {
        if (!dinfo->case_sensitive && !force_case_sensitivity) {
            filter = talloc_asprintf(tmp_ctx, "(|(%s=%s)(%s=%s))",
                                     SYSDB_NAME_ALIAS, lc_sanitized,
                                     SYSDB_NAME_ALIAS, sanitized);
        } else {
            filter = talloc_asprintf(tmp_ctx, fmt, SYSDB_NAME, sanitized);
        }
    } else {
        filter = talloc_strdup(tmp_ctx, sanitized);
    }
    if (filter == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory\n");
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;

done:
    if (ret == EOK) {
        talloc_free(*_filter);
        *_filter = talloc_steal(tctx, filter);
    }

    talloc_free(tmp_ctx);
    return ret;

}

/* This function updates all filters for specified domain using this
 * domains regex to parse string into domain and name (if exists). */
static errno_t update_all_filters(struct cache_tool_ctx *tctx,
                                  struct sss_domain_info *dinfo)
{
    errno_t ret;

    /* Update user filter */
    ret = update_filter(tctx, dinfo, tctx->user_name,
                        tctx->update_user_filter, "(%s=%s)",
                        TYPE_USER, false,
                        &tctx->user_filter);
    if (ret != EOK) {
        return ret;
    }

    /* Update group filter */
    ret = update_filter(tctx, dinfo, tctx->group_name,
                        tctx->update_group_filter, "(%s=%s)",
                        TYPE_GROUP, false,
                        &tctx->group_filter);
    if (ret != EOK) {
        return ret;
    }

    /* Update netgroup filter */
    ret = update_filter(tctx, dinfo, tctx->netgroup_name,
                        tctx->update_netgroup_filter, "(%s=%s)",
                        TYPE_NETGROUP, false,
                        &tctx->netgroup_filter);
    if (ret != EOK) {
        return ret;
    }

    /* Update service filter */
    ret = update_filter(tctx, dinfo, tctx->service_name,
                        tctx->update_service_filter, "(%s=%s)",
                        TYPE_SERVICE, false,
                        &tctx->service_filter);
    if (ret != EOK) {
        return ret;
    }

    /* Update autofs filter */
    ret = update_filter(tctx, dinfo, tctx->autofs_name,
                        tctx->update_autofs_filter,
                        "(&(objectclass="SYSDB_AUTOFS_MAP_OC")(%s=%s))",
                        TYPE_AUTOFSMAP, true,
                        &tctx->autofs_filter);
    if (ret != EOK) {
        return ret;
    }

    /* Update ssh host filter */
    ret = update_filter(tctx, dinfo, tctx->ssh_host_name,
                        tctx->update_ssh_host_filter, "(%s=%s)",
                        TYPE_SSH_HOST, false,
                        &tctx->ssh_host_filter);
    if (ret != EOK) {
        return ret;
    }

    /* Update sudo rule filter */
    ret = update_filter(tctx, dinfo, tctx->sudo_rule_name,
                        tctx->update_sudo_rule_filter,
                        "(%s=%s)", TYPE_SUDO_RULE, false,
                        &tctx->sudo_rule_filter);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

static bool invalidate_entries(TALLOC_CTX *ctx,
                               struct sss_domain_info *dinfo,
                               enum sss_cache_entry entry_type,
                               const char *filter, const char *name)
{
    const char *attrs[] = {SYSDB_NAME, NULL};
    size_t msg_count = 0;
    struct ldb_message **msgs;
    const char *type_string = "unknown";
    errno_t ret = EINVAL;
    int i;
    const char *c_name;
    bool iret;

    if (!filter) return false;
    switch (entry_type) {
    case TYPE_USER:
        type_string = "user";
        ret = sysdb_search_users(ctx, dinfo,
                                 filter, attrs, &msg_count, &msgs);
        break;
    case TYPE_GROUP:
        type_string = "group";
        ret = sysdb_search_groups(ctx, dinfo,
                                  filter, attrs, &msg_count, &msgs);
        break;
    case TYPE_NETGROUP:
        type_string = "netgroup";
        ret = sysdb_search_netgroups(ctx, dinfo,
                                     filter, attrs, &msg_count, &msgs);
        break;
    case TYPE_SERVICE:
        type_string = "service";
        ret = sysdb_search_services(ctx, dinfo,
                                    filter, attrs, &msg_count, &msgs);
        break;
    case TYPE_AUTOFSMAP:
        type_string = "autofs map";
        ret = search_autofsmaps(ctx, dinfo, filter, attrs, &msg_count, &msgs);
        break;
    case TYPE_SSH_HOST:
        type_string = "ssh_host";
#ifdef BUILD_SSH
        ret = sysdb_search_ssh_hosts(ctx, dinfo,
                                     filter, attrs, &msg_count, &msgs);
#else  /* BUILD_SSH */
        ret = ENOSYS;
#endif /* BUILD_SSH */
        break;
    case TYPE_SUDO_RULE:
        type_string = "sudo_rule";
#ifdef BUILD_SUDO
        ret = sysdb_search_sudo_rules(ctx, dinfo,
                                      filter, attrs, &msg_count, &msgs);
#else  /* BUILD_SUDO */
        ret = ENOSYS;
#endif /* BUILD_SUDO */
        break;
    }

    if (ret != EOK) {
        if (ret == ENOENT) {
            DEBUG(SSSDBG_TRACE_FUNC, "'%s' %s: Not found in domain '%s'\n",
                  type_string, name ? name : "", dinfo->name);
            if (name == NULL) {
                /* nothing to invalidate in that domain, no reason to fail */
                return true;
            } else {
                /* we failed to invalidate explicit name; inform about it */
                return false;
            }
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Searching for %s in domain %s with filter %s failed\n",
                   type_string, dinfo->name, filter);
        }
        return false;
    }

    iret = true;
    for (i = 0; i < msg_count; i++) {
        c_name = ldb_msg_find_attr_as_string(msgs[i], SYSDB_NAME, NULL);
        if (c_name == NULL) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Something bad happened, can't find attribute %s\n",
                  SYSDB_NAME);
            ERROR("Couldn't invalidate %1$s\n", type_string);
            iret = false;
        } else {
            ret = invalidate_entry(ctx, dinfo, c_name, entry_type);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Couldn't invalidate %s %s\n", type_string, c_name);
                ERROR("Couldn't invalidate %1$s %2$s\n", type_string, c_name);
                iret = false;
            }
        }
    }
    talloc_zfree(msgs);
    return iret;
}

static errno_t invalidate_entry(TALLOC_CTX *ctx,
                                struct sss_domain_info *domain,
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
                    /* For users, we also need to reset the initgroups
                     * cache expiry */
                    ret = sysdb_attrs_add_time_t(sys_attrs,
                            SYSDB_INITGR_EXPIRE, 1);
                    if (ret != EOK) return ret;
                    ret = sysdb_attrs_add_string(sys_attrs,
                            SYSDB_ORIG_MODSTAMP, "1");
                    if (ret != EOK) return ret;
                    ret = sysdb_attrs_add_uint32(sys_attrs,
                            SYSDB_USN, 1);
                    if (ret != EOK) return ret;

                    ret = sysdb_set_user_attr(domain, name, sys_attrs,
                                              SYSDB_MOD_REP);
                    if (ret != EOK) break;

                    /* WARNING: Direct writing to persistent cache!! */
                    ret = sysdb_invalidate_user_cache_entry(domain, name);
                    break;
                case TYPE_GROUP:
                    ret = sysdb_attrs_add_string(sys_attrs,
                            SYSDB_ORIG_MODSTAMP, "1");
                    if (ret != EOK) return ret;
                    ret = sysdb_attrs_add_uint32(sys_attrs,
                            SYSDB_USN, 1);
                    if (ret != EOK) return ret;

                    ret = sysdb_set_group_attr(domain, name, sys_attrs,
                                               SYSDB_MOD_REP);
                    if (ret != EOK) break;

                    /* WARNING: Direct writing to persistent cache!! */
                    ret = sysdb_invalidate_group_cache_entry(domain, name);
                    break;
                case TYPE_NETGROUP:
                    ret = sysdb_set_netgroup_attr(domain, name, sys_attrs,
                                                  SYSDB_MOD_REP);
                    break;
                case TYPE_SERVICE:
                    ret = sysdb_set_service_attr(domain, name,
                                                 sys_attrs, SYSDB_MOD_REP);
                    break;
                case TYPE_AUTOFSMAP:
                    /* For users, we also need to reset the enumeration
                     * expiration time. */
                    ret = sysdb_attrs_add_time_t(sys_attrs,
                                                 SYSDB_ENUM_EXPIRE, 1);
                    if (ret != EOK) {
                        return ret;
                    }

                    ret = sysdb_set_autofsmap_attr(domain, name,
                                                   sys_attrs, SYSDB_MOD_REP);
                    if (ret != EOK) {
                        DEBUG(SSSDBG_MINOR_FAILURE, "Could not invalidate "
                              "autofs map %s\n", name);
                        break;
                    }

                    ret = sysdb_invalidate_autofs_entries(domain, name);
                    break;
                case TYPE_SSH_HOST:
#ifdef BUILD_SSH
                    ret = sysdb_set_ssh_host_attr(domain, name,
                                                  sys_attrs, SYSDB_MOD_REP);
#else  /* BUILD_SSH */
                    ret = ENOSYS;
#endif /* BUILD_SSH */
                    break;
                case TYPE_SUDO_RULE:
#ifdef BUILD_SUDO
                    ret = sysdb_set_sudo_rule_attr(domain, name,
                                                   sys_attrs, SYSDB_MOD_REP);
#else  /* BUILD_SUDO */
                    ret = ENOSYS;
#endif /* BUILD_SUDO */
                    break;
                default:
                    return EINVAL;
            }
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE, "Could not set entry attributes\n");
            }
        } else {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Could not add expiration time to attributes\n");
        }
        talloc_zfree(sys_attrs);
    } else {
        DEBUG(SSSDBG_MINOR_FAILURE, "Could not create sysdb attributes\n");
        ret = ENOMEM;
    }
    return ret;
}

static errno_t init_domains(struct cache_tool_ctx *ctx,
                            const char *domain)
{
    int ret;
    struct sss_domain_info *dinfo;

    ret = sss_tool_confdb_init(ctx, &ctx->confdb);
    if (ret != EOK) {
        ERROR("Can't find configuration db, was SSSD configured and run?\n");
        return ERR_NO_DOMAIN_ENABLED;
    }

    if (domain) {
        ret = sssd_domain_init(ctx, ctx->confdb,
                               domain, DB_PATH, &ctx->domains);
        if (ret != EOK) {
            SYSDB_VERSION_ERROR(ret);
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Could not initialize connection to the sysdb\n");
            return ret;
        }

    } else {
        ret = confdb_get_domains(ctx->confdb, &ctx->domains);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not initialize domains\n");
            return ret;
        }

        ret = sysdb_init(ctx, ctx->domains);
        SYSDB_VERSION_ERROR(ret);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Could not initialize connection to the sysdb\n");
            return ret;
        }
    }

    for (dinfo = ctx->domains; dinfo; dinfo = get_next_domain(dinfo, 0)) {
        ret = sss_names_init(ctx, ctx->confdb, dinfo->name, &dinfo->names);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "sss_names_init() failed\n");
            return ret;
        }
    }

    return EOK;
}

static errno_t init_context(int argc, const char *argv[],
                            struct cache_tool_ctx **tctx)
{
    struct cache_tool_ctx *ctx = NULL;
    int idb = INVALIDATE_NONE;
    struct input_values values = { 0 };
    int debug = SSSDBG_TOOLS_DEFAULT;
    errno_t ret = EOK;

    poptContext pc = NULL;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        { "debug", '\0', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &debug,
            0, _("The debug level to run with"), NULL },
        { "everything", 'E', POPT_ARG_NONE, NULL, 'e',
            _("Invalidate all cached entries"), NULL },
        { "user", 'u', POPT_ARG_STRING, &(values.user), 0,
            _("Invalidate particular user"), NULL },
        { "users", 'U', POPT_ARG_NONE, NULL, 'u',
            _("Invalidate all users"), NULL },
        { "group", 'g', POPT_ARG_STRING, &(values.group), 0,
            _("Invalidate particular group"), NULL },
        { "groups", 'G', POPT_ARG_NONE, NULL, 'g',
            _("Invalidate all groups"), NULL },
        { "netgroup", 'n', POPT_ARG_STRING, &(values.netgroup), 0,
            _("Invalidate particular netgroup"), NULL },
        { "netgroups", 'N', POPT_ARG_NONE, NULL, 'n',
            _("Invalidate all netgroups"), NULL },
        { "service", 's', POPT_ARG_STRING, &(values.service), 0,
            _("Invalidate particular service"), NULL },
        { "services", 'S', POPT_ARG_NONE, NULL, 's',
            _("Invalidate all services"), NULL },
#ifdef BUILD_AUTOFS
        { "autofs-map", 'a', POPT_ARG_STRING, &(values.map), 0,
            _("Invalidate particular autofs map"), NULL },
        { "autofs-maps", 'A', POPT_ARG_NONE, NULL, 'a',
            _("Invalidate all autofs maps"), NULL },
#endif /* BUILD_AUTOFS */
#ifdef BUILD_SSH
        { "ssh-host", 'h', POPT_ARG_STRING, &(values.ssh_host), 0,
            _("Invalidate particular SSH host"), NULL },
        { "ssh-hosts", 'H', POPT_ARG_NONE, NULL, 'h',
            _("Invalidate all SSH hosts"), NULL },
#endif /* BUILD_SSH */
#ifdef BUILD_SUDO
        { "sudo-rule", 'r', POPT_ARG_STRING, &(values.sudo_rule), 0,
            _("Invalidate particular sudo rule"), NULL },
        { "sudo-rules", 'R', POPT_ARG_NONE, NULL, 'r',
            _("Invalidate all cached sudo rules"), NULL },
#endif /* BUILD_SUDO */
        { "domain", 'd', POPT_ARG_STRING, &(values.domain), 0,
            _("Only invalidate entries from a particular domain"), NULL },
        POPT_TABLEEND
    };

    ret = set_locale();
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "set_locale failed (%d): %s\n", ret, strerror(ret));
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
            case 'h':
                idb |= INVALIDATE_SSH_HOSTS;
                break;
            case 'r':
                idb |= INVALIDATE_SUDO_RULES;
                break;
            case 'e':
                idb = INVALIDATE_EVERYTHING;
#ifdef BUILD_SUDO
                idb |= INVALIDATE_SUDO_RULES;
#endif /* BUILD_SUDO */
                break;
        }
    }

    DEBUG_CLI_INIT(debug);
    debug_prg_name = argv[0];

    if (ret != -1) {
        BAD_POPT_PARAMS(pc, poptStrerror(ret), ret, fini);
    }

    if (poptGetArg(pc)) {
        BAD_POPT_PARAMS(pc,
                _("Unexpected argument(s) provided, options that "
                  "invalidate a single object only accept a single "
                  "provided argument.\n"),
                  ret, fini);
    }

    if (idb == INVALIDATE_NONE && !values.user && !values.group &&
        !values.netgroup && !values.service && !values.map &&
        !values.ssh_host && !values.sudo_rule) {
        BAD_POPT_PARAMS(pc,
                _("Please select at least one object to invalidate\n"),
                ret, fini);
    }

    CHECK_ROOT(ret, debug_prg_name);

    ctx = talloc_zero(NULL, struct cache_tool_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not allocate memory for tools context\n");
        ret = ENOMEM;
        goto fini;
    }

    if (idb & INVALIDATE_USERS) {
        ctx->user_filter = talloc_asprintf(ctx, "(%s=*)", SYSDB_NAME);
        ctx->update_user_filter = false;
    } else if (values.user) {
        ctx->user_name = talloc_strdup(ctx, values.user);
        ctx->update_user_filter = true;
    }

    if (idb & INVALIDATE_GROUPS) {
        ctx->group_filter = talloc_asprintf(ctx, "(%s=*)", SYSDB_NAME);
        ctx->update_group_filter = false;
    } else if (values.group) {
        ctx->group_name = talloc_strdup(ctx, values.group);
        ctx->update_group_filter = true;
    }

    if (idb & INVALIDATE_NETGROUPS) {
        ctx->netgroup_filter = talloc_asprintf(ctx, "(%s=*)", SYSDB_NAME);
        ctx->update_netgroup_filter = false;
    } else if (values.netgroup) {
        ctx->netgroup_name = talloc_strdup(ctx, values.netgroup);
        ctx->update_netgroup_filter = true;
    }

    if (idb & INVALIDATE_SERVICES) {
        ctx->service_filter = talloc_asprintf(ctx, "(%s=*)", SYSDB_NAME);
        ctx->update_service_filter = false;
    } else if (values.service) {
        ctx->service_name = talloc_strdup(ctx, values.service);
        ctx->update_service_filter = true;
    }

    if (idb & INVALIDATE_AUTOFSMAPS) {
        ctx->autofs_filter = talloc_asprintf(ctx, "(&(objectclass=%s)(%s=*))",
                                             SYSDB_AUTOFS_MAP_OC, SYSDB_NAME);
        ctx->update_autofs_filter = false;
    } else if (values.map) {
        ctx->autofs_name = talloc_strdup(ctx, values.map);
        ctx->update_autofs_filter = true;
    }

    if (idb & INVALIDATE_SSH_HOSTS) {
        ctx->ssh_host_filter = talloc_asprintf(ctx, "(%s=*)", SYSDB_NAME);
        ctx->update_ssh_host_filter = false;
    } else if (values.ssh_host) {
        ctx->ssh_host_name = talloc_strdup(ctx, values.ssh_host);
        ctx->update_ssh_host_filter = true;
    }

    if (idb & INVALIDATE_SUDO_RULES) {
        ctx->sudo_rule_filter = talloc_asprintf(ctx, "(%s=*)", SYSDB_NAME);
        ctx->update_sudo_rule_filter = false;
    } else if (values.sudo_rule) {
        ctx->sudo_rule_name = talloc_strdup(ctx, values.sudo_rule);
        ctx->update_sudo_rule_filter = true;
    }

    if (is_filter_valid(ctx, &values, idb) == false) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Construction of filters failed\n");
        ret = ENOMEM;
        goto fini;
    }

    ret = init_domains(ctx, values.domain);
    if (ret == ERR_NO_DOMAIN_ENABLED && values.domain == NULL) {
        /* Nothing to invalidate; do not log confusing messages. */
        goto fini;
    } else if (ret != EOK) {
        if (values.domain) {
            ERROR("Could not open domain %1$s. If the domain is a subdomain "
                  "(trusted domain), use fully qualified name instead of "
                  "--domain/-d parameter.\n", values.domain);
            ret = ERR_DOMAIN_NOT_FOUND;
        } else {
            ERROR("Could not open available domains\n");
        }
        DEBUG(SSSDBG_OP_FAILURE,
              "Initialization of sysdb connections failed\n");
        goto fini;
    }

    ret = EOK;

fini:
    poptFreeContext(pc);
    free_input_values(&values);
    if (ret != EOK && ctx) {
        talloc_zfree(ctx);
    }
    if (ret == EOK) {
        *tctx = ctx;
    }
    return ret;
}

static bool is_filter_valid(struct cache_tool_ctx *ctx,
                            struct input_values *values, int idb)
{
    if ((idb & INVALIDATE_USERS) && ctx->user_filter == NULL) {
        return false;
    }

    if ((idb & INVALIDATE_GROUPS) && ctx->group_filter == NULL) {
        return false;
    }

    if ((idb & INVALIDATE_NETGROUPS) && ctx->netgroup_filter == NULL) {
        return false;
    }

    if ((idb & INVALIDATE_SERVICES) && ctx->service_filter == NULL) {
        return false;
    }

    if ((idb & INVALIDATE_AUTOFSMAPS) && ctx->autofs_filter == NULL) {
        return false;
    }

    if ((idb & INVALIDATE_SSH_HOSTS) && ctx->ssh_host_filter == NULL) {
        return false;
    }

    if (values->user && ctx->user_name == NULL) {
        return false;
    }

    if (values->group && ctx->group_name == NULL) {
        return false;
    }

    if (values->netgroup && ctx->netgroup_name == NULL) {
        return false;
    }

    if (values->service && ctx->service_name == NULL) {
        return false;
    }

    if (values->map && ctx->autofs_name == NULL) {
        return false;
    }

    if (values->ssh_host && ctx->ssh_host_name == NULL) {
        return false;
    }

    if (values->sudo_rule && ctx->sudo_rule_name == NULL) {
        return false;
    }

    return true;
}

static errno_t
search_autofsmaps(TALLOC_CTX *mem_ctx,
                  struct sss_domain_info *domain,
                  const char *sub_filter, const char **attrs,
                  size_t *msgs_count, struct ldb_message ***msgs)
{
#ifdef BUILD_AUTOFS
    return sysdb_search_custom(mem_ctx, domain, sub_filter,
                               AUTOFS_MAP_SUBDIR, attrs,
                               msgs_count, msgs);
#else
    return ENOSYS;
#endif  /* BUILD_AUTOFS */
}

/* WARNING: Direct writing to persistent cache!! */
static int sysdb_invalidate_user_cache_entry(struct sss_domain_info *domain,
                                             const char *name)
{
    return sysdb_invalidate_cache_entry(domain, name, true);
}

/* WARNING: Direct writing to persistent cache!! */
static int sysdb_invalidate_group_cache_entry(struct sss_domain_info *domain,
                                              const char *name)
{
    return sysdb_invalidate_cache_entry(domain, name, false);
}
