/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2016 Red Hat

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

#include <popt.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>

#include "util/util.h"
#include "db/sysdb.h"
#include "tools/common/sss_tools.h"
#include "tools/sssctl/sssctl.h"

#define NOT_FOUND_MSG(obj) _(obj " %s is not present in cache.\n")

#define SSSCTL_CACHE_NAME   {_("Name"), SYSDB_NAME, get_attr_name}
#define SSSCTL_CACHE_CREATE {_("Cache entry creation date"), SYSDB_CREATE_TIME, get_attr_time}
#define SSSCTL_CACHE_UPDATE {_("Cache entry last update time"), SYSDB_LAST_UPDATE, get_attr_time}
#define SSSCTL_CACHE_EXPIRE {_("Cache entry expiration time"), SYSDB_CACHE_EXPIRE, get_attr_expire}
#define SSSCTL_CACHE_IFP    {_("Cached in InfoPipe"), SYSDB_IFP_CACHED, get_attr_yesno}
#define SSSCTL_CACHE_GPO_NAME    {_("Policy Name"), SYSDB_NAME, get_attr_string}
#define SSSCTL_CACHE_GPO_GUID    {_("Policy GUID"), SYSDB_GPO_GUID_ATTR, get_attr_string}
#define SSSCTL_CACHE_GPO_PATH    {_("Policy Path"), SYSDB_GPO_PATH_ATTR, get_attr_string}
#define SSSCTL_CACHE_GPO_TIMEOUT {_("Policy file timeout"), SYSDB_GPO_TIMEOUT_ATTR, get_attr_time}
#define SSSCTL_CACHE_GPO_VERSION {_("Policy version"), SYSDB_GPO_VERSION_ATTR, get_attr_string}
#define SSSCTL_CACHE_NULL   {NULL, NULL, NULL}

enum cache_object {
    CACHED_USER,
    CACHED_GROUP,
    CACHED_NETGROUP,
    CACHED_GPO,
};

typedef errno_t (*sssctl_attr_fn)(TALLOC_CTX *mem_ctx,
                                  struct sysdb_attrs *entry,
                                  struct sss_domain_info *dom,
                                  const char *attr,
                                  const char **_value);

typedef struct ldb_dn *(*sssctl_basedn_fn)(TALLOC_CTX *mem_ctx,
                                           struct sss_domain_info *domain);

struct sssctl_object_info {
    const char *msg;
    const char *attr;
    sssctl_attr_fn attr_fn;
};

static errno_t time_to_string(TALLOC_CTX *mem_ctx,
                              time_t timestamp,
                              const char **_value)
{
    const char *value;
    struct tm *tm;
    char str[255];
    size_t ret;

    tm = localtime(&timestamp);
    if (tm == NULL) {
        return ENOMEM;
    }

    ret = strftime(str, 255, "%x %X", tm);
    if (ret == 0) {
        return ERANGE;
    }

    value = talloc_strdup(mem_ctx, str);
    if (value == NULL) {
        return ENOMEM;
    }

    *_value = value;

    return EOK;
}

static errno_t get_attr_name(TALLOC_CTX *mem_ctx,
                             struct sysdb_attrs *entry,
                             struct sss_domain_info *dom,
                             const char *attr,
                             const char **_value)
{
    errno_t ret;
    const char *orig_name;
    char *tmp_name;
    char *outname;

    ret = sysdb_attrs_get_string(entry, attr, &orig_name);
    if (ret != EOK) {
        return ret;
    }

    tmp_name = sss_output_name(mem_ctx, orig_name, dom->case_preserve, 0);
    if (tmp_name == NULL) {
        return ENOMEM;
    }

    if (dom->fqnames) {
        outname = sss_tc_fqname(mem_ctx, dom->names, dom, tmp_name);
        talloc_free(tmp_name);
        if (outname == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "sss_tc_fqname() failed\n");
            return ENOMEM;
        }
    } else {
        outname = tmp_name;
    }

    *_value = outname;
    return EOK;
}

static errno_t get_attr_time(TALLOC_CTX *mem_ctx,
                             struct sysdb_attrs *entry,
                             struct sss_domain_info *dom,
                             const char *attr,
                             const char **_value)
{
    uint32_t value;
    errno_t ret;

    ret = sysdb_attrs_get_uint32_t(entry, attr, &value);
    if (ret != EOK) {
        return ret;
    }

    return time_to_string(mem_ctx, value, _value);
}

static errno_t get_attr_expire(TALLOC_CTX *mem_ctx,
                               struct sysdb_attrs *entry,
                               struct sss_domain_info *dom,
                               const char *attr,
                               const char **_value)
{
    uint32_t value;
    errno_t ret;

    ret = sysdb_attrs_get_uint32_t(entry, attr, &value);
    if (ret != EOK) {
        return ret;
    }

    if (is_files_provider(dom)) {
        *_value = "Never";
        return EOK;
    }

    if (value < time(NULL)) {
        *_value = "Expired";
        return EOK;
    }

    return time_to_string(mem_ctx, value, _value);
}

static errno_t get_attr_string(TALLOC_CTX *mem_ctx,
                                    struct sysdb_attrs *entry,
                                    struct sss_domain_info *dom,
                                    const char *attr, const char **_value)
{
    errno_t ret;
    const char *value;

    ret = sysdb_attrs_get_string(entry, attr, &value);
    if (ret == ENOENT) {
        value = "-";
    } else if (ret != EOK) {
        return ret;
    }

    *_value = value;

    return EOK;
}

static errno_t attr_initgr(TALLOC_CTX *mem_ctx,
                           struct sysdb_attrs *entry,
                           struct sss_domain_info *dom,
                           const char *attr,
                           const char **_value)
{
    uint32_t value;
    errno_t ret;

    ret = sysdb_attrs_get_uint32_t(entry, attr, &value);
    if (ret == ENOENT || (ret == EOK && value == 0)) {
        *_value = "Initgroups were not yet performed";
        return EOK;
    } else if (ret != EOK) {
        return ret;
    }

    if (is_files_provider(dom)) {
        *_value = "Never";
        return EOK;
    }

    if (value < time(NULL)) {
        *_value = "Expired";
        return EOK;
    }

    return time_to_string(mem_ctx, value, _value);
}

static errno_t get_attr_yesno(TALLOC_CTX *mem_ctx,
                              struct sysdb_attrs *entry,
                              struct sss_domain_info *dom,
                              const char *attr,
                              const char **_value)
{
    errno_t ret;
    bool val;

    ret = sysdb_attrs_get_bool(entry, attr, &val);
    if (ret == ENOENT) {
        val = 0;
    } else if (ret != EOK) {
        return ret;
    }

    *_value = val ? "Yes" : "No";

    return EOK;
}

static const char **sssctl_build_attrs(TALLOC_CTX *mem_ctx,
                                       struct sssctl_object_info *info)
{
    const char **attrs;
    size_t count;
    int i;

    for (count = 0; info[count].attr != NULL; count++) {
        /* no op */
    }

    attrs = talloc_zero_array(mem_ctx, const char *, count + 1);
    if (attrs == NULL) {
        return NULL;
    }

    for (i = 0; i < count; i++) {
        attrs[i] = talloc_strdup(attrs, info[i].attr);
        if (attrs[i] == NULL) {
            talloc_free(attrs);
            return NULL;
        }
    }

    return attrs;
}

static errno_t sssctl_query_cache(TALLOC_CTX *mem_ctx,
                                  struct sysdb_ctx *sysdb,
                                  struct ldb_dn *base_dn,
                                  const char *filter,
                                  const char **attrs,
                                  struct sysdb_attrs **_entry)
{
    TALLOC_CTX *tmp_ctx;
    struct sysdb_attrs **sysdb_attrs;
    struct ldb_message **msgs;
    size_t count;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        return ENOMEM;
    }

    ret = sysdb_search_entry(tmp_ctx, sysdb, base_dn, LDB_SCOPE_SUBTREE,
                             filter, attrs, &count, &msgs);
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, "No result\n");
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to search sysdb "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    if (count != 1) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Search returned more than one result!\n");
        ret = ERR_INTERNAL;
        goto done;
    }

    ret = sysdb_msg2attrs(tmp_ctx, count, msgs, &sysdb_attrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to convert message to sysdb attrs "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    *_entry = talloc_steal(mem_ctx, sysdb_attrs[0]);

done:
    talloc_free(tmp_ctx);
    return ret;
}

static const char *sssctl_create_filter(TALLOC_CTX *mem_ctx,
                                        struct sss_domain_info *dom,
                                        enum cache_object obj_type,
                                        const char *attr_name,
                                        const char *attr_value)
{
    const char *class;
    const char *filter;
    char *filter_value;
    bool qualify_attr = false;

    if (strcmp(attr_name, SYSDB_NAME) == 0) {
        if (obj_type == CACHED_USER || obj_type == CACHED_GROUP) {
            qualify_attr = true;
        }
    }

    switch (obj_type) {
    case CACHED_USER:
        class = SYSDB_USER_CLASS;
        break;
    case CACHED_GROUP:
        class = SYSDB_GROUP_CLASS;
        break;
    case CACHED_NETGROUP:
        class = SYSDB_NETGROUP_CLASS;
        break;
    case CACHED_GPO:
        class = SYSDB_GPO_OC;
        break;
    default:
        DEBUG(SSSDBG_FATAL_FAILURE,
              "sssctl doesn't handle this object type (type=%d)\n", obj_type);
        return NULL;
    }

    if (qualify_attr) {
        filter_value = sss_create_internal_fqname(NULL, attr_value, dom->name);
    } else {
        filter_value = talloc_strdup(NULL, attr_value);
    }
    if (filter_value == NULL) {
        return NULL;
    }

    if (obj_type == CACHED_GPO && strcmp(attr_name, SYSDB_GPO_GUID_ATTR) == 0) {
        char *filter_value_old;
        errno_t ret;

        filter_value_old = filter_value;
        ret = sysdb_gpo_canon_guid(filter_value, mem_ctx, &filter_value);
        talloc_free(filter_value_old);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Failed to canonicalize GPO GUID '%s': %s\n",
                  filter_value, strerror(ret));
            return NULL;
        }
    } else if (dom->case_sensitive == false) {
        char *filter_value_old;

        filter_value_old = filter_value;
        filter_value = sss_tc_utf8_str_tolower(mem_ctx, filter_value_old);
        talloc_free(filter_value_old);
    }

    filter = talloc_asprintf(mem_ctx, "(&(%s=%s)(|(%s=%s)(%s=%s)))",
                             (obj_type == CACHED_NETGROUP ||
                              obj_type == CACHED_GPO) ?
                                SYSDB_OBJECTCLASS : SYSDB_OBJECTCATEGORY,
                             class, attr_name, filter_value,
                             SYSDB_NAME_ALIAS, filter_value);

    talloc_free(filter_value);

    return filter;
}

static errno_t sssctl_find_object(TALLOC_CTX *mem_ctx,
                                  struct sss_domain_info *domains,
                                  struct sss_domain_info *domain,
                                  sssctl_basedn_fn basedn_fn,
                                  enum cache_object obj_type,
                                  const char *attr_name,
                                  const char *attr_value,
                                  const char **attrs,
                                  struct sysdb_attrs **_entry,
                                  struct sss_domain_info **_dom)
{
    TALLOC_CTX *tmp_ctx;
    struct sss_domain_info *dom;
    struct sysdb_attrs *entry = NULL;
    struct ldb_dn *base_dn;
    bool fqn_provided;
    const char *filter;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    dom = domain == NULL ? domains : domain;
    fqn_provided = domain == NULL ? false : true;
    while (dom != NULL) {
        if (!fqn_provided && dom->fqnames) {
            dom = get_next_domain(dom, 0);
            continue;
        }

        base_dn = basedn_fn(tmp_ctx, dom);
        if (base_dn == NULL) {
            ret = ENOMEM;
            goto done;
        }

        filter = sssctl_create_filter(tmp_ctx, dom, obj_type,
                                      attr_name, attr_value);
        if (filter == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create filter\n");
            ret = ENOMEM;
            goto done;
        }

        ret = sssctl_query_cache(tmp_ctx, dom->sysdb, base_dn, filter,
                                 attrs, &entry);
        switch(ret) {
        case EOK:
            /* Entry was found. */
            *_entry = talloc_steal(mem_ctx, entry);
            *_dom = dom;
            goto done;
        case ENOENT:
            if (fqn_provided) {
                /* Not found but a domain was provided in input. We're done. */
                goto done;
            }
            break;
        default:
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to query cache [%d]: %s\n",
                  ret, sss_strerror(ret));
            goto done;
        }

        dom = get_next_domain(dom, 0);
    }

    ret = ENOENT;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t sssctl_fetch_object(TALLOC_CTX *mem_ctx,
                                   struct sssctl_object_info *info,
                                   struct sss_domain_info *domains,
                                   struct sss_domain_info *domain,
                                   sssctl_basedn_fn basedn_fn,
                                   enum cache_object obj_type,
                                   const char *attr_name,
                                   const char *attr_value,
                                   struct sysdb_attrs **_entry,
                                   struct sss_domain_info **_dom)
{
    TALLOC_CTX *tmp_ctx;
    struct sysdb_attrs *entry = NULL;
    struct sss_domain_info *dom = NULL;
    const char **attrs;
    char *sanitized;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    ret = sss_filter_sanitize(tmp_ctx, attr_value, &sanitized);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to sanitize input [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    attrs = sssctl_build_attrs(tmp_ctx, info);
    if (attrs == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get attribute list!\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sssctl_find_object(tmp_ctx, domains, domain, basedn_fn,
                             obj_type, attr_name, sanitized, attrs,
                             &entry, &dom);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to query cache [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    *_entry = talloc_steal(mem_ctx, entry);
    *_dom = dom;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t sssctl_print_object(struct sssctl_object_info *info,
                                   struct sss_domain_info *domains,
                                   struct sss_domain_info *domain,
                                   sssctl_basedn_fn basedn_fn,
                                   const char *noent_fmt,
                                   enum cache_object obj_type,
                                   const char *attr_name,
                                   const char *attr_value)
{
    TALLOC_CTX *tmp_ctx;
    struct sysdb_attrs *entry = NULL;
    const char *value;
    errno_t ret;
    int i;
    struct sss_domain_info *dom = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    ret = sssctl_fetch_object(tmp_ctx, info, domains, domain, basedn_fn,
                              obj_type, attr_name, attr_value,
                              &entry, &dom);
    if (ret == ENOENT) {
        printf(noent_fmt, attr_value);
        ret = EOK;
        goto done;
    } else if (ret != EOK) {
        ERROR("Error: Unable to get object [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    if (dom == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not determine object domain\n");
        ret = ERR_DOMAIN_NOT_FOUND;
        goto done;
    }

    for (i = 0; info[i].attr != NULL; i++) {
        ret = info[i].attr_fn(tmp_ctx, entry, dom, info[i].attr, &value);
        if (ret == ENOENT) {
            continue;
        } else if (ret != EOK) {
            ERROR("%s: Unable to read value [%d]: %s\n",
                  info[i].msg, ret, sss_strerror(ret));
            continue;
        }

        printf("%s: %s\n", info[i].msg, value);
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t parse_cmdline(struct sss_cmdline *cmdline,
                             struct sss_tool_ctx *tool_ctx,
                             struct poptOption *options,
                             const char *extended_help,
                             const char **_orig_name,
                             struct sss_domain_info **_domain)
{
    const char *input_name = NULL;
    const char *orig_name;
    struct sss_domain_info *domain;
    int ret;

    ret = sss_tool_popt_ex(cmdline, options, extended_help,
                           SSS_TOOL_OPT_OPTIONAL,
                           NULL, NULL, "NAME", _("Specify name."),
                           SSS_TOOL_OPT_REQUIRED, &input_name, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command arguments\n");
        goto done;
    }

    ret = sss_tool_parse_name(tool_ctx, tool_ctx, input_name,
                              &orig_name, &domain);
    if (ret != EOK) {
        ERROR("Unable to parse name %s.\n", input_name);
        goto done;
    }

    *_orig_name = orig_name;
    *_domain = domain;

done:
    free(discard_const(input_name));

    return ret;
}

struct sssctl_cache_opts {
    struct sss_domain_info *domain;
    const char *value;
    int sid;
    int id;
    const char *guid;
};

errno_t sssctl_user_show(struct sss_cmdline *cmdline,
                         struct sss_tool_ctx *tool_ctx,
                         void *pvt)
{
    struct sssctl_cache_opts opts = {0};
    const char *attr;
    errno_t ret;

    struct poptOption options[] = {
        {"sid", 's', POPT_ARG_NONE , &opts.sid, 0, _("Search by SID"), NULL },
        {"uid", 'u', POPT_ARG_NONE, &opts.id, 0, _("Search by user ID"), NULL },
        POPT_TABLEEND
    };

    struct sssctl_object_info info[] = {
        SSSCTL_CACHE_NAME,
        SSSCTL_CACHE_CREATE,
        SSSCTL_CACHE_UPDATE,
        SSSCTL_CACHE_EXPIRE,
        {_("Initgroups expiration time"), SYSDB_INITGR_EXPIRE, attr_initgr},
        SSSCTL_CACHE_IFP,
        SSSCTL_CACHE_NULL
    };

    ret = parse_cmdline(cmdline, tool_ctx, options, NULL, &opts.value,
                        &opts.domain);
    if (ret != EOK) {
        return ret;
    }

    attr = SYSDB_NAME;
    if (opts.sid) {
        attr = SYSDB_SID;
    } else if (opts.id) {
        attr = SYSDB_UIDNUM;
    }

    ret = sssctl_print_object(info, tool_ctx->domains, opts.domain,
                              sysdb_user_base_dn, NOT_FOUND_MSG("User"),
                              CACHED_USER, attr, opts.value);
    if (ret != EOK) {
        return ret;
    }


    return EOK;
}

errno_t sssctl_group_show(struct sss_cmdline *cmdline,
                          struct sss_tool_ctx *tool_ctx,
                          void *pvt)
{
    struct sssctl_cache_opts opts = {0};
    const char *attr;
    errno_t ret;

    struct poptOption options[] = {
        {"sid", 's', POPT_ARG_NONE , &opts.sid, 0, _("Search by SID"), NULL },
        {"gid", 'g', POPT_ARG_NONE, &opts.id, 0, _("Search by group ID"), NULL },
        POPT_TABLEEND
    };

    struct sssctl_object_info info[] = {
        SSSCTL_CACHE_NAME,
        SSSCTL_CACHE_CREATE,
        SSSCTL_CACHE_UPDATE,
        SSSCTL_CACHE_EXPIRE,
        SSSCTL_CACHE_IFP,
        SSSCTL_CACHE_NULL
    };

    ret = parse_cmdline(cmdline, tool_ctx, options, NULL, &opts.value,
                        &opts.domain);
    if (ret != EOK) {
        return ret;
    }

    attr = SYSDB_NAME;
    if (opts.sid) {
        attr = SYSDB_SID;
    } else if (opts.id) {
        attr = SYSDB_GIDNUM;
    }

    ret = sssctl_print_object(info, tool_ctx->domains, opts.domain,
                              sysdb_group_base_dn, NOT_FOUND_MSG("Group"),
                              CACHED_GROUP, attr, opts.value);
    if (ret != EOK) {
        return ret;
    }


    return EOK;
}

errno_t sssctl_netgroup_show(struct sss_cmdline *cmdline,
                             struct sss_tool_ctx *tool_ctx,
                             void *pvt)
{
    struct sssctl_cache_opts opts = {0};
    errno_t ret;

    struct sssctl_object_info info[] = {
        SSSCTL_CACHE_NAME,
        SSSCTL_CACHE_CREATE,
        SSSCTL_CACHE_UPDATE,
        SSSCTL_CACHE_EXPIRE,
        SSSCTL_CACHE_NULL
    };

    ret = parse_cmdline(cmdline, tool_ctx, NULL, NULL, &opts.value,
                        &opts.domain);
    if (ret != EOK) {
        return ret;
    }

    ret = sssctl_print_object(info, tool_ctx->domains, opts.domain,
                              sysdb_netgroup_base_dn, NOT_FOUND_MSG("Netgroup"),
                              CACHED_NETGROUP, SYSDB_NAME, opts.value);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

errno_t sssctl_gpo_show(struct sss_cmdline *cmdline,
                        struct sss_tool_ctx *tool_ctx,
                        void *pvt)
{
    struct sssctl_cache_opts opts = {0};
    const char *attr;
    errno_t ret;
    const char *extended_help =
        "This command requires the domain name to be given because the "
        "same policy name (or GUID) might exists in different domains.\nE.g.:\n"
        "  'Default Domain Policy'@one.test\n"
        "  'Default Domain Policy'@two.test";

    struct sssctl_object_info info[] = {
        SSSCTL_CACHE_GPO_NAME,
        SSSCTL_CACHE_GPO_GUID,
        SSSCTL_CACHE_GPO_PATH,
        SSSCTL_CACHE_GPO_VERSION,
        SSSCTL_CACHE_GPO_TIMEOUT,
        SSSCTL_CACHE_NULL
    };

    struct poptOption options[] = {
        {"guid", 'g', POPT_ARG_NONE, &opts.guid, 0, _("Search by GPO guid"), NULL },
        POPT_TABLEEND
    };

    ret = parse_cmdline(cmdline, tool_ctx, options, extended_help, &opts.value,
                        &opts.domain);
    if (ret != EOK) {
        ERROR("Failed to parse command line: %s\n", sss_strerror(ret));
        return ret;
    }

    if (opts.domain == NULL) {
        ERROR("%s\n", extended_help);
        return EINVAL;
    }

    attr = SYSDB_NAME;
    if (opts.guid) {
        attr = SYSDB_GPO_GUID_ATTR;
    }

    ret = sssctl_print_object(info, tool_ctx->domains, opts.domain,
                              sysdb_gpos_base_dn, NOT_FOUND_MSG("GPO"),
                              CACHED_GPO, attr, opts.value);
    if (ret != EOK) {
        ERROR("Failed to print object: %s\n", sss_strerror(ret));
        return ret;
    }

    return EOK;
}

typedef errno_t (*sssctl_gpo_traverse_func)(struct sss_domain_info *,
                                            struct sssctl_object_info *,
                                            struct sysdb_attrs *,
                                            void *);

static int sssctl_gpo_traverse(TALLOC_CTX *mem_ctx,
                               const char *domain_prompt,
                               struct sss_domain_info *domains,
                               sssctl_gpo_traverse_func fn,
                               void *private_data)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct sssctl_object_info info[] = {
        SSSCTL_CACHE_GPO_NAME,
        SSSCTL_CACHE_GPO_GUID,
        SSSCTL_CACHE_GPO_PATH,
        SSSCTL_CACHE_NULL
    };
    struct sss_domain_info *dom = NULL;
    const char **attrs = NULL;
    const char *filter = NULL;
    errno_t ret;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        ERROR("talloc failed\n");
        return ENOMEM;
    }

    attrs = sssctl_build_attrs(tmp_ctx, info);
    if (attrs == NULL) {
        ERROR("Unable to get attribute list!\n");
        ret = ENOMEM;
        goto done;
    }

    filter = talloc_asprintf(tmp_ctx, "(%s=%s)", SYSDB_OBJECTCLASS, SYSDB_GPO_OC);
    if (filter == NULL) {
        ERROR("Unable to create filter\n");
        ret = ENOMEM;
        goto done;
    }

    for (dom = domains; dom != NULL;
         dom = get_next_domain(dom, SSS_GND_DESCEND)) {
        struct ldb_message **msgs = NULL;
        struct sysdb_attrs **sysdb_attrs = NULL;
        struct ldb_dn *base_dn = NULL;
        size_t count;

        if (domain_prompt != NULL) {
            PRINT("%s [%s]:\n", domain_prompt, dom->name);
        }

        base_dn = sysdb_gpos_base_dn(tmp_ctx, dom);
        if (base_dn == NULL) {
            ERROR("Unable to get GPOs base DN\n");
            ret = ENOMEM;
            goto done;
        }

        ret = sysdb_search_entry(tmp_ctx, dom->sysdb, base_dn, LDB_SCOPE_SUBTREE,
                                 filter, attrs, &count, &msgs);
        if (ret == ENOENT) {
            continue;
        } else if (ret != EOK) {
            ERROR("Unable to search sysdb: %s\n", sss_strerror(ret));
            goto done;
        }

        ret = sysdb_msg2attrs(tmp_ctx, count, msgs, &sysdb_attrs);
        if (ret != EOK) {
            ERROR("Unable to convert message to sysdb attrs: %s\n", sss_strerror(ret));
            goto done;
        }
        TALLOC_FREE(msgs);

        for (size_t i = 0; i < count; i++) {
            struct sysdb_attrs *entry = sysdb_attrs[i];

            if (fn) {
                ret = fn(dom, info, entry, private_data);
                if (ret != EOK) {
                    break;
                }
            }
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t sssctl_gpo_print(struct sss_domain_info *dom,
                                struct sssctl_object_info *info,
                                struct sysdb_attrs *entry,
                                void *private_data)
{
    TALLOC_CTX *tmp_ctx = NULL;
    const char *value = NULL;
    errno_t ret;

    tmp_ctx = talloc_new(entry);
    if (tmp_ctx == NULL) {
        ERROR("talloc failed\n");
        return ENOMEM;
    }

    for (size_t j = 0; info[j].attr != NULL; j++) {
        ret = info[j].attr_fn(tmp_ctx, entry, dom, info[j].attr, &value);
        if (ret == ENOENT) {
            continue;
        } else if (ret != EOK) {
            ERROR("%s: Unable to read value [%d]: %s\n",
                  info[j].msg, ret, sss_strerror(ret));
            goto done;
        }
        PRINT("\t%s: %s\n", info[j].msg, value);
    }
    PRINT("\n");
    ret = EOK;
done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t sssctl_gpo_list(struct sss_cmdline *cmdline,
                        struct sss_tool_ctx *tool_ctx,
                        void *pvt)
{
    TALLOC_CTX *tmp_ctx = NULL;
    const char *domain_prompt = NULL;
    errno_t ret;

    tmp_ctx = talloc_new(tool_ctx);
    if (tmp_ctx == NULL) {
        ERROR("talloc failed\n");
        return ENOMEM;
    }

    domain_prompt = talloc_strdup(tmp_ctx, "Cached GPOs in domain");
    if (domain_prompt == NULL) {
        ERROR("talloc failed\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sssctl_gpo_traverse(tmp_ctx, domain_prompt, tool_ctx->domains,
                              sssctl_gpo_print, NULL);
done:
    talloc_free(tmp_ctx);

    return ret;
}

static bool confirm(const char *prompt)
{
    char str[5];

    fprintf(stdout, "%s [y/n]\n", prompt);
    fflush(stdout);

    if (fgets(str, sizeof(str), stdin) == NULL) {
        return false;
    }

    if (str[strlen(str) - 1] == '\n') {
        str[strlen(str) - 1] = '\0';
    }

    if (strcmp(str, "y") == 0 || strcmp(str, "yes") == 0) {
        return true;
    }

    fprintf(stdout, "Aborted.\n");
    fflush(stdout);

    return false;
}

static errno_t sssctl_gpo_remove_entry(TALLOC_CTX *mem_ctx,
                                       struct sss_domain_info *dom,
                                       struct sysdb_attrs *entry,
                                       bool ask_for_confirm)
{
    TALLOC_CTX *tmp_ctx = NULL;
    const char *gpo_name = NULL;
    const char *gpo_guid = NULL;
    const char *gpo_path = NULL;
    char gpo_cache_realpath[PATH_MAX];
    char gpo_realpath[PATH_MAX];
    char *prompt = NULL;
    errno_t ret;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        ERROR("talloc failed\n");
        return ENOMEM;
    }

    ret = get_attr_string(tmp_ctx, entry, dom, SYSDB_GPO_GUID_ATTR, &gpo_guid);
    if (ret != EOK) {
        ERROR("Could not find GUID attribute from GPO entry\n");
        ret = ENOENT;
        goto done;
    }

    ret = get_attr_string(tmp_ctx, entry, dom, SYSDB_NAME, &gpo_name);
    if (ret != EOK) {
        ERROR("Could not find description attribute from GPO entry\n");
        ret = ENOENT;
        goto done;
    }

    if (ask_for_confirm) {
        prompt = talloc_asprintf(tmp_ctx,
                                 "About to delete GPO entry named [%s] with GUID "
                                 "[%s] from database. Proceed?",
                                 gpo_name, gpo_guid);
        if (prompt == NULL) {
            ERROR("talloc failed\n");
            ret = ENOMEM;
            goto done;
        }

        if (!confirm(prompt)) {
            ret = EOK;
            goto done;
        }
    }

    ret = sysdb_gpo_delete_gpo_by_guid(tmp_ctx, dom, gpo_guid);
    if (ret != EOK) {
        ERROR("Could not delete GPO entry from cache\n");
        goto done;
    }

    ret = sysdb_attrs_get_string(entry, SYSDB_GPO_PATH_ATTR, &gpo_path);
    if (ret == ENOENT) {
        PRINT("The GPO path was not yet stored in cache. Please remove files "
              "manually from [%s]\n", GPO_CACHE_PATH);
        goto done;
    } else if (ret != EOK) {
        return ret;
    }

    if (realpath(gpo_path, gpo_realpath) == NULL) {
        ret = errno;
        ERROR("Could not determine real path for [%s]: %s\n", gpo_path, strerror(ret));
        goto done;
    }

    if (realpath(GPO_CACHE_PATH, gpo_cache_realpath) == NULL) {
        ret = errno;
        ERROR("Could not determine real path for [%s]: %s\n", GPO_CACHE_PATH, strerror(ret));
        goto done;
    }

    if (strncmp(gpo_realpath, gpo_cache_realpath, strlen(gpo_cache_realpath)) != 0) {
        ERROR("The cached GPO path [%s] is not under [%s], ignoring.\n",
              gpo_realpath, gpo_cache_realpath);
        ret = EOK;
        goto done;
    }

    if (ask_for_confirm) {
        prompt = talloc_asprintf(tmp_ctx,
                                 "About to recursively delete GPO downloaded "
                                 "files [%s]. Proceed?",
                                 gpo_path);
        if (prompt == NULL) {
            ERROR("talloc failed\n");
            ret = ENOMEM;
            goto done;
        }

        if (!confirm(prompt)) {
            ret = EOK;
            goto done;
        }
    }

    ret = sss_remove_tree(gpo_path);
    if (ret != EOK) {
        ERROR("Unable to remove downloaded GPO files: %s\n", sss_strerror(ret));
        goto done;
    }

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t sssctl_gpo_remove(struct sss_cmdline *cmdline,
                          struct sss_tool_ctx *tool_ctx,
                          void *pvt)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct sssctl_cache_opts opts = {0};
    const char *attr;
    errno_t ret;
    struct sssctl_object_info info[] = {
        SSSCTL_CACHE_GPO_NAME,
        SSSCTL_CACHE_GPO_GUID,
        SSSCTL_CACHE_GPO_PATH,
        SSSCTL_CACHE_GPO_VERSION,
        SSSCTL_CACHE_GPO_TIMEOUT,
        SSSCTL_CACHE_NULL
    };
    struct sysdb_attrs *entry = NULL;
    struct sss_domain_info *dom = NULL;
    struct poptOption options[] = {
        {"guid", 'g', POPT_ARG_NONE, &opts.guid, 0, _("Search by GPO guid"), NULL },
        POPT_TABLEEND
    };
    const char *extended_help =
        "This command requires the domain name to be given because the "
        "same policy name (or GUID) might exists in different domains.\nE.g.:\n"
        "  'Default Domain Policy'@one.test\n"
        "  'Default Domain Policy'@two.test";

    tmp_ctx = talloc_new(tool_ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = parse_cmdline(cmdline, tool_ctx, options, extended_help, &opts.value,
                        &opts.domain);
    if (ret != EOK) {
        ERROR("Failed to parse command line: %s\n", sss_strerror(ret));
        goto done;
    }

    if (opts.domain == NULL) {
        ERROR("%s\n", extended_help);
        return EINVAL;
    }

    attr = SYSDB_NAME;
    if (opts.guid) {
        attr = SYSDB_GPO_GUID_ATTR;
    }

    ret = sssctl_fetch_object(tmp_ctx, info, tool_ctx->domains, opts.domain,
                              sysdb_gpos_base_dn, CACHED_GPO, attr, opts.value,
                              &entry, &dom);
    if (ret == ENOENT) {
        PRINT(NOT_FOUND_MSG("GPO"), opts.value);
        ret = EOK;
        goto done;
    } else if (ret != EOK) {
        ERROR("Failed to fetch cache entry: %s\n", sss_strerror(ret));
        goto done;
    }

    if (dom == NULL) {
        ERROR("Could not determine object domain\n");
        ret = ERR_DOMAIN_NOT_FOUND;
        goto done;
    }

    ret = sssctl_gpo_remove_entry(tmp_ctx, dom, entry, true);

done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t sssctl_gpo_traverse_remove(struct sss_domain_info *dom,
                                          struct sssctl_object_info *info,
                                          struct sysdb_attrs *entry,
                                          void *private_data)
{
    TALLOC_CTX *tmp_ctx = NULL;
    const char *gpo_guid = NULL;
    errno_t ret;

    tmp_ctx = talloc_new(entry);
    if (tmp_ctx == NULL) {
        ERROR("talloc failed\n");
        return ENOMEM;
    }

    ret = get_attr_string(tmp_ctx, entry, dom, SYSDB_GPO_GUID_ATTR, &gpo_guid);
    if (ret != EOK) {
        ERROR("Could not find GUID attribute in GPO entry\n");
        goto done;
    }

    ret = sssctl_gpo_remove_entry(tmp_ctx, dom, entry, false);
    if (ret != EOK) {
        ERROR("Failed to delete GPO: %s\n", sss_strerror(ret));
        ret = EOK;
        goto done;
    }
    PRINT("%s removed from cache\n", gpo_guid);

    ret = EOK;
done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t sssctl_gpo_purge(struct sss_cmdline *cmdline,
                         struct sss_tool_ctx *tool_ctx,
                         void *pvt)
{
    TALLOC_CTX *tmp_ctx = NULL;
    const char *domain_prompt = NULL;
    const char *prompt = NULL;
    errno_t ret;

    tmp_ctx = talloc_new(tool_ctx);
    if (tmp_ctx == NULL) {
        ERROR("talloc failed\n");
        return ENOMEM;
    }

    domain_prompt = talloc_strdup(tmp_ctx, "Removing GPOs from domain");
    if (domain_prompt == NULL) {
        ERROR("talloc failed\n");
        ret = ENOMEM;
        goto done;
    }

    prompt = talloc_asprintf(tmp_ctx,
        "About to delete all cached GPO entries from the database and their "
        "associated downloaded files. Proceed?");
    if (prompt == NULL) {
        ERROR("talloc failed\n");
        ret = ENOMEM;
        goto done;
    }

    if (!confirm(prompt)) {
        ret = EOK;
        goto done;
    }

    ret = sssctl_gpo_traverse(tmp_ctx, domain_prompt, tool_ctx->domains,
                              sssctl_gpo_traverse_remove, NULL);
done:
    talloc_free(tmp_ctx);

    return ret;
}
