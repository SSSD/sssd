/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2015 Red Hat

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

#include <stdlib.h>

#include "util/util.h"
#include "util/crypto/sss_crypto.h"
#include "db/sysdb.h"
#include "tools/common/sss_tools.h"
#include "tools/common/sss_colondb.h"

#define LOCALVIEW SYSDB_LOCAL_VIEW_NAME
#define ORIGNAME "originalName"

struct override_user {
    const char *input_name;
    const char *orig_name;
    const char *sysdb_name;
    struct sss_domain_info *domain;

    const char *name;
    uid_t uid;
    gid_t gid;
    const char *home;
    const char *shell;
    const char *gecos;
    const char *cert;
};

struct override_group {
    const char *input_name;
    const char *orig_name;
    const char *sysdb_name;
    struct sss_domain_info *domain;

    const char *name;
    gid_t gid;
};

static errno_t parse_cmdline(struct sss_cmdline *cmdline,
                             struct sss_tool_ctx *tool_ctx,
                             struct poptOption *options,
                             const char **_input_name,
                             const char **_orig_name,
                             struct sss_domain_info **_domain)
{
    enum sss_tool_opt require;
    const char *input_name = NULL;
    const char *orig_name;
    struct sss_domain_info *domain;
    errno_t ret;

    *_input_name = NULL;
    require = options == NULL ? SSS_TOOL_OPT_OPTIONAL : SSS_TOOL_OPT_REQUIRED;

    ret = sss_tool_popt_ex(cmdline, options, NULL, require,
                           NULL, NULL, "NAME", _("Specify name."),
                           SSS_TOOL_OPT_REQUIRED, &input_name, NULL);
    if (ret != EXIT_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command arguments\n");
        return ret;
    }

    ret = sss_tool_parse_name(tool_ctx, tool_ctx, input_name,
                              &orig_name, &domain);
    if (ret != EOK) {
        ERROR("Unable to parse name %s.\n", input_name);
        free(discard_const(input_name));
        return ret;
    }

    *_input_name = input_name;
    *_orig_name = orig_name;
    *_domain = domain;

    return EXIT_SUCCESS;
}

static errno_t parse_cmdline_user_add(struct sss_cmdline *cmdline,
                                      struct sss_tool_ctx *tool_ctx,
                                      struct override_user *user)
{
    struct poptOption options[] = {
        {"name", 'n', POPT_ARG_STRING, &user->name, 0, _("Override name"), NULL },
        {"uid", 'u', POPT_ARG_INT, &user->uid, 0, _("Override uid (non-zero value)"), NULL },
        {"gid", 'g', POPT_ARG_INT, &user->gid, 0, _("Override gid (non-zero value)"), NULL },
        {"home", 'h', POPT_ARG_STRING, &user->home, 0, _("Override home directory"), NULL },
        {"shell", 's', POPT_ARG_STRING, &user->shell, 0, _("Override shell"), NULL },
        {"gecos", 'c', POPT_ARG_STRING, &user->gecos, 0, _("Override gecos"), NULL },
        {"certificate", 'x', POPT_ARG_STRING, &user->cert, 0, _("Override certificate"), NULL },
        POPT_TABLEEND
    };

    return parse_cmdline(cmdline, tool_ctx, options, &user->input_name,
                         &user->orig_name, &user->domain);
}

static errno_t parse_cmdline_user_del(struct sss_cmdline *cmdline,
                                      struct sss_tool_ctx *tool_ctx,
                                      struct override_user *user)
{
    return parse_cmdline(cmdline, tool_ctx, NULL, &user->input_name,
                         &user->orig_name, &user->domain);
}

static errno_t parse_cmdline_user_show(struct sss_cmdline *cmdline,
                                       struct sss_tool_ctx *tool_ctx,
                                       struct override_user *user)
{
    return parse_cmdline(cmdline, tool_ctx, NULL, &user->input_name,
                         &user->orig_name, &user->domain);
}

static errno_t parse_cmdline_group_add(struct sss_cmdline *cmdline,
                                       struct sss_tool_ctx *tool_ctx,
                                       struct override_group *group)
{
    struct poptOption options[] = {
        {"name", 'n', POPT_ARG_STRING, &group->name, 0, _("Override name"), NULL },
        {"gid", 'g', POPT_ARG_INT, &group->gid, 0, _("Override gid"), NULL },
        POPT_TABLEEND
    };

    return parse_cmdline(cmdline, tool_ctx, options, &group->input_name,
                         &group->orig_name, &group->domain);
}

static errno_t parse_cmdline_group_del(struct sss_cmdline *cmdline,
                                       struct sss_tool_ctx *tool_ctx,
                                       struct override_group *group)
{
    return parse_cmdline(cmdline, tool_ctx, NULL, &group->input_name,
                         &group->orig_name, &group->domain);
}

static errno_t parse_cmdline_group_show(struct sss_cmdline *cmdline,
                                        struct sss_tool_ctx *tool_ctx,
                                        struct override_group *group)
{
    return parse_cmdline(cmdline, tool_ctx, NULL, &group->input_name,
                         &group->orig_name, &group->domain);
}

static errno_t parse_cmdline_find(struct sss_cmdline *cmdline,
                                  struct sss_tool_ctx *tool_ctx,
                                  struct sss_domain_info **_dom)
{
    struct sss_domain_info *dom;
    const char *domname = NULL;
    errno_t ret;
    struct poptOption options[] = {
        {"domain", 'd', POPT_ARG_STRING | POPT_ARGFLAG_OPTIONAL,
            &domname, 0, _("Domain name"), NULL },
        POPT_TABLEEND
    };

    ret = sss_tool_popt_ex(cmdline, options, NULL, SSS_TOOL_OPT_OPTIONAL,
                           NULL, NULL, NULL, NULL, SSS_TOOL_OPT_REQUIRED,
                           NULL, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command arguments\n");
        return ret;
    }

    if (domname == NULL) {
        *_dom = NULL;
        return EOK;
    }

    dom = find_domain_by_name(tool_ctx->domains, domname, true);
    if (dom == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to find domain %s\n", domname);
        ERROR("Unable to find domain %s\n", domname);
        return EINVAL;
    }

    *_dom = dom;

    return EOK;
}

static errno_t parse_cmdline_import(struct sss_cmdline *cmdline,
                                    const char **_file)
{
    errno_t ret;

    ret = sss_tool_popt_ex(cmdline, NULL, NULL, SSS_TOOL_OPT_OPTIONAL,
                           NULL, NULL, "FILE", "File to import the data from.",
                           SSS_TOOL_OPT_REQUIRED, _file, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command arguments\n");
        return ret;
    }

    return EOK;
}

static errno_t parse_cmdline_export(struct sss_cmdline *cmdline,
                                    const char **_file)
{
    errno_t ret;

    ret = sss_tool_popt_ex(cmdline, NULL, NULL, SSS_TOOL_OPT_OPTIONAL,
                           NULL, NULL, "FILE", "File to export the data to.",
                           SSS_TOOL_OPT_REQUIRED, _file, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command arguments\n");
        return ret;
    }

    return EOK;
}

static errno_t prepare_view(struct sss_domain_info *domain)
{
    char *viewname = NULL;
    errno_t ret;

    ret = sysdb_get_view_name(NULL, domain->sysdb, &viewname);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_get_view_name() failed.\n");
        return ret;
    }

    if (ret == EOK) {
        if (is_local_view(viewname)) {
            DEBUG(SSSDBG_TRACE_FUNC, "%s view is already present.\n", viewname);
            ret = EOK;
            goto done;
        } else if (viewname != NULL) {
            DEBUG(SSSDBG_MINOR_FAILURE, "There already exists view %s. "
                  "Only one view is supported. Nothing to do.\n", viewname);
            ret = EEXIST;
            goto done;
        }
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Creating %s view.\n", LOCALVIEW);

    ret = sysdb_update_view_name(domain->sysdb, LOCALVIEW);
    if (ret == EOK) {
        printf("SSSD needs to be restarted for the changes to take effect.\n");
    }

done:
    talloc_free(viewname);
    return ret;
}

errno_t prepare_view_msg(struct sss_domain_info *domain)
{
    errno_t ret;

    ret = prepare_view(domain);
    if (ret == EEXIST) {
        ERROR("Other than " LOCALVIEW " view already exists "
              "in domain %s.\n", domain->name);
    } else if (ret != EOK) {
        ERROR("Unable to prepare " LOCALVIEW
              " view in domain %s.\n", domain->name);
    }

    return ret;
}

static char *build_anchor(TALLOC_CTX *mem_ctx, const char *obj_dn)
{
    char *anchor;
    char *safe_dn;
    errno_t ret;

    ret = sysdb_dn_sanitize(mem_ctx, obj_dn, &safe_dn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_dn_sanitize() failed\n");
        return NULL;
    }

    anchor = talloc_asprintf(mem_ctx, ":%s:%s", LOCALVIEW, safe_dn);

    talloc_free(safe_dn);

    return anchor;
}

static struct sysdb_attrs *build_attrs(TALLOC_CTX *mem_ctx,
                                       struct sss_domain_info *dom,
                                       const char *name,
                                       uid_t uid,
                                       gid_t gid,
                                       const char *home,
                                       const char *shell,
                                       const char *gecos,
                                       const char *cert)
{
    struct sysdb_attrs *attrs;
    errno_t ret;
    char *fqname;

    attrs = sysdb_new_attrs(mem_ctx);
    if (attrs == NULL) {
        return NULL;
    }

    if (name != NULL) {
        fqname = sss_create_internal_fqname(attrs, name, dom->name);
        if (fqname == NULL) {
            return NULL;
        }

        ret = sysdb_attrs_add_string(attrs, SYSDB_NAME, fqname);
        talloc_free(fqname);
        if (ret != EOK) {
            goto done;
        }
    }

    if (uid != 0) {
        ret = sysdb_attrs_add_uint32(attrs, SYSDB_UIDNUM, uid);
        if (ret != EOK) {
            goto done;
        }
    }

    if (gid != 0) {
        ret = sysdb_attrs_add_uint32(attrs, SYSDB_GIDNUM, gid);
        if (ret != EOK) {
            goto done;
        }
    }

    if (home != NULL) {
        ret = sysdb_attrs_add_string(attrs, SYSDB_HOMEDIR, home);
        if (ret != EOK) {
            goto done;
        }
    }

    if (shell != NULL) {
        ret = sysdb_attrs_add_string(attrs, SYSDB_SHELL, shell);
        if (ret != EOK) {
            goto done;
        }
    }

    if (gecos != NULL) {
        ret = sysdb_attrs_add_string(attrs, SYSDB_GECOS, gecos);
        if (ret != EOK) {
            goto done;
        }
    }

    if (cert != NULL) {
        ret = sysdb_attrs_add_base64_blob(attrs, SYSDB_USER_CERT, cert);
        if (ret != EOK) {
            goto done;
        }
    }

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(attrs);
        return NULL;
    }

    return attrs;
}

static struct sysdb_attrs *build_user_attrs(TALLOC_CTX *mem_ctx,
                                            struct override_user *user)
{
    return build_attrs(mem_ctx, user->domain, user->name, user->uid, user->gid,
                       user->home, user->shell, user->gecos, user->cert);
}

static struct sysdb_attrs *build_group_attrs(TALLOC_CTX *mem_ctx,
                                             struct override_group *group)
{
    return build_attrs(mem_ctx, group->domain, group->name, 0, group->gid,
                       0, NULL, NULL, NULL);
}

static char *get_fqname(TALLOC_CTX *mem_ctx,
                        struct sss_domain_info *domain,
                        const char *name)
{
    char *fqname = NULL;
    char *dummy_domain = NULL;
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    char *shortname;
    struct sss_domain_info *dom;

    if (domain == NULL || domain->names == NULL) {
        return NULL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return NULL;
    }

    /* the name stored in sysdb already contains the lowercased domain */
    ret = sss_parse_internal_fqname(tmp_ctx, name, &shortname, &dummy_domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "sss_parse_internal_fqname failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    dom = find_domain_by_name(get_domains_head(domain), dummy_domain, true);
    if (dom == NULL) {
        goto done;
    }

    /* Get length. */
    fqname = sss_tc_fqname(mem_ctx, dom->names, dom, shortname);
done:
    talloc_free(tmp_ctx);
    return fqname;
}

static char *get_sysname(TALLOC_CTX *mem_ctx,
                         struct sss_domain_info *domain,
                         const char *name)
{
    if (domain == NULL || !domain->fqnames) {
        return talloc_strdup(mem_ctx, name);
    }

    return sss_tc_fqname(mem_ctx, domain->names, domain, name);
}

static struct sss_domain_info *
get_object_domain(enum sysdb_member_type type,
                  const char *name,
                  struct sss_domain_info *domain,
                  struct sss_domain_info *domains)
{
    TALLOC_CTX *tmp_ctx;
    struct sss_domain_info *dom = NULL;
    struct ldb_result *res;
    const char *strtype;
    char *sysname;
    char *fqname = NULL;
    bool check_next;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return NULL;
    }

    sysname = get_sysname(tmp_ctx, domain, name);
    if (sysname == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Ensure that the object is in cache. */
    switch (type) {
    case SYSDB_MEMBER_USER:
        if (getpwnam(sysname) == NULL) {
            ret = ENOENT;
            goto done;
        }
        break;
    case SYSDB_MEMBER_GROUP:
        if (getgrnam(sysname) == NULL) {
            ret = ENOENT;
            goto done;
        }
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Unsupported member type %d\n", type);
        ret = ERR_INTERNAL;
        goto done;
    }

    /* Find domain if it is unknown. */
    if (domain == NULL) {
        check_next = true;
        dom = domains;
    } else {
        check_next = false;
        dom = domain;
    }

    do {
        talloc_zfree(fqname);
        fqname = sss_create_internal_fqname(tmp_ctx, name, dom->name);
        if (fqname == NULL) {
            ret = ENOMEM;
            goto done;
        }

        switch (type) {
        case SYSDB_MEMBER_USER:
            DEBUG(SSSDBG_TRACE_FUNC, "Trying to find user %s@%s\n",
                  name, dom->name);
            ret = sysdb_getpwnam(tmp_ctx, dom, fqname, &res);
            strtype = "user";
            break;
        case SYSDB_MEMBER_GROUP:
            DEBUG(SSSDBG_TRACE_FUNC, "Trying to find group %s@%s\n",
                  name, dom->name);
            ret = sysdb_getgrnam(tmp_ctx, dom, fqname, &res);
            strtype = "group";
            break;
        default:
            DEBUG(SSSDBG_CRIT_FAILURE, "Unsupported member type %d\n", type);
            ret = ERR_INTERNAL;
            goto done;
        }

        if (ret == EOK && res->count == 0) {
            ret = ENOENT;

            if (check_next) {
                dom = dom->next;
                continue;
            }
        }

        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to find %s %s@%s [%d]: %s\n",
                  strtype, name, dom->name, ret, sss_strerror(ret));
            goto done;
        } else if (res->count != 1) {
            DEBUG(SSSDBG_CRIT_FAILURE, "More than one %s found?\n", strtype);
            ret = ERR_INTERNAL;
            goto done;
        }

        check_next = false;
    } while (check_next && dom != NULL);

    if (dom == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No domain match for %s\n", name);
        ret = ENOENT;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Domain of %s %s is %s\n",
          strtype, name, dom->name);

done:
    talloc_free(tmp_ctx);

    if (ret != EOK) {
        return NULL;
    }

    return dom;
}

static errno_t get_user_domain_msg(struct sss_tool_ctx *tool_ctx,
                                   struct override_user *user)
{
    struct sss_domain_info *newdom;
    const char *domname;

    newdom = get_object_domain(SYSDB_MEMBER_USER, user->orig_name,
                               user->domain, tool_ctx->domains);
    if (newdom == NULL) {
        domname = user->domain == NULL ? "[unknown]" : user->domain->name;
        ERROR("Unable to find user %s@%s.\n", user->orig_name, domname);
        return ENOENT;
    }

    user->sysdb_name = sss_create_internal_fqname(tool_ctx, user->orig_name,
                                                  newdom->name);
    if (user->sysdb_name == NULL) {
        return ENOMEM;
    }

    user->domain = newdom;
    return EOK;
}

static errno_t get_group_domain_msg(struct sss_tool_ctx *tool_ctx,
                                    struct override_group *group)
{
    struct sss_domain_info *newdom;
    const char *domname;

    newdom = get_object_domain(SYSDB_MEMBER_GROUP, group->orig_name,
                               group->domain, tool_ctx->domains);
    if (newdom == NULL) {
        domname = group->domain == NULL ? "[unknown]" : group->domain->name;
        ERROR("Unable to find group %s@%s.\n", group->orig_name, domname);
        return ENOENT;
    }

    group->sysdb_name = sss_create_internal_fqname(tool_ctx, group->orig_name,
                                                   newdom->name);
    if (group->sysdb_name == NULL) {
        return ENOMEM;
    }

    group->domain = newdom;
    return EOK;
}

static errno_t get_object_dn(TALLOC_CTX *mem_ctx,
                             struct sss_domain_info *domain,
                             enum sysdb_member_type type,
                             const char *name,
                             struct ldb_dn **_ldb_dn,
                             const char **_str_dn)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *ldb_dn;
    const char *str_dn;
    errno_t ret;
    struct ldb_result *res;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    switch (type) {
    case SYSDB_MEMBER_USER:
        ret = sysdb_getpwnam(tmp_ctx, domain, name, &res);
        break;
    case SYSDB_MEMBER_GROUP:
        ret = sysdb_getgrnam(tmp_ctx, domain, name, &res);
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Unsupported member type %d\n", type);
        ret = ERR_INTERNAL;
        goto done;
    }

    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to look up original object in cache.\n");
        goto done;
    }

    if (res->count == 0) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Original object not found in cache.\n");
        ret = ENOENT;
        goto done;
    } else if (res->count > 1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "There are multiple object with name [%s] in the cache.\n", name);
        ret = EINVAL;
        goto done;
    }

    ldb_dn = res->msgs[0]->dn;

    if (ldb_dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (_str_dn != NULL) {
        str_dn = talloc_strdup(tmp_ctx, ldb_dn_get_linearized(ldb_dn));
        if (str_dn == NULL) {
            ret = ENOMEM;
            goto done;
        }

        *_str_dn = talloc_steal(mem_ctx, str_dn);
    }

    if (_ldb_dn != NULL) {
        *_ldb_dn = talloc_steal(mem_ctx, ldb_dn);
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t override_object_add(struct sss_domain_info *domain,
                                   enum sysdb_member_type type,
                                   struct sysdb_attrs *attrs,
                                   const char *name)
{
    TALLOC_CTX *tmp_ctx;
    const char *anchor;
    struct ldb_dn *ldb_dn;
    const char *str_dn;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = get_object_dn(tmp_ctx, domain, type, name, &ldb_dn, &str_dn);
    if (ret != EOK) {
        goto done;
    }

    anchor = build_anchor(tmp_ctx, str_dn);
    if (anchor == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_OVERRIDE_ANCHOR_UUID, anchor);
    if (ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Creating override for %s\n", str_dn);

    ret = sysdb_store_override(domain, NULL, NULL, LOCALVIEW, type, attrs, ldb_dn);

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t override_fqn(TALLOC_CTX *mem_ctx,
                            struct sss_tool_ctx *tool_ctx,
                            struct sss_domain_info *domain,
                            const char *input,
                            const char **_name)
{
    struct sss_domain_info *dom;
    errno_t ret;

    if (input == NULL) {
        return EOK;
    }

    ret = sss_tool_parse_name(mem_ctx, tool_ctx, input, _name, &dom);
    if (ret == EAGAIN) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to find domain from "
              "fqn %s\n", input);
        ERROR("Changing domain is not allowed!\n");
        ret = EINVAL;
    } else if (ret == EOK && dom != NULL && dom != domain) {
        DEBUG(SSSDBG_OP_FAILURE, "Trying to change domain from "
              "%s to %s, not allowed!\n", domain->name, dom->name);
        ERROR("Changing domain is not allowed!\n");
        ret = EINVAL;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse name %s [%d]: %s\n",
              input, ret, sss_strerror(ret));
    }

    return ret;
}

static errno_t override_user(struct sss_tool_ctx *tool_ctx,
                             struct override_user *input_user)
{
    TALLOC_CTX *tmp_ctx;
    struct override_user user;
    struct sysdb_attrs *attrs;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    user = *input_user;

    /* We need to parse the name and ensure that domain did not change. */
    ret = override_fqn(tmp_ctx, tool_ctx, user.domain, user.name, &user.name);
    if (ret != EOK) {
        goto done;
    }

    ret = prepare_view_msg(user.domain);
    if (ret != EOK) {
        goto done;
    }

    attrs = build_user_attrs(tool_ctx, &user);
    if (attrs == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to build sysdb attrs.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = override_object_add(user.domain, SYSDB_MEMBER_USER, attrs,
                              user.sysdb_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to add override object.\n");
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t override_group(struct sss_tool_ctx *tool_ctx,
                              struct override_group *input_group)
{
    TALLOC_CTX *tmp_ctx;
    struct override_group group;
    struct sysdb_attrs *attrs;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    group = *input_group;

    /* We need to parse the name and ensure that domain did not change. */
    ret = override_fqn(tmp_ctx, tool_ctx, group.domain, group.name,
                       &group.name);
    if (ret != EOK) {
        goto done;
    }

    ret = prepare_view_msg(group.domain);
    if (ret != EOK) {
        goto done;
    }

    attrs = build_group_attrs(tool_ctx, &group);
    if (attrs == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to build sysdb attrs.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = override_object_add(group.domain, SYSDB_MEMBER_GROUP, attrs,
                              group.sysdb_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to add override object.\n");
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t override_object_del(struct sss_domain_info *domain,
                                   enum sysdb_member_type type,
                                   const char *name)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_message *msg;
    struct ldb_dn *override_dn;
    struct ldb_dn *ldb_dn;
    const char *str_dn;
    const char *anchor;
    errno_t ret;
    int sret;
    bool in_transaction = false;
    struct ldb_context *ldb = sysdb_ctx_get_ldb(domain->sysdb);

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = get_object_dn(tmp_ctx, domain, type, name, &ldb_dn, &str_dn);
    if (ret != EOK) {
        goto done;
    }

    anchor = build_anchor(tmp_ctx, str_dn);
    if (anchor == NULL) {
        ret = ENOMEM;
        goto done;
    }

    override_dn = ldb_dn_new_fmt(tmp_ctx, ldb,
                        SYSDB_TMPL_OVERRIDE, anchor, LOCALVIEW);
    if (override_dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Removing override for %s\n", str_dn);

    ret = sysdb_transaction_start(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_transaction_start() failed.\n");
        goto done;
    }
    in_transaction = true;

    ret = sysdb_delete_entry(domain->sysdb, override_dn, true);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_delete_entry() failed.\n");
        goto done;
    }

    msg = ldb_msg_new(tmp_ctx);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    msg->dn = talloc_steal(msg, ldb_dn);
    if (msg->dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, SYSDB_OVERRIDE_DN, LDB_FLAG_MOD_DELETE, NULL);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_msg_add_empty() failed\n");
        ret = sss_ldb_error_to_errno(ret);
        goto done;
    }

    ret = ldb_modify(ldb, msg);
    if (ret != LDB_SUCCESS && ret != LDB_ERR_NO_SUCH_ATTRIBUTE) {
        DEBUG(SSSDBG_OP_FAILURE,
              "ldb_modify() failed: [%s](%d)[%s]\n",
              ldb_strerror(ret), ret, ldb_errstring(ldb));
        ret = sss_ldb_error_to_errno(ret);
        goto done;
    }

    ret = sysdb_transaction_commit(domain->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to commit transaction\n");
        goto done;
    }
    in_transaction = false;

    ret = EOK;

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(domain->sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not cancel transaction\n");
        }
    }

    talloc_free(tmp_ctx);
    return ret;
}

static errno_t append_name(struct sss_domain_info *domain,
                           struct ldb_message *override)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_context *ldb = sysdb_ctx_get_ldb(domain->sysdb);
    struct ldb_dn *dn;
    struct ldb_message **msgs;
    const char *attrs[] = {SYSDB_NAME, NULL};
    const char *name;
    const char *fqname;
    size_t count;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed.\n");
        return ENOMEM;
    }

    dn = ldb_msg_find_attr_as_dn(ldb, tmp_ctx, override,
                                 SYSDB_OVERRIDE_OBJECT_DN);
    if (dn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing overrideObjectDN?\n");
        ret = ERR_INTERNAL;
        goto done;
    }

    ret = sysdb_search_entry(tmp_ctx, domain->sysdb, dn, LDB_SCOPE_BASE,
                             NULL, attrs, &count, &msgs);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_search_entry() failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    } else if (count != 1) {
        DEBUG(SSSDBG_CRIT_FAILURE, "More than one user found?\n");
        ret = ERR_INTERNAL;
        goto done;
    }

    name = ldb_msg_find_attr_as_string(msgs[0], SYSDB_NAME, NULL);
    if (name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Object with no name?\n");
        ret = ERR_INTERNAL;
        goto done;
    }

    fqname = get_fqname(tmp_ctx, domain, name);
    if (fqname == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get fqname\n");
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_string(override, ORIGNAME, fqname);
    if (ret != LDB_SUCCESS) {
        ret = sss_ldb_error_to_errno(ret);
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to add attribute to msg\n");
        goto done;
    }

    talloc_steal(override, fqname);

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t list_overrides(TALLOC_CTX *mem_ctx,
                              const char *base_filter,
                              const char *ext_filter,
                              const char **attrs,
                              struct sss_domain_info *domain,
                              size_t *_count,
                              struct ldb_message ***_msgs)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *dn;
    struct ldb_context *ldb = sysdb_ctx_get_ldb(domain->sysdb);
    size_t count;
    struct ldb_message **msgs;
    const char *filter;
    size_t i;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed.\n");
        return ENOMEM;
    }

    filter = base_filter;
    if (ext_filter != NULL) {
        filter = talloc_asprintf(tmp_ctx, "(&%s%s)", filter, ext_filter);
        if (filter == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf() failed.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    /* Acquire list of override objects. */
    dn = ldb_dn_new_fmt(tmp_ctx, ldb, SYSDB_TMPL_VIEW_SEARCH_BASE, LOCALVIEW);
    if (dn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_new_fmt() failed.\n");
        ret = EIO;
        goto done;
    }

    ret = sysdb_search_entry(tmp_ctx, domain->sysdb, dn, LDB_SCOPE_SUBTREE,
                             filter, attrs, &count, &msgs);
    if (ret == ENOENT) {
        *_msgs = NULL;
        *_count = 0;
        ret = EOK;
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_search_entry() failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    /* Amend messages with original name. */
    for (i = 0; i < count; i++) {
        ret = append_name(domain, msgs[i]);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to append name [%d]: %s\n",
                  ret, sss_strerror(ret));
            goto done;
        }
    }

    *_msgs = talloc_steal(mem_ctx, msgs);
    *_count = count;

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static struct override_user *
list_user_overrides(TALLOC_CTX *mem_ctx,
                    struct sss_domain_info *domain,
                    const char *filter)
{
    TALLOC_CTX *tmp_ctx;
    struct override_user *objs = NULL;
    struct ldb_message **msgs;
    size_t count;
    size_t i;
    errno_t ret;
    const char *attrs[] = SYSDB_PW_ATTRS;
    struct ldb_message_element *el;
    const char *fqname;
    char *name;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed.\n");
        return NULL;
    }

    ret = list_overrides(tmp_ctx, "(objectClass=" SYSDB_OVERRIDE_USER_CLASS ")",
                         filter, attrs, domain, &count, &msgs);
    if (ret != EOK) {
        goto done;
    }

    objs = talloc_zero_array(tmp_ctx, struct override_user, count + 1);
    if (objs == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < count; i++) {
        objs[i].orig_name = ldb_msg_find_attr_as_string(msgs[i], ORIGNAME,
                                                        NULL);
        if (objs[i].orig_name == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Missing name?!\n");
            ret = ERR_INTERNAL;
            goto done;
        }

        fqname = ldb_msg_find_attr_as_string(msgs[i], SYSDB_NAME, NULL);
        if (fqname != NULL) {
            ret = sss_parse_internal_fqname(tmp_ctx, fqname, &name, NULL);
            if (ret != EOK) {
                ret = ERR_WRONG_NAME_FORMAT;
                goto done;
            }
            objs[i].name = talloc_steal(objs, name);
        }

        objs[i].uid = ldb_msg_find_attr_as_uint(msgs[i], SYSDB_UIDNUM, 0);
        objs[i].gid = ldb_msg_find_attr_as_uint(msgs[i], SYSDB_GIDNUM, 0);
        objs[i].home = ldb_msg_find_attr_as_string(msgs[i], SYSDB_HOMEDIR, NULL);
        objs[i].shell = ldb_msg_find_attr_as_string(msgs[i], SYSDB_SHELL, NULL);
        objs[i].gecos = ldb_msg_find_attr_as_string(msgs[i], SYSDB_GECOS, NULL);

        el = ldb_msg_find_element(msgs[i], SYSDB_USER_CERT);
        if (el != NULL && el->num_values > 0) {
            /* Currently we support only 1 certificate override */
            objs[i].cert = sss_base64_encode(objs, el->values[0].data,
                                             el->values[0].length);
            if (objs[i].cert == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "sss_base64_encode failed.\n");
                ret = ERR_INTERNAL;
                goto done;
            }
        } else {
            objs[i].cert = NULL;
        }

        talloc_steal(objs, objs[i].orig_name);
        talloc_steal(objs, objs[i].home);
        talloc_steal(objs, objs[i].shell);
        talloc_steal(objs, objs[i].gecos);
    }

    talloc_steal(mem_ctx, objs);

done:
    talloc_free(tmp_ctx);

    if (ret != EOK) {
        return NULL;
    }

    return objs;
}

static struct override_group *
list_group_overrides(TALLOC_CTX *mem_ctx,
                     struct sss_domain_info *domain,
                     const char *filter)
{
    TALLOC_CTX *tmp_ctx;
    struct override_group *objs = NULL;
    struct ldb_message **msgs;
    size_t count;
    size_t i;
    errno_t ret;
    const char *attrs[] = SYSDB_GRSRC_ATTRS;
    const char *fqname;
    char *name;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed.\n");
        return NULL;
    }

    ret = list_overrides(tmp_ctx, "(objectClass=" SYSDB_OVERRIDE_GROUP_CLASS ")",
                         filter, attrs, domain, &count, &msgs);
    if (ret != EOK) {
        goto done;
    }

    objs = talloc_zero_array(tmp_ctx, struct override_group, count + 1);
    if (objs == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < count; i++) {
        objs[i].orig_name = ldb_msg_find_attr_as_string(msgs[i], ORIGNAME,
                                                        NULL);
        if (objs[i].orig_name == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Missing name?!\n");
            ret = ERR_INTERNAL;
            goto done;
        }
        talloc_steal(objs, objs[i].orig_name);

        fqname = ldb_msg_find_attr_as_string(msgs[i], SYSDB_NAME, NULL);
        if (fqname != NULL) {
            ret = sss_parse_internal_fqname(tmp_ctx, fqname, &name, NULL);
            if (ret != EOK) {
                ret = ERR_WRONG_NAME_FORMAT;
                goto done;
            }
            objs[i].name = talloc_steal(objs, name);
        }

        objs[i].gid = ldb_msg_find_attr_as_uint(msgs[i], SYSDB_GIDNUM, 0);
    }

    talloc_steal(mem_ctx, objs);

done:
    talloc_free(tmp_ctx);

    if (ret != EOK) {
        return NULL;
    }

    return objs;
}

static errno_t user_export(const char *filename,
                           struct sss_domain_info *dom,
                           bool iterate,
                           const char *filter)
{
    TALLOC_CTX *tmp_ctx;
    struct sss_colondb *db;
    struct override_user *objs;
    errno_t ret;
    int i;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    db = sss_colondb_open(tmp_ctx, SSS_COLONDB_WRITE, filename);
    if (db == NULL) {
        ERROR("Unable to open %s.\n",
              filename == NULL ? "stdout" : filename);
        ret = EIO;
        goto done;
    }

    do {
        objs = list_user_overrides(tmp_ctx, dom, filter);
        if (objs == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get override objects\n");
            ret = ENOMEM;
            goto done;
        }

        for (i = 0; objs[i].orig_name != NULL; i++) {
            /**
             * Format: orig_name:name:uid:gid:gecos:home:shell:certificate
             */
            struct sss_colondb_write_field table[] = {
                {SSS_COLONDB_STRING, {.str = objs[i].orig_name}},
                {SSS_COLONDB_STRING, {.str = objs[i].name}},
                {SSS_COLONDB_UINT32, {.uint32 = objs[i].uid}},
                {SSS_COLONDB_UINT32, {.uint32 = objs[i].gid}},
                {SSS_COLONDB_STRING, {.str = objs[i].gecos}},
                {SSS_COLONDB_STRING, {.str = objs[i].home}},
                {SSS_COLONDB_STRING, {.str = objs[i].shell}},
                {SSS_COLONDB_STRING, {.str = objs[i].cert}},
                {SSS_COLONDB_SENTINEL, {0}}
            };

            ret = sss_colondb_writeline(db, table);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Unable to write line to db\n");
                goto done;
            }
        }

        /* All overrides are under the same subtree, so we don't want to
         * descent into subdomains. */
        dom = get_next_domain(dom, false);
    } while (dom != NULL && iterate);

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t group_export(const char *filename,
                            struct sss_domain_info *dom,
                            bool iterate,
                            const char *filter)
{
    TALLOC_CTX *tmp_ctx;
    struct sss_colondb *db;
    struct override_group *objs;
    errno_t ret;
    int i;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }


    db = sss_colondb_open(tmp_ctx, SSS_COLONDB_WRITE, filename);
    if (db == NULL) {
        ERROR("Unable to open %s.\n",
                filename == NULL ? "stdout" : filename);
        ret = EIO;
        goto done;
    }

    do {
        objs = list_group_overrides(tmp_ctx, dom, filter);
        if (objs == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get override objects\n");
            ret = ENOMEM;
            goto done;
        }

        for (i = 0; objs[i].orig_name != NULL; i++) {
            /**
             * Format: orig_name:name:gid
             */
            struct sss_colondb_write_field table[] = {
                {SSS_COLONDB_STRING, {.str = objs[i].orig_name}},
                {SSS_COLONDB_STRING, {.str = objs[i].name}},
                {SSS_COLONDB_UINT32, {.uint32 = objs[i].gid}},
                {SSS_COLONDB_SENTINEL, {0}}
            };

            ret = sss_colondb_writeline(db, table);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Unable to write line to db\n");
                goto done;
            }
        }

        /* All overrides are under the same subtree, so we don't want to
         * descent into subdomains. */
        dom = get_next_domain(dom, false);
    } while (dom != NULL && iterate);

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static int override_user_add(struct sss_cmdline *cmdline,
                             struct sss_tool_ctx *tool_ctx)
{
    struct override_user user = {NULL};
    errno_t ret;

    ret = parse_cmdline_user_add(cmdline, tool_ctx, &user);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command line.\n");
        goto done;
    }

    ret = get_user_domain_msg(tool_ctx, &user);
    if (ret != EOK) {
        goto done;
    }

    ret = override_user(tool_ctx, &user);
    if (ret != EOK) {
        goto done;
    }

    ret = EOK;

done:
    free(discard_const(user.input_name));

    return ret;
}

static int override_user_del(struct sss_cmdline *cmdline,
                             struct sss_tool_ctx *tool_ctx)
{
    struct override_user user = {NULL};
    errno_t ret;

    ret = parse_cmdline_user_del(cmdline, tool_ctx, &user);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command line.\n");
        goto done;
    }

    ret = get_user_domain_msg(tool_ctx, &user);
    if (ret != EOK) {
        goto done;
    }

    ret = override_object_del(user.domain, SYSDB_MEMBER_USER, user.sysdb_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to delete override object.\n");
        goto done;
    }

    ret = EOK;

done:
    free(discard_const(user.input_name));

    return ret;
}

static int override_user_find(struct sss_cmdline *cmdline,
                              struct sss_tool_ctx *tool_ctx)
{
    struct sss_domain_info *dom;
    bool iterate;
    errno_t ret;

    ret = parse_cmdline_find(cmdline, tool_ctx, &dom);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command line.\n");
        return ret;
    }

    if (dom == NULL) {
        dom = tool_ctx->domains;
        iterate = true;
    } else {
        iterate = false;
    }

    ret = user_export(NULL, dom, iterate, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to export users\n");
        return ret;
    }

    return EOK;
}

static int override_user_show(struct sss_cmdline *cmdline,
                              struct sss_tool_ctx *tool_ctx)
{
    TALLOC_CTX *tmp_ctx;
    struct override_user input = {NULL};
    const char *dn;
    char *anchor;
    const char *filter;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed.\n");
        return ENOMEM;
    }

    ret = parse_cmdline_user_show(cmdline, tool_ctx, &input);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command line.\n");
        goto done;
    }

    ret = get_user_domain_msg(tool_ctx, &input);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get object domain\n");
        goto done;
    }

    ret = get_object_dn(tmp_ctx, input.domain, SYSDB_MEMBER_USER,
                        input.sysdb_name, NULL, &dn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get object dn\n");
        goto done;
    }

    anchor = build_anchor(tmp_ctx, dn);
    if (anchor == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_filter_sanitize(tmp_ctx, anchor, &anchor);
    if (ret != EOK) {
        ret = ENOMEM;
        goto done;
    }

    filter = talloc_asprintf(tmp_ctx, "(%s=%s)",
                             SYSDB_OVERRIDE_ANCHOR_UUID, anchor);
    if (filter == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf() failed\n");
        ret = ENOMEM;
        goto done;
    }

    ret = user_export(NULL, input.domain, false, filter);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to export users\n");
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    free(discard_const(input.input_name));

    return ret;
}

static int override_user_import(struct sss_cmdline *cmdline,
                                struct sss_tool_ctx *tool_ctx)
{
    TALLOC_CTX *tmp_ctx;
    struct sss_colondb *db;
    const char *filename = NULL;
    struct override_user obj = {0};
    int linenum = 1;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed.\n");
        return EXIT_FAILURE;
    }

    /**
     * Format: orig_name:name:uid:gid:gecos:home:shell:certificate
     */
    struct sss_colondb_read_field table[] = {
        {SSS_COLONDB_STRING, {.str = &obj.input_name}},
        {SSS_COLONDB_STRING, {.str = &obj.name}},
        {SSS_COLONDB_UINT32, {.uint32 = &obj.uid}},
        {SSS_COLONDB_UINT32, {.uint32 = &obj.gid}},
        {SSS_COLONDB_STRING, {.str = &obj.gecos}},
        {SSS_COLONDB_STRING, {.str = &obj.home}},
        {SSS_COLONDB_STRING, {.str = &obj.shell}},
        {SSS_COLONDB_STRING, {.str = &obj.cert}},
        {SSS_COLONDB_SENTINEL, {0}}
    };

    ret = parse_cmdline_import(cmdline, &filename);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command line.\n");
        goto done;
    }

    db = sss_colondb_open(tool_ctx, SSS_COLONDB_READ, filename);
    if (db == NULL) {
        ERROR("Unable to open %s.\n", filename);
        ret = EIO;
        goto done;
    }

    while ((ret = sss_colondb_readline(tmp_ctx, db, table)) == EOK) {
        linenum++;

        ret = sss_tool_parse_name(tool_ctx, tool_ctx, obj.input_name,
                                  &obj.orig_name, &obj.domain);
        if (ret != EOK) {
            ERROR("Unable to parse name %s.\n", obj.input_name);
            goto done;
        }

        ret = get_user_domain_msg(tool_ctx, &obj);
        if (ret != EOK) {
            goto done;
        }

        ret = override_user(tool_ctx, &obj);
        if (ret != EOK) {
            goto done;
        }

        talloc_free_children(tmp_ctx);
    }

    if (ret != EOF) {
        ERROR("Invalid format on line %d. "
              "Use --debug option for more information.\n", linenum);
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    free(discard_const(filename));

    return ret;
}

static int override_user_export(struct sss_cmdline *cmdline,
                                struct sss_tool_ctx *tool_ctx)
{
    const char *filename = NULL;
    errno_t ret;

    ret = parse_cmdline_export(cmdline, &filename);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command line.\n");
        goto done;
    }

    ret = user_export(filename, tool_ctx->domains, true, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to export users\n");
        goto done;
    }

    ret = EOK;

done:
    free(discard_const(filename));

    return ret;
}

static int override_group_add(struct sss_cmdline *cmdline,
                              struct sss_tool_ctx *tool_ctx)
{
    struct override_group group = {NULL};
    errno_t ret;

    ret = parse_cmdline_group_add(cmdline, tool_ctx, &group);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command line.\n");
        goto done;
    }

    ret = get_group_domain_msg(tool_ctx, &group);
    if (ret != EOK) {
        goto done;
    }

    ret = override_group(tool_ctx, &group);
    if (ret != EOK) {
        goto done;
    }

    ret = EOK;

done:
    free(discard_const(group.input_name));

    return ret;
}

static int override_group_del(struct sss_cmdline *cmdline,
                              struct sss_tool_ctx *tool_ctx)
{
    struct override_group group = {NULL};
    errno_t ret;

    ret = parse_cmdline_group_del(cmdline, tool_ctx, &group);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command line.\n");
        goto done;
    }

    ret = get_group_domain_msg(tool_ctx, &group);
    if (ret != EOK) {
        goto done;
    }

    ret = override_object_del(group.domain, SYSDB_MEMBER_GROUP,
                              group.sysdb_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to delete override object.\n");
        goto done;
    }

    ret = EOK;

done:
    free(discard_const(group.input_name));

    return ret;
}

static int override_group_find(struct sss_cmdline *cmdline,
                               struct sss_tool_ctx *tool_ctx)
{
    struct sss_domain_info *dom;
    bool iterate;
    errno_t ret;

    ret = parse_cmdline_find(cmdline, tool_ctx, &dom);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command line.\n");
        return ret;
    }

    if (dom == NULL) {
        dom = tool_ctx->domains;
        iterate = true;
    } else {
        iterate = false;
    }

    ret = group_export(NULL, dom, iterate, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to export groups\n");
        return ret;
    }

    return EOK;
}

static int override_group_show(struct sss_cmdline *cmdline,
                               struct sss_tool_ctx *tool_ctx)
{
    TALLOC_CTX *tmp_ctx;
    struct override_group input = {NULL};
    const char *dn;
    char *anchor;
    const char *filter;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed.\n");
        return ENOMEM;
    }

    ret = parse_cmdline_group_show(cmdline, tool_ctx, &input);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command line.\n");
        goto done;
    }

    ret = get_group_domain_msg(tool_ctx, &input);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get object domain\n");
        goto done;
    }

    ret = get_object_dn(tmp_ctx, input.domain, SYSDB_MEMBER_GROUP,
                        input.sysdb_name, NULL, &dn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get object dn\n");
        goto done;
    }

    anchor = build_anchor(tmp_ctx, dn);
    if (anchor == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_filter_sanitize(tmp_ctx, anchor, &anchor);
    if (ret != EOK) {
        ret = ENOMEM;
        goto done;
    }

    filter = talloc_asprintf(tmp_ctx, "(%s=%s)",
                             SYSDB_OVERRIDE_ANCHOR_UUID, anchor);
    if (filter == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf() failed\n");
        ret = ENOMEM;
        goto done;
    }

    ret = group_export(NULL, input.domain, false, filter);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to export groups\n");
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    free(discard_const(input.input_name));

    return ret;
}

static int override_group_import(struct sss_cmdline *cmdline,
                                 struct sss_tool_ctx *tool_ctx)
{
    TALLOC_CTX *tmp_ctx;
    struct sss_colondb *db;
    const char *filename = NULL;
    struct override_group obj = {0};
    int linenum = 1;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed.\n");
        return ENOMEM;
    }

    /**
     * Format: orig_name:name:gid
     */
    struct sss_colondb_read_field table[] = {
        {SSS_COLONDB_STRING, {.str = &obj.input_name}},
        {SSS_COLONDB_STRING, {.str = &obj.name}},
        {SSS_COLONDB_UINT32, {.uint32 = &obj.gid}},
        {SSS_COLONDB_SENTINEL, {0}}
    };

    ret = parse_cmdline_import(cmdline, &filename);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command line.\n");
        goto done;
    }

    db = sss_colondb_open(tool_ctx, SSS_COLONDB_READ, filename);
    if (db == NULL) {
        ERROR("Unable to open %s.\n", filename);
        ret = EIO;
        goto done;
    }

    while ((ret = sss_colondb_readline(tmp_ctx, db, table)) == EOK) {
        linenum++;

        ret = sss_tool_parse_name(tool_ctx, tool_ctx, obj.input_name,
                                  &obj.orig_name, &obj.domain);
        if (ret != EOK) {
            ERROR("Unable to parse name %s.\n", obj.input_name);
            goto done;
        }

        ret = get_group_domain_msg(tool_ctx, &obj);
        if (ret != EOK) {
            goto done;
        }

        ret = override_group(tool_ctx, &obj);
        if (ret != EOK) {
            goto done;
        }

        talloc_free_children(tmp_ctx);
    }

    if (ret != EOF) {
        ERROR("Invalid format on line %d. "
              "Use --debug option for more information.\n", linenum);
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    free(discard_const(filename));

    return ret;
}

static int override_group_export(struct sss_cmdline *cmdline,
                                 struct sss_tool_ctx *tool_ctx)
{
    const char *filename = NULL;
    errno_t ret;

    ret = parse_cmdline_export(cmdline, &filename);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command line.\n");
        goto done;
    }

    ret = group_export(filename, tool_ctx->domains, true, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to export groups\n");
        goto done;
    }

    ret = EOK;

done:
    free(discard_const(filename));

    return ret;
}

int main(int argc, const char **argv)
{
    struct sss_route_cmd commands[] = {
        SSS_TOOL_COMMAND_NOMSG("user-add", override_user_add),
        SSS_TOOL_COMMAND_NOMSG("user-del", override_user_del),
        SSS_TOOL_COMMAND_NOMSG("user-find", override_user_find),
        SSS_TOOL_COMMAND_NOMSG("user-show", override_user_show),
        SSS_TOOL_COMMAND_NOMSG("user-import", override_user_import),
        SSS_TOOL_COMMAND_NOMSG("user-export", override_user_export),
        SSS_TOOL_COMMAND_NOMSG("group-add", override_group_add),
        SSS_TOOL_COMMAND_NOMSG("group-del", override_group_del),
        SSS_TOOL_COMMAND_NOMSG("group-find", override_group_find),
        SSS_TOOL_COMMAND_NOMSG("group-show", override_group_show),
        SSS_TOOL_COMMAND_NOMSG("group-import", override_group_import),
        SSS_TOOL_COMMAND_NOMSG("group-export", override_group_export),
        SSS_TOOL_LAST
    };

    return sss_tool_main(argc, argv, commands);
}
