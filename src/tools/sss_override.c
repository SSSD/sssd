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
#include "db/sysdb.h"
#include "tools/common/sss_tools.h"

#define LOCALVIEW SYSDB_LOCAL_VIEW_NAME

struct override_user {
    const char *input_name;
    const char *orig_name;
    struct sss_domain_info *domain;

    const char *name;
    uid_t uid;
    gid_t gid;
    const char *home;
    const char *shell;
    const char *gecos;
};

struct override_group {
    const char *input_name;
    const char *orig_name;
    struct sss_domain_info *domain;

    const char *name;
    gid_t gid;
};

static int parse_cmdline(struct sss_cmdline *cmdline,
                         struct sss_tool_ctx *tool_ctx,
                         struct poptOption *options,
                         const char **_input_name,
                         const char **_orig_name,
                         struct sss_domain_info **_domain)
{
    enum sss_tool_opt require;
    const char *input_name;
    const char *orig_name;
    struct sss_domain_info *domain;
    int ret;

    require = options == NULL ? SSS_TOOL_OPT_OPTIONAL : SSS_TOOL_OPT_REQUIRED;

    ret = sss_tool_popt_ex(cmdline, options, require,
                           NULL, NULL, "NAME", _("Specify name of modified "
                           "object."), &input_name);
    if (ret != EXIT_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command arguments\n");
        return ret;
    }

    ret = sss_tool_parse_name(tool_ctx, tool_ctx, input_name,
                              &orig_name, &domain);
    if (ret != EOK) {
        fprintf(stderr, _("Unable to parse name.\n"));
        return ret;
    }

    *_input_name = input_name;
    *_orig_name = orig_name;
    *_domain = domain;

    return EXIT_SUCCESS;
}

static int parse_cmdline_user_add(struct sss_cmdline *cmdline,
                                  struct sss_tool_ctx *tool_ctx,
                                  struct override_user *user)
{
    struct poptOption options[] = {
        POPT_AUTOHELP
        {"name", 'n', POPT_ARG_STRING, &user->name, 0, _("Override name"), NULL },
        {"uid", 'u', POPT_ARG_INT, &user->uid, 0, _("Override uid (non-zero value)"), NULL },
        {"gid", 'g', POPT_ARG_INT, &user->gid, 0, _("Override gid (non-zero value)"), NULL },
        {"home", 'h', POPT_ARG_STRING, &user->home, 0, _("Override home directory"), NULL },
        {"shell", 's', POPT_ARG_STRING, &user->shell, 0, _("Override shell"), NULL },
        {"gecos", 'c', POPT_ARG_STRING, &user->gecos, 0, _("Override gecos"), NULL },
        POPT_TABLEEND
    };

    return parse_cmdline(cmdline, tool_ctx, options, &user->input_name,
                         &user->orig_name, &user->domain);
}

static int parse_cmdline_user_del(struct sss_cmdline *cmdline,
                                  struct sss_tool_ctx *tool_ctx,
                                  struct override_user *user)
{
    return parse_cmdline(cmdline, tool_ctx, NULL, &user->input_name,
                         &user->orig_name, &user->domain);
}

static int parse_cmdline_group_add(struct sss_cmdline *cmdline,
                                   struct sss_tool_ctx *tool_ctx,
                                   struct override_group *group)
{
    struct poptOption options[] = {
        POPT_AUTOHELP
        {"name", 'n', POPT_ARG_STRING, &group->name, 0, _("Override name"), NULL },
        {"gid", 'g', POPT_ARG_INT, &group->gid, 0, _("Override gid"), NULL },
        POPT_TABLEEND
    };

    return parse_cmdline(cmdline, tool_ctx, options, &group->input_name,
                         &group->orig_name, &group->domain);
}

static int parse_cmdline_group_del(struct sss_cmdline *cmdline,
                                   struct sss_tool_ctx *tool_ctx,
                                   struct override_group *group)
{
    return parse_cmdline(cmdline, tool_ctx, NULL, &group->input_name,
                         &group->orig_name, &group->domain);
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
                                       const char *name,
                                       uid_t uid,
                                       gid_t gid,
                                       const char *home,
                                       const char *shell,
                                       const char *gecos)
{
    struct sysdb_attrs *attrs;
    errno_t ret;

    attrs = sysdb_new_attrs(mem_ctx);
    if (attrs == NULL) {
        return NULL;
    }

    if (name != NULL) {
        ret = sysdb_attrs_add_string(attrs, SYSDB_NAME, name);
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
    return build_attrs(mem_ctx, user->name, user->uid, user->gid, user->home,
                       user->shell, user->gecos);
}

static struct sysdb_attrs *build_group_attrs(TALLOC_CTX *mem_ctx,
                                             struct override_group *group)
{
    return build_attrs(mem_ctx, group->name, 0, group->gid, 0, NULL, NULL);
}

static const char *get_object_dn_and_domain(TALLOC_CTX *mem_ctx,
                                         enum sysdb_member_type type,
                                         const char *name,
                                         struct sss_domain_info *domain,
                                         struct sss_domain_info *domains,
                                         struct sss_domain_info **_new_domain)
{
    TALLOC_CTX *tmp_ctx;
    struct sss_domain_info *dom;
    struct ldb_result *res;
    const char *dn;
    const char *strtype;
    bool check_next;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return NULL;
    }

    /* Ensure that the object is in cache. */
    switch (type) {
    case SYSDB_MEMBER_USER:
        if (getpwnam(name) == NULL) {
            ret = ENOENT;
            goto done;
        }
        break;
    case SYSDB_MEMBER_GROUP:
        if (getgrnam(name) == NULL) {
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
        switch (type) {
        case SYSDB_MEMBER_USER:
            DEBUG(SSSDBG_TRACE_FUNC, "Trying to find user %s@%s\n",
                  name, dom->name);
            ret = sysdb_getpwnam(tmp_ctx, dom, name, &res);
            strtype = "user";
            break;
        case SYSDB_MEMBER_GROUP:
            DEBUG(SSSDBG_TRACE_FUNC, "Trying to find group %s@%s\n",
                  name, dom->name);
            ret = sysdb_getgrnam(tmp_ctx, dom, name, &res);
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

    dn = ldb_dn_get_linearized(res->msgs[0]->dn);
    if (dn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "ldb_dn_get_linearized() failed.\n");
        ret = ENOMEM;
        goto done;
    }

    talloc_steal(mem_ctx, dn);
    *_new_domain = dom;

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    if (ret != EOK) {
        return NULL;
    }

    return dn;
}

static const char * get_user_dn_and_domain(TALLOC_CTX *mem_ctx,
                                           struct sss_domain_info *domains,
                                           struct override_user *user)
{
    return get_object_dn_and_domain(mem_ctx, SYSDB_MEMBER_USER,
                         user->orig_name, user->domain, domains,
                         &user->domain);
}

static const char * get_group_dn_and_domain(TALLOC_CTX *mem_ctx,
                                            struct sss_domain_info *domains,
                                            struct override_group *group)
{
    return get_object_dn_and_domain(mem_ctx, SYSDB_MEMBER_GROUP,
                         group->orig_name, group->domain, domains,
                         &group->domain);
}

static errno_t override_object_add(struct sss_domain_info *domain,
                                   enum sysdb_member_type type,
                                   struct sysdb_attrs *attrs,
                                   const char *obj_dn)
{
    TALLOC_CTX *tmp_ctx;
    const char *anchor;
    struct ldb_dn *ldb_dn;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ldb_dn = ldb_dn_new(tmp_ctx, sysdb_ctx_get_ldb(domain->sysdb), obj_dn);
    if (ldb_dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    anchor = build_anchor(tmp_ctx, obj_dn);
    if (anchor == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_OVERRIDE_ANCHOR_UUID, anchor);
    if (ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Creating override for %s\n", obj_dn);

    ret = sysdb_store_override(domain, LOCALVIEW, type, attrs, ldb_dn);

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t override_object_del(struct sss_domain_info *domain,
                                   const char *obj_dn)
{
    TALLOC_CTX *tmp_ctx;
    const char *anchor;
    struct ldb_dn *override_dn;
    struct ldb_message *msg;
    errno_t ret;
    int sret;
    bool in_transaction = false;
    struct ldb_context *ldb = sysdb_ctx_get_ldb(domain->sysdb);

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    anchor = build_anchor(tmp_ctx, obj_dn);
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

    DEBUG(SSSDBG_TRACE_FUNC, "Removing override for %s\n", obj_dn);

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

    msg->dn = ldb_dn_new(msg, ldb, obj_dn);
    if (msg->dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_msg_add_empty(msg, SYSDB_OVERRIDE_DN, LDB_FLAG_MOD_DELETE, NULL);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_msg_add_empty() failed\n");
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    ret = ldb_modify(ldb, msg);
    if (ret != LDB_SUCCESS && ret != LDB_ERR_NO_SUCH_ATTRIBUTE) {
        DEBUG(SSSDBG_OP_FAILURE,
              "ldb_modify() failed: [%s](%d)[%s]\n",
              ldb_strerror(ret), ret, ldb_errstring(ldb));
        ret = sysdb_error_to_errno(ret);
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

static int override_user_add(struct sss_cmdline *cmdline,
                             struct sss_tool_ctx *tool_ctx,
                             void *pvt)
{
    struct override_user user = {NULL};
    struct sysdb_attrs *attrs;
    const char *dn;
    int ret;

    ret = parse_cmdline_user_add(cmdline, tool_ctx, &user);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command line.\n");
        return EXIT_FAILURE;
    }

    dn = get_user_dn_and_domain(tool_ctx, tool_ctx->domains, &user);
    if (dn == NULL) {
        fprintf(stderr, _("Unable to find user %s@%s.\n"),
                user.orig_name,
                user.domain == NULL ? "[unknown]" : user.domain->name);
        return EXIT_FAILURE;
    }

    ret = prepare_view(user.domain);
    if (ret == EEXIST) {
        fprintf(stderr, _("Other than LOCAL view already exist in "
                "domain %s.\n"), user.domain->name);
        return EXIT_FAILURE;
    } else if (ret != EOK) {
        fprintf(stderr, _("Unable to prepare view [%d]: %s.\n"),
                ret, sss_strerror(ret));
        return EXIT_FAILURE;
    }

    attrs = build_user_attrs(tool_ctx, &user);
    if (attrs == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to build sysdb attrs.\n");
        return EXIT_FAILURE;
    }

    ret = override_object_add(user.domain, SYSDB_MEMBER_USER, attrs, dn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to add override object.\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static int override_user_del(struct sss_cmdline *cmdline,
                             struct sss_tool_ctx *tool_ctx,
                             void *pvt)
{
    struct override_user user = {NULL};
    const char *dn;
    int ret;

    ret = parse_cmdline_user_del(cmdline, tool_ctx, &user);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command line.\n");
        return EXIT_FAILURE;
    }

    dn = get_user_dn_and_domain(tool_ctx, tool_ctx->domains, &user);
    if (dn == NULL) {
        fprintf(stderr, _("Unable to find user %s@%s.\n"),
                user.orig_name, user.domain->name);
        return EXIT_FAILURE;
    }

    ret = override_object_del(user.domain, dn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to add override object.\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static int override_group_add(struct sss_cmdline *cmdline,
                              struct sss_tool_ctx *tool_ctx,
                              void *pvt)
{
    struct override_group group = {NULL};
    struct sysdb_attrs *attrs;
    const char *dn;
    int ret;

    ret = parse_cmdline_group_add(cmdline, tool_ctx, &group);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command line.\n");
        return EXIT_FAILURE;
    }

    dn = get_group_dn_and_domain(tool_ctx, tool_ctx->domains, &group);
    if (dn == NULL) {
        fprintf(stderr, _("Unable to find group %s@%s.\n"),
                group.orig_name, group.domain->name);
        return EXIT_FAILURE;
    }

    ret = prepare_view(group.domain);
    if (ret == EEXIST) {
        fprintf(stderr, _("Other than LOCAL view already exist in "
                "domain %s.\n"), group.domain->name);
        return EXIT_FAILURE;
    } else if (ret != EOK) {
        fprintf(stderr, _("Unable to prepare view [%d]: %s.\n"),
                ret, sss_strerror(ret));
        return EXIT_FAILURE;
    }

    attrs = build_group_attrs(tool_ctx, &group);
    if (attrs == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to build sysdb attrs.\n");
        return EXIT_FAILURE;
    }

    ret = override_object_add(group.domain, SYSDB_MEMBER_GROUP, attrs, dn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to add override object.\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static int override_group_del(struct sss_cmdline *cmdline,
                              struct sss_tool_ctx *tool_ctx,
                              void *pvt)
{
    struct override_group group = {NULL};
    const char *dn;
    int ret;

    ret = parse_cmdline_group_del(cmdline, tool_ctx, &group);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command line.\n");
        return EXIT_FAILURE;
    }

    dn = get_group_dn_and_domain(tool_ctx, tool_ctx->domains, &group);
    if (dn == NULL) {
        fprintf(stderr, _("Unable to find group %s@%s.\n"),
                group.orig_name, group.domain->name);
        return EXIT_FAILURE;
    }

    ret = override_object_del(group.domain, dn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to add override object.\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int main(int argc, const char **argv)
{
    struct sss_route_cmd commands[] = {
        {"user-add", override_user_add},
        {"user-del", override_user_del},
        {"group-add", override_group_add},
        {"group-del", override_group_del},
        {NULL, NULL}
    };

    return sss_tool_main(argc, argv, commands, NULL);
}
