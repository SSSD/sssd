/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2009 Red Hat

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

#include <tevent.h>
#include <talloc.h>
#include <sys/types.h>

#include "util/util.h"
#include "db/sysdb.h"
#include "tools/sss_sync_ops.h"

/* Default settings for user attributes */
#define DFL_SHELL_VAL      "/bin/bash"
#define DFL_BASEDIR_VAL    "/home"
#define DFL_CREATE_HOMEDIR true
#define DFL_REMOVE_HOMEDIR true
#define DFL_SKEL_DIR       "/etc/skel"
#define DFL_MAIL_DIR       "/var/spool/mail"

#define ATTR_NAME_SEP      '='
#define ATTR_VAL_SEP       ','

static int attr_name_val_split(TALLOC_CTX *mem_ctx, const char *nameval,
                               char **_name, char ***_values, int *_nvals)
{
    char *name;
    char **values;
    const char *vals;
    int nvals;
    TALLOC_CTX *tmp_ctx;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) return ENOMEM;

    vals = strchr(nameval, ATTR_NAME_SEP);
    if (vals == NULL) {
        ret = EINVAL;
        goto done;
    }

    name = talloc_strndup(tmp_ctx, nameval, vals-nameval);
    if (name == NULL) {
        ret = ENOMEM;
        goto done;
    }
    vals++;

    ret = split_on_separator(tmp_ctx, vals, ATTR_VAL_SEP, true, true,
                             &values, &nvals);
    if (ret != EOK) {
        goto done;
    }

    *_name = talloc_steal(mem_ctx, name);
    *_values = talloc_steal(mem_ctx, values);
    *_nvals = nvals;
    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

static int attr_op(struct ops_ctx *octx, const char *nameval, int op)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    struct sysdb_attrs *attrs;
    char *name;
    char **vals;
    int nvals;
    int i;

    switch(op) {
    case SYSDB_MOD_ADD:
    case SYSDB_MOD_DEL:
    case SYSDB_MOD_REP:
        break;
    default:
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) return ENOMEM;

    attrs = sysdb_new_attrs(tmp_ctx);
    if (attrs == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = attr_name_val_split(tmp_ctx, nameval, &name, &vals, &nvals);
    if (ret != EOK) {
        goto done;
    }

    for (i=0; i < nvals; i++) {
        ret = sysdb_attrs_add_string(attrs, name, vals[i]);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Could not add %s to %s\n", vals[i], name);
            continue;
        }
    }

    ret = sysdb_set_user_attr(octx->domain, octx->name, attrs, op);
done:
    talloc_free(tmp_ctx);
    return ret;
}
/*
 * Generic modify groups member
 */
static int mod_groups_member(struct sss_domain_info *dom,
                             char **grouplist,
                             struct ldb_dn *member_dn,
                             int optype)
{
    TALLOC_CTX *tmpctx;
    struct ldb_dn *parent_dn;
    int ret;
    int i;
    char *grp_sysdb_fqname = NULL;

    tmpctx = talloc_new(NULL);
    if (!tmpctx) {
        return ENOMEM;
    }

/* FIXME: add transaction around loop */
    for (i = 0; grouplist[i]; i++) {
        grp_sysdb_fqname = sss_create_internal_fqname(tmpctx, grouplist[i],
                                                      dom->name);
        if (grp_sysdb_fqname == NULL) {
            ret = ENOMEM;
            goto done;
        }

        parent_dn = sysdb_group_dn(tmpctx, dom, grp_sysdb_fqname);
        if (!parent_dn) {
            ret = ENOMEM;
            goto done;
        }

        talloc_free(grp_sysdb_fqname);

        ret = sysdb_mod_group_member(dom, member_dn, parent_dn, optype);
        if (ret) {
            goto done;
        }
    }

    ret = EOK;

done:
    talloc_zfree(tmpctx);
    return ret;
}

#define add_to_groups(data, member_dn) \
    mod_groups_member(data->domain, data->addgroups, member_dn, \
                      LDB_FLAG_MOD_ADD)
#define remove_from_groups(data, member_dn) \
    mod_groups_member(data->domain, data->rmgroups, member_dn, \
                      LDB_FLAG_MOD_DELETE)

/*
 * Modify a user
 */
struct user_mod_state {
    struct sysdb_ctx *sysdb;

    struct sysdb_attrs *attrs;
    struct ldb_dn *member_dn;

    struct ops_ctx *data;
};

static int usermod_build_attrs(TALLOC_CTX *mem_ctx,
                               const char *gecos,
                               const char *home,
                               const char *shell,
                               uid_t uid,
                               gid_t gid,
                               int lock,
                               struct sysdb_attrs **_attrs)
{
    int ret = EOK;
    struct sysdb_attrs *attrs;
    const char *attr_name = NULL;

    attrs = sysdb_new_attrs(mem_ctx);
    if (attrs == NULL) {
        return ENOMEM;
    }

    if (shell) {
        attr_name = SYSDB_SHELL;
        ret = sysdb_attrs_add_string(attrs,
                                     attr_name,
                                     shell);
    }

    if (ret == EOK && home) {
        attr_name = SYSDB_HOMEDIR;
        ret = sysdb_attrs_add_string(attrs,
                                     attr_name,
                                     home);
    }

    if (ret == EOK && gecos) {
        attr_name = SYSDB_GECOS;
        ret = sysdb_attrs_add_string(attrs,
                                     attr_name,
                                     gecos);
    }

    if (ret == EOK && uid) {
        attr_name = SYSDB_UIDNUM;
        ret = sysdb_attrs_add_long(attrs,
                                   attr_name,
                                   uid);
    }

    if (ret == EOK && gid) {
        attr_name = SYSDB_GIDNUM;
        ret = sysdb_attrs_add_long(attrs,
                                   attr_name,
                                   gid);
    }

    if (ret == EOK && lock == DO_LOCK) {
        attr_name = SYSDB_DISABLED;
        ret = sysdb_attrs_add_string(attrs,
                                     attr_name,
                                     "true");
    }

    if (ret == EOK && lock == DO_UNLOCK) {
        attr_name = SYSDB_DISABLED;
        /* PAM code checks for 'false' value in SYSDB_DISABLED attribute */
        ret = sysdb_attrs_add_string(attrs,
                                     attr_name,
                                     "false");
    }

    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not add attribute [%s] to changeset.\n", attr_name);
        return ret;
    }

    *_attrs = attrs;
    return EOK;
}

/*
 * Public interface for modifying users
 */
int usermod(TALLOC_CTX *mem_ctx,
            struct ops_ctx *data)
{
    struct sysdb_attrs *attrs = NULL;
    struct ldb_dn *member_dn = NULL;
    int ret;

    data->sysdb_fqname = sss_create_internal_fqname(data,
                                                    data->name,
                                                    data->domain->name);
    if (data->sysdb_fqname == NULL) {
        return ENOMEM;
    }

    if (data->addgroups || data->rmgroups) {
        member_dn = sysdb_user_dn(mem_ctx, data->domain, data->sysdb_fqname);
        if (!member_dn) {
            return ENOMEM;
        }
    }

    ret = usermod_build_attrs(mem_ctx,
                              data->gecos,
                              data->home,
                              data->shell,
                              data->uid,
                              data->gid,
                              data->lock,
                              &attrs);
    if (ret != EOK) {
        return ret;
    }

    if (attrs->num != 0) {
        ret = sysdb_set_user_attr(data->domain, data->sysdb_fqname,
                                  attrs, SYSDB_MOD_REP);
        if (ret) {
            return ret;
        }
    }

    if (data->rmgroups != NULL) {
        ret = remove_from_groups(data, member_dn);
        if (ret) {
            return ret;
        }
    }

    if (data->addgroups != NULL) {
        ret = add_to_groups(data, member_dn);
        if (ret) {
            return ret;
        }
    }

    if (data->addattr) {
        ret = attr_op(data, data->addattr, SYSDB_MOD_ADD);
        if (ret) {
            return ret;
        }
    }

    if (data->setattr) {
        ret = attr_op(data, data->setattr, SYSDB_MOD_REP);
        if (ret) {
            return ret;
        }

    }

    if (data->delattr) {
        ret = attr_op(data, data->delattr, SYSDB_MOD_DEL);
        if (ret) {
            return ret;
        }
    }

    flush_nscd_cache(NSCD_DB_PASSWD);
    flush_nscd_cache(NSCD_DB_GROUP);

    return EOK;
}

/*
 * Public interface for modifying groups
 */
int groupmod(TALLOC_CTX *mem_ctx,
             struct ops_ctx *data)
{
    struct sysdb_attrs *attrs = NULL;
    struct ldb_dn *member_dn = NULL;
    int ret;

    data->sysdb_fqname = sss_create_internal_fqname(data,
                                                    data->name,
                                                    data->domain->name);
    if (data->sysdb_fqname == NULL) {
        return ENOMEM;
    }

    if (data->addgroups || data->rmgroups) {
        member_dn = sysdb_group_dn(mem_ctx, data->domain, data->sysdb_fqname);
        if (!member_dn) {
            return ENOMEM;
        }
    }

    if (data->gid != 0) {
        attrs = sysdb_new_attrs(mem_ctx);
        if (!attrs) {
            return ENOMEM;
        }
        ret = sysdb_attrs_add_uint32(attrs, SYSDB_GIDNUM, data->gid);
        if (ret) {
            return ret;
        }

        ret = sysdb_set_group_attr(data->domain, data->sysdb_fqname,
                                   attrs, SYSDB_MOD_REP);
        if (ret) {
            return ret;
        }
    }

    if (data->rmgroups != NULL) {
        ret = remove_from_groups(data, member_dn);
        if (ret) {
            return ret;
        }
    }

    if (data->addgroups != NULL) {
        ret = add_to_groups(data, member_dn);
        if (ret) {
            return ret;
        }
    }

    flush_nscd_cache(NSCD_DB_GROUP);

    return EOK;
}

int userdel_defaults(TALLOC_CTX *mem_ctx,
                     struct confdb_ctx *confdb,
                     struct ops_ctx *data,
                     int remove_home)
{
    int ret;
    char *conf_path;
    bool dfl_remove_home;

    conf_path = talloc_asprintf(mem_ctx, CONFDB_DOMAIN_PATH_TMPL, data->domain->name);
    if (!conf_path) {
        return ENOMEM;
    }

    /* remove homedir on user creation? */
    if (!remove_home) {
        ret = confdb_get_bool(confdb,
                             conf_path, CONFDB_LOCAL_REMOVE_HOMEDIR,
                             DFL_REMOVE_HOMEDIR, &dfl_remove_home);
        if (ret != EOK) {
            goto done;
        }
        data->remove_homedir = dfl_remove_home;
    } else {
        data->remove_homedir = (remove_home == DO_REMOVE_HOME);
    }

    /* a directory to remove mail spools from */
    ret = confdb_get_string(confdb, mem_ctx,
            conf_path, CONFDB_LOCAL_MAIL_DIR,
            DFL_MAIL_DIR, &data->maildir);
    if (ret != EOK) {
        goto done;
    }

    ret = EOK;
done:
    talloc_free(conf_path);
    return ret;
}

/*
 * Default values for add operations
 */
int useradd_defaults(TALLOC_CTX *mem_ctx,
                     struct confdb_ctx *confdb,
                     struct ops_ctx *data,
                     const char *gecos,
                     const char *homedir,
                     const char *shell,
                     int create_home,
                     const char *skeldir)
{
    int ret;
    char *basedir = NULL;
    char *conf_path = NULL;

    conf_path = talloc_asprintf(mem_ctx, CONFDB_DOMAIN_PATH_TMPL, data->domain->name);
    if (!conf_path) {
        return ENOMEM;
    }

    /* gecos */
    data->gecos = talloc_strdup(mem_ctx, gecos ? gecos : data->name);
    if (!data->gecos) {
        ret = ENOMEM;
        goto done;
    }
    DEBUG(SSSDBG_TRACE_LIBS, "Gecos: %s\n", data->gecos);

    /* homedir */
    if (homedir) {
        data->home = talloc_strdup(data, homedir);
    } else {
        ret = confdb_get_string(confdb, mem_ctx,
                                conf_path, CONFDB_LOCAL_DEFAULT_BASEDIR,
                                DFL_BASEDIR_VAL, &basedir);
        if (ret != EOK) {
            goto done;
        }
        data->home = talloc_asprintf(mem_ctx, "%s/%s", basedir, data->name);
    }
    if (!data->home) {
        ret = ENOMEM;
        goto done;
    }
    DEBUG(SSSDBG_TRACE_LIBS, "Homedir: %s\n", data->home);

    /* default shell */
    if (!shell) {
        ret = confdb_get_string(confdb, mem_ctx,
                                conf_path, CONFDB_LOCAL_DEFAULT_SHELL,
                                DFL_SHELL_VAL, &data->shell);
        if (ret != EOK) {
            goto done;
        }
    } else {
        data->shell = talloc_strdup(mem_ctx, shell);
        if (!data->shell) {
            ret = ENOMEM;
            goto done;
        }
    }
    DEBUG(SSSDBG_TRACE_LIBS, "Shell: %s\n", data->shell);

    /* create homedir on user creation? */
    if (!create_home) {
        ret = confdb_get_bool(confdb,
                             conf_path, CONFDB_LOCAL_CREATE_HOMEDIR,
                             DFL_CREATE_HOMEDIR, &data->create_homedir);
        if (ret != EOK) {
            goto done;
        }
    } else {
        data->create_homedir = (create_home == DO_CREATE_HOME);
    }
    DEBUG(SSSDBG_TRACE_LIBS,
          "Auto create homedir: %s\n", data->create_homedir?"True":"False");

    /* umask to create homedirs */
    ret = confdb_get_int(confdb,
                         conf_path, CONFDB_LOCAL_UMASK,
                         SSS_DFL_UMASK, (int *) &data->umask);
    if (ret != EOK) {
        goto done;
    }
    DEBUG(SSSDBG_TRACE_LIBS, "Umask: %o\n", data->umask);

    /* a directory to create mail spools in */
    ret = confdb_get_string(confdb, mem_ctx,
            conf_path, CONFDB_LOCAL_MAIL_DIR,
            DFL_MAIL_DIR, &data->maildir);
    if (ret != EOK) {
        goto done;
    }
    DEBUG(SSSDBG_TRACE_LIBS, "Mail dir: %s\n", data->maildir);

    /* skeleton dir */
    if (!skeldir) {
        ret = confdb_get_string(confdb, mem_ctx,
                                conf_path, CONFDB_LOCAL_SKEL_DIR,
                                DFL_SKEL_DIR, &data->skeldir);
        if (ret != EOK) {
            goto done;
        }
    } else {
        data->skeldir = talloc_strdup(mem_ctx, skeldir);
        if (!data->skeldir) {
            ret = ENOMEM;
            goto done;
        }
    }
    DEBUG(SSSDBG_TRACE_LIBS, "Skeleton dir: %s\n", data->skeldir);

    ret = EOK;
done:
    talloc_free(basedir);
    talloc_free(conf_path);
    return ret;
}

/*
 * Public interface for adding users
 */
int useradd(TALLOC_CTX *mem_ctx,
            struct ops_ctx *data)
{
    int ret;

    data->sysdb_fqname = sss_create_internal_fqname(data,
                                                    data->name,
                                                    data->domain->name);
    if (data->sysdb_fqname == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_add_user(data->domain, data->sysdb_fqname, data->uid, data->gid,
                         data->gecos, data->home, data->shell,
                         NULL, NULL, 0, 0);
    if (ret) {
        goto done;
    }

    if (data->addgroups) {
        struct ldb_dn *member_dn;

        member_dn = sysdb_user_dn(mem_ctx, data->domain, data->sysdb_fqname);
        if (!member_dn) {
            ret = ENOMEM;
            goto done;
        }

        ret = add_to_groups(data, member_dn);
        if (ret) {
            goto done;
        }
    }

    flush_nscd_cache(NSCD_DB_PASSWD);
    flush_nscd_cache(NSCD_DB_GROUP);

done:
    return ret;
}

/*
 * Public interface for deleting users
 */
int userdel(TALLOC_CTX *mem_ctx,
            struct sysdb_ctx *sysdb,
            struct ops_ctx *data)
{
    struct ldb_dn *user_dn;
    int ret;

    data->sysdb_fqname = sss_create_internal_fqname(data,
                                                    data->name,
                                                    data->domain->name);
    if (data->sysdb_fqname == NULL) {
        return ENOMEM;
    }

    user_dn = sysdb_user_dn(mem_ctx, data->domain, data->sysdb_fqname);
    if (!user_dn) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not construct a user DN\n");
        return ENOMEM;
    }

    ret = sysdb_delete_entry(sysdb, user_dn, false);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Removing user failed: %s (%d)\n", strerror(ret), ret);
    }

    flush_nscd_cache(NSCD_DB_PASSWD);
    flush_nscd_cache(NSCD_DB_GROUP);

    return ret;
}

/*
 * Public interface for adding groups
 */
int groupadd(struct ops_ctx *data)
{
    int ret;

    data->sysdb_fqname = sss_create_internal_fqname(data,
                                                    data->name,
                                                    data->domain->name);
    if (data->sysdb_fqname == NULL) {
        return ENOMEM;
    }

    ret = sysdb_add_group(data->domain, data->sysdb_fqname, data->gid, NULL, 0, 0);
    if (ret == EOK) {
        flush_nscd_cache(NSCD_DB_GROUP);
    }
    return ret;
}

/*
 * Public interface for deleting groups
 */
int groupdel(TALLOC_CTX *mem_ctx,
            struct sysdb_ctx *sysdb,
            struct ops_ctx *data)
{
    struct ldb_dn *group_dn;
    int ret;

    data->sysdb_fqname = sss_create_internal_fqname(data,
                                                    data->name,
                                                    data->domain->name);
    if (data->sysdb_fqname == NULL) {
        return ENOMEM;
    }

    group_dn = sysdb_group_dn(mem_ctx, data->domain, data->sysdb_fqname);
    if (group_dn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not construct a group DN\n");
        return ENOMEM;
    }

    ret = sysdb_delete_entry(sysdb, group_dn, false);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Removing group failed: %s (%d)\n", strerror(ret), ret);
    }

    flush_nscd_cache(NSCD_DB_GROUP);

    return ret;
}

/*
 * getpwnam, getgrnam and friends
 */
int sysdb_getpwnam_sync(TALLOC_CTX *mem_ctx,
                        const char *name,
                        struct ops_ctx *out)
{
    struct ldb_result *res;
    const char *str;
    int ret;

    out->sysdb_fqname = sss_create_internal_fqname(out, name,
                                                   out->domain->name);
    if (out->sysdb_fqname == NULL) {
        return ENOMEM;
    }

    ret = sysdb_getpwnam(mem_ctx, out->domain, out->sysdb_fqname, &res);
    if (ret) {
        return ret;
    }

    switch (res->count) {
    case 0:
        DEBUG(SSSDBG_CRIT_FAILURE, "No result for sysdb_getpwnam call\n");
        return ENOENT;

    case 1:
        /* fill ops_ctx */
        out->uid = ldb_msg_find_attr_as_uint64(res->msgs[0], SYSDB_UIDNUM, 0);

        out->gid = ldb_msg_find_attr_as_uint64(res->msgs[0], SYSDB_GIDNUM, 0);

        str = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, NULL);
        ret = sss_parse_internal_fqname(out, str, &out->name, NULL);
        if (ret != EOK) {
            return ENOMEM;
        }

        str = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_GECOS, NULL);
        out->gecos = talloc_strdup(out, str);
        if (out->gecos == NULL) {
            return ENOMEM;
        }

        str = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_HOMEDIR, NULL);
        out->home = talloc_strdup(out, str);
        if (out->home == NULL) {
            return ENOMEM;
        }

        str = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_SHELL, NULL);
        out->shell = talloc_strdup(out, str);
        if (out->shell == NULL) {
            return ENOMEM;
        }

        str = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_DISABLED, NULL);
        if (str == NULL) {
            out->lock = DO_UNLOCK;
        } else {
            if (strcasecmp(str, "true") == 0) {
                out->lock = DO_LOCK;
            } else if (strcasecmp(str, "false") == 0) {
                out->lock = DO_UNLOCK;
            } else { /* Invalid value */
                DEBUG(SSSDBG_OP_FAILURE, "Invalid value for %s attribute: %s\n",
                          SYSDB_DISABLED, str ? str : "NULL");
                return EIO;
            }
        }
        break;

    default:
        DEBUG(SSSDBG_CRIT_FAILURE,
              "More than one result for sysdb_getpwnam call\n");
        return EIO;
    }

    return EOK;
}

int sysdb_getgrnam_sync(TALLOC_CTX *mem_ctx,
                        const char *name,
                        struct ops_ctx *out)
{
    struct ldb_result *res;
    const char *str;
    int ret;

    out->sysdb_fqname = sss_create_internal_fqname(out, name,
                                                   out->domain->name);
    if (out->sysdb_fqname == NULL) {
        return ENOMEM;
    }

    ret = sysdb_getgrnam(mem_ctx, out->domain, out->sysdb_fqname, &res);
    if (ret) {
        return ret;
    }

    switch (res->count) {
    case 0:
        DEBUG(SSSDBG_CRIT_FAILURE, "No result for sysdb_getgrnam call\n");
        return ENOENT;

    case 1:
        /* fill ops_ctx */
        out->gid = ldb_msg_find_attr_as_uint64(res->msgs[0], SYSDB_GIDNUM, 0);
        str = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, NULL);
        ret = sss_parse_internal_fqname(out, str, &out->name, NULL);
        if (ret != EOK) {
            return ENOMEM;
        }

        if (out->name == NULL) {
            return ENOMEM;
        }
        break;

    default:
        DEBUG(SSSDBG_CRIT_FAILURE,
              "More than one result for sysdb_getgrnam call\n");
        return EIO;
    }

    return EOK;
}

