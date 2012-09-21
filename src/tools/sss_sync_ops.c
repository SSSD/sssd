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
#define DFL_UMASK          077
#define DFL_SKEL_DIR       "/etc/skel"
#define DFL_MAIL_DIR       "/var/spool/mail"


#define VAR_CHECK(var, val, attr, msg) do { \
        if (var != (val)) { \
            DEBUG(1, (msg" attribute: %s", attr)); \
            return val; \
        } \
} while(0)

struct sync_op_res {
    struct ops_ctx *data;
    int error;
    bool done;
};

/*
 * Generic modify groups member
 */
static int mod_groups_member(struct sysdb_ctx *sysdb,
                             char **grouplist,
                             struct ldb_dn *member_dn,
                             int optype)
{
    TALLOC_CTX *tmpctx;
    struct ldb_dn *parent_dn;
    int ret;
    int i;

    tmpctx = talloc_new(NULL);
    if (!tmpctx) {
        return ENOMEM;
    }

/* FIXME: add transaction around loop */
    for (i = 0; grouplist[i]; i++) {

        parent_dn = sysdb_group_dn(sysdb, tmpctx,
                                   grouplist[i]);
        if (!parent_dn) {
            ret = ENOMEM;
            goto done;
        }

        ret = sysdb_mod_group_member(sysdb, member_dn, parent_dn, optype);
        if (ret) {
            goto done;
        }
    }

    ret = EOK;

done:
    talloc_zfree(tmpctx);
    return ret;
}

#define add_to_groups(sysdb, data, member_dn) \
    mod_groups_member(sysdb, data->addgroups, member_dn, \
                      LDB_FLAG_MOD_ADD)
#define remove_from_groups(sysdb, data, member_dn) \
    mod_groups_member(sysdb, data->rmgroups, member_dn, \
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
    int ret;
    struct sysdb_attrs *attrs;

    attrs = sysdb_new_attrs(mem_ctx);
    if (attrs == NULL) {
        return ENOMEM;
    }

    if (shell) {
        ret = sysdb_attrs_add_string(attrs,
                                     SYSDB_SHELL,
                                     shell);
        VAR_CHECK(ret, EOK, SYSDB_SHELL,
                  "Could not add attribute to changeset\n");
    }

    if (home) {
        ret = sysdb_attrs_add_string(attrs,
                                     SYSDB_HOMEDIR,
                                     home);
        VAR_CHECK(ret, EOK, SYSDB_HOMEDIR,
                  "Could not add attribute to changeset\n");
    }

    if (gecos) {
        ret = sysdb_attrs_add_string(attrs,
                                     SYSDB_GECOS,
                                     gecos);
        VAR_CHECK(ret, EOK, SYSDB_GECOS,
                  "Could not add attribute to changeset\n");
    }

    if (uid) {
        ret = sysdb_attrs_add_long(attrs,
                                   SYSDB_UIDNUM,
                                   uid);
        VAR_CHECK(ret, EOK, SYSDB_UIDNUM,
                  "Could not add attribute to changeset\n");
    }

    if (gid) {
        ret = sysdb_attrs_add_long(attrs,
                                   SYSDB_GIDNUM,
                                   gid);
        VAR_CHECK(ret, EOK, SYSDB_GIDNUM,
                  "Could not add attribute to changeset\n");
    }

    if (lock == DO_LOCK) {
        ret = sysdb_attrs_add_string(attrs,
                                     SYSDB_DISABLED,
                                     "true");
        VAR_CHECK(ret, EOK, SYSDB_DISABLED,
                  "Could not add attribute to changeset\n");
    }

    if (lock == DO_UNLOCK) {
        /* PAM code checks for 'false' value in SYSDB_DISABLED attribute */
        ret = sysdb_attrs_add_string(attrs,
                                     SYSDB_DISABLED,
                                     "false");
        VAR_CHECK(ret, EOK, SYSDB_DISABLED,
                  "Could not add attribute to changeset\n");
    }

    *_attrs = attrs;
    return EOK;
}

/*
 * Public interface for modifying users
 */
int usermod(TALLOC_CTX *mem_ctx,
            struct sysdb_ctx *sysdb,
            struct ops_ctx *data)
{
    struct sysdb_attrs *attrs = NULL;
    struct ldb_dn *member_dn = NULL;
    int ret;

    if (data->addgroups || data->rmgroups) {
        member_dn = sysdb_user_dn(sysdb, mem_ctx, data->name);
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
        ret = sysdb_set_user_attr(sysdb, data->name, attrs, SYSDB_MOD_REP);
        if (ret) {
            return ret;
        }
    }

    if (data->rmgroups != NULL) {
        ret = remove_from_groups(sysdb, data, member_dn);
        if (ret) {
            return ret;
        }
    }

    if (data->addgroups != NULL) {
        ret = add_to_groups(sysdb, data, member_dn);
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
             struct sysdb_ctx *sysdb,
             struct ops_ctx *data)
{
    struct sysdb_attrs *attrs = NULL;
    struct ldb_dn *member_dn = NULL;
    int ret;

    if (data->addgroups || data->rmgroups) {
        member_dn = sysdb_group_dn(sysdb, mem_ctx, data->name);
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

        ret = sysdb_set_group_attr(sysdb, data->name, attrs, SYSDB_MOD_REP);
        if (ret) {
            return ret;
        }
    }

    if (data->rmgroups != NULL) {
        ret = remove_from_groups(sysdb, data, member_dn);
        if (ret) {
            return ret;
        }
    }

    if (data->addgroups != NULL) {
        ret = add_to_groups(sysdb, data, member_dn);
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
    DEBUG(7, ("Gecos: %s\n", data->gecos));

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
    DEBUG(7, ("Homedir: %s\n", data->home));

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
    DEBUG(7, ("Shell: %s\n", data->shell));

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
    DEBUG(7, ("Auto create homedir: %s\n", data->create_homedir?"True":"False"));

    /* umask to create homedirs */
    ret = confdb_get_int(confdb,
                         conf_path, CONFDB_LOCAL_UMASK,
                         DFL_UMASK, (int *) &data->umask);
    if (ret != EOK) {
        goto done;
    }
    DEBUG(7, ("Umask: %o\n", data->umask));

    /* a directory to create mail spools in */
    ret = confdb_get_string(confdb, mem_ctx,
            conf_path, CONFDB_LOCAL_MAIL_DIR,
            DFL_MAIL_DIR, &data->maildir);
    if (ret != EOK) {
        goto done;
    }
    DEBUG(7, ("Mail dir: %s\n", data->maildir));

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
    DEBUG(7, ("Skeleton dir: %s\n", data->skeldir));

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
            struct sysdb_ctx *sysdb,
            struct ops_ctx *data)
{
    int ret;

    ret = sysdb_add_user(sysdb, data->name, data->uid, data->gid,
                         data->gecos, data->home, data->shell, NULL, 0, 0);
    if (ret) {
        goto done;
    }

    if (data->addgroups) {
        struct ldb_dn *member_dn;

        member_dn = sysdb_user_dn(sysdb, mem_ctx, data->name);
        if (!member_dn) {
            ret = ENOMEM;
            goto done;
        }

        ret = add_to_groups(sysdb, data, member_dn);
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

    user_dn = sysdb_user_dn(sysdb, mem_ctx, data->name);
    if (!user_dn) {
        DEBUG(1, ("Could not construct a user DN\n"));
        return ENOMEM;
    }

    ret = sysdb_delete_entry(sysdb, user_dn, false);
    if (ret) {
        DEBUG(2, ("Removing user failed: %s (%d)\n", strerror(ret), ret));
    }

    flush_nscd_cache(NSCD_DB_PASSWD);
    flush_nscd_cache(NSCD_DB_GROUP);

    return ret;
}

/*
 * Public interface for adding groups
 */
int groupadd(struct sysdb_ctx *sysdb,
             struct ops_ctx *data)
{
    int ret;

    ret = sysdb_add_group(sysdb, data->name, data->gid, NULL, 0, 0);
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

    group_dn = sysdb_group_dn(sysdb, mem_ctx, data->name);
    if (group_dn == NULL) {
        DEBUG(1, ("Could not construct a group DN\n"));
        return ENOMEM;
    }

    ret = sysdb_delete_entry(sysdb, group_dn, false);
    if (ret) {
        DEBUG(2, ("Removing group failed: %s (%d)\n", strerror(ret), ret));
    }

    flush_nscd_cache(NSCD_DB_GROUP);

    return ret;
}

/*
 * getpwnam, getgrnam and friends
 */
int sysdb_getpwnam_sync(TALLOC_CTX *mem_ctx,
                        struct sysdb_ctx *sysdb,
                        const char *name,
                        struct ops_ctx *out)
{
    struct ldb_result *res;
    const char *str;
    int ret;

    ret = sysdb_getpwnam(mem_ctx, sysdb, name, &res);
    if (ret) {
        return ret;
    }

    switch (res->count) {
    case 0:
        DEBUG(1, ("No result for sysdb_getpwnam call\n"));
        return ENOENT;

    case 1:
        /* fill ops_ctx */
        out->uid = ldb_msg_find_attr_as_uint64(res->msgs[0], SYSDB_UIDNUM, 0);

        out->gid = ldb_msg_find_attr_as_uint64(res->msgs[0], SYSDB_GIDNUM, 0);

        str = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, NULL);
        out->name = talloc_strdup(out, str);
        if (out->name == NULL) {
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
                DEBUG(2, ("Invalid value for %s attribute: %s\n",
                          SYSDB_DISABLED, str ? str : "NULL"));
                return EIO;
            }
        }
        break;

    default:
        DEBUG(1, ("More than one result for sysdb_getpwnam call\n"));
        return EIO;
    }

    return EOK;
}

int sysdb_getgrnam_sync(TALLOC_CTX *mem_ctx,
                        struct sysdb_ctx *sysdb,
                        const char *name,
                        struct ops_ctx *out)
{
    struct ldb_result *res;
    const char *str;
    int ret;

    ret = sysdb_getgrnam(mem_ctx, sysdb, name, &res);
    if (ret) {
        return ret;
    }

    switch (res->count) {
    case 0:
        DEBUG(1, ("No result for sysdb_getgrnam call\n"));
        return ENOENT;

    case 1:
        /* fill ops_ctx */
        out->gid = ldb_msg_find_attr_as_uint64(res->msgs[0], SYSDB_GIDNUM, 0);
        str = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, NULL);
        out->name = talloc_strdup(out, str);
        if (out->name == NULL) {
            return ENOMEM;
        }
        break;

    default:
        DEBUG(1, ("More than one result for sysdb_getgrnam call\n"));
        return EIO;
    }

    return EOK;
}

