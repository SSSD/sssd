/*
   SSSD

   sss_usermod

   Copyright (C) Jakub Hrozek <jhrozek@redhat.com>        2009

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
#include <errno.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "util/util.h"
#include "db/sysdb.h"
#include "tools/tools_util.h"

#define DO_LOCK     1
#define DO_UNLOCK   2

#define VAR_CHECK(var, val, msg) do { \
        if (var != (val)) { \
            DEBUG(0, (msg)); \
            var = EXIT_FAILURE; \
            goto fini; \
        } \
} while(0)

/* Define default command strings if not redefined by user */
#ifndef USERMOD
#define USERMOD SHADOW_UTILS_PATH"/usermod "
#endif

#ifndef USERMOD_UID
#define USERMOD_UID "-u %u "
#endif

#ifndef USERMOD_GID
#define USERMOD_GID "-g %u "
#endif

#ifndef USERMOD_GECOS
#define USERMOD_GECOS "-c %s "
#endif

#ifndef USERMOD_HOME
#define USERMOD_HOME "-d %s "
#endif

#ifndef USERMOD_SHELL
#define USERMOD_SHELL "-s %s "
#endif

#ifndef USERMOD_LOCK
#define USERMOD_LOCK  "--lock "
#endif

#ifndef USERMOD_UNLOCK
#define USERMOD_UNLOCK "--unlock "
#endif

#ifndef USERMOD_USERNAME
#define USERMOD_USERNAME "%s"
#endif

struct user_mod_ctx {
    struct sysdb_req *sysreq;

    struct sss_domain_info *domain;
    struct tools_ctx *ctx;

    const char *username;
    struct sysdb_attrs *attrs;

    char **addgroups;
    char **rmgroups;
    int cur;

    int error;
    bool done;
};

/* sysdb callback */
static void mod_user_done(void *pvt, int error, struct ldb_result *ignore)
{
    struct user_mod_ctx *data = talloc_get_type(pvt, struct user_mod_ctx);

    data->done = true;

    sysdb_transaction_done(data->sysreq, error);

    if (error)
        data->error = error;
}

static void add_to_groups(void *, int, struct ldb_result *);

/* sysdb_req_fn_t */
static void mod_user(struct sysdb_req *req, void *pvt)
{
    struct user_mod_ctx *user_ctx;
    int ret;

    user_ctx = talloc_get_type(pvt, struct user_mod_ctx);
    user_ctx->sysreq = req;

    if(user_ctx->attrs->num == 0) {
        add_to_groups(user_ctx, EOK, NULL);
    } else {
        ret = sysdb_set_user_attr(req,
                                  user_ctx->domain,
                                  user_ctx->username,
                                  user_ctx->attrs,
                                  add_to_groups,
                                  user_ctx);

        if (ret != EOK) {
            mod_user_done(user_ctx, ret, NULL);
        }
    }
}

static void remove_from_groups(void *pvt, int error, struct ldb_result *ignore)
{
    struct user_mod_ctx *user_ctx = talloc_get_type(pvt, struct user_mod_ctx);
    struct ldb_dn *group_dn;
    struct ldb_dn *user_dn;
    int ret;

    if (error) {
        mod_user_done(pvt, error, NULL);
        return;
    }

    /* check if we removed all of them */
    if (user_ctx->rmgroups == NULL ||
        user_ctx->rmgroups[user_ctx->cur] == NULL) {
        mod_user_done(user_ctx, EOK, NULL);
        return;
    }

    user_dn = sysdb_user_dn(user_ctx->ctx->sysdb, user_ctx,
                            user_ctx->domain->name, user_ctx->username);
    if (!user_dn) {
        mod_user_done(pvt, ENOMEM, NULL);
        return;
    }

    group_dn = sysdb_group_dn(user_ctx->ctx->sysdb, user_ctx,
                              user_ctx->domain->name,
                              user_ctx->rmgroups[user_ctx->cur]);
    if (!group_dn) {
        mod_user_done(pvt, ENOMEM, NULL);
        return;
    }

    ret = sysdb_remove_group_member(user_ctx->sysreq,
                                    user_dn, group_dn,
                                    remove_from_groups, user_ctx);
    if (ret != EOK)
        mod_user_done(user_ctx, ret, NULL);

    /* go on to next group */
    user_ctx->cur++;
}

static void add_to_groups(void *pvt, int error, struct ldb_result *ignore)
{
    struct user_mod_ctx *user_ctx = talloc_get_type(pvt, struct user_mod_ctx);
    struct ldb_dn *group_dn;
    struct ldb_dn *user_dn;
    int ret;

    if (error) {
        mod_user_done(pvt, error, NULL);
        return;
    }

    /* check if we added all of them */
    if (user_ctx->addgroups == NULL ||
        user_ctx->addgroups[user_ctx->cur] == NULL) {
        user_ctx->cur = 0;
        remove_from_groups(user_ctx, EOK, NULL);
        return;
    }

    user_dn = sysdb_user_dn(user_ctx->ctx->sysdb, user_ctx,
                            user_ctx->domain->name, user_ctx->username);
    if (!user_dn) {
        mod_user_done(pvt, ENOMEM, NULL);
        return;
    }

    group_dn = sysdb_group_dn(user_ctx->ctx->sysdb, user_ctx,
                              user_ctx->domain->name,
                              user_ctx->addgroups[user_ctx->cur]);
    if (!group_dn) {
        mod_user_done(pvt, ENOMEM, NULL);
        return;
    }

    ret = sysdb_add_group_member(user_ctx->sysreq,
                                 user_dn, group_dn,
                                 add_to_groups, user_ctx);
    if (ret != EOK)
        mod_user_done(user_ctx, ret, NULL);

    /* go on to next group */
    user_ctx->cur++;
}

static int usermod_legacy(struct tools_ctx *tools_ctx, struct user_mod_ctx *ctx,
                          uid_t uid, gid_t gid,
                          const char *gecos, const char *home,
                          const char *shell, int lock, int old_domain)
{
    int ret = EOK;
    char *command = NULL;
    struct sss_domain_info *dom = NULL;

    APPEND_STRING(command, USERMOD);

    if (uid) {
        ret = find_domain_for_id(tools_ctx, uid, &dom);
        if (ret == old_domain) {
            APPEND_PARAM(command, USERMOD_UID, uid);
        } else {
            DEBUG(0, ("Changing uid only allowed inside the same domain\n"));
            talloc_free(command);
            return EINVAL;
        }
    }

    if (gid) {
        ret = find_domain_for_id(tools_ctx, gid, &dom);
        if (ret == old_domain) {
            APPEND_PARAM(command, USERMOD_GID, gid);
        } else {
            DEBUG(0, ("Changing gid only allowed inside the same domain\n"));
            talloc_free(command);
            return EINVAL;
        }
    }

    APPEND_PARAM(command, USERMOD_GECOS, gecos);
    APPEND_PARAM(command, USERMOD_HOME, home);
    APPEND_PARAM(command, USERMOD_SHELL, shell);

    if (lock == DO_LOCK) {
        APPEND_STRING(command, USERMOD_LOCK);
    }

    if (lock == DO_UNLOCK) {
        APPEND_STRING(command, USERMOD_UNLOCK);
    }

    APPEND_PARAM(command, USERMOD_USERNAME, ctx->username);

    ret = system(command);
    if (ret) {
        if (ret == -1) {
            DEBUG(0, ("system(3) failed\n"));
        } else {
            DEBUG(0,("Could not exec '%s', return code: %d\n", command, WEXITSTATUS(ret)));
        }
        talloc_free(command);
        return EFAULT;
    }

    talloc_free(command);
    return ret;
}

int main(int argc, const char **argv)
{
    int pc_lock = 0;
    uid_t pc_uid = 0;
    gid_t pc_gid = 0;
    const char *pc_gecos = NULL;
    const char *pc_home = NULL;
    const char *pc_shell = NULL;
    int pc_debug = 0;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        { "debug", '\0', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &pc_debug, 0, "The debug level to run with", NULL },
        { "uid",   'u', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &pc_uid, 0, "The UID of the user", NULL },
        { "gid",   'g', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &pc_gid, 0, "The GID of the user", NULL },
        { "gecos", 'c', POPT_ARG_STRING, &pc_gecos, 0, "The comment string", NULL },
        { "home",  'h', POPT_ARG_STRING, &pc_home, 0, "Home directory", NULL },
        { "shell", 's', POPT_ARG_STRING, &pc_shell, 0, "Login shell", NULL },
        { "append-group", 'a', POPT_ARG_STRING, NULL, 'a', "Groups to add this user to", NULL },
        { "remove-group", 'r', POPT_ARG_STRING, NULL, 'r', "Groups to remove this user from", NULL },
        { "lock", 'L', POPT_ARG_NONE, NULL, 'L', "Lock the account", NULL },
        { "unlock", 'U', POPT_ARG_NONE, NULL, 'U', "Unlock the account", NULL },
        POPT_TABLEEND
    };
    poptContext pc = NULL;
    struct sss_domain_info *dom;
    struct user_mod_ctx *user_ctx = NULL;
    struct tools_ctx *ctx = NULL;
    char *groups;
    int ret;
    struct passwd *pwd_info;
    uid_t old_uid = 0;

    debug_prg_name = argv[0];

    ret = init_sss_tools(&ctx);
    if (ret != EOK) {
        DEBUG(0, ("Could not set up tools\n"));
        ret = EXIT_FAILURE;
        goto fini;
    }

    user_ctx = talloc_zero(ctx, struct user_mod_ctx);
    if (user_ctx == NULL) {
        DEBUG(0, ("Could not allocate memory for user_ctx context\n"));
        return ENOMEM;
    }
    user_ctx->ctx = ctx;

    user_ctx->attrs = sysdb_new_attrs(ctx);
    if (user_ctx->attrs == NULL) {
        DEBUG(0, ("Could not allocate memory for sysdb_attrs\n"));
        return ENOMEM;
    }

    /* parse user_ctx */
    pc = poptGetContext(NULL, argc, argv, long_options, 0);
    poptSetOtherOptionHelp(pc, "USERNAME");
    while ((ret = poptGetNextOpt(pc)) > 0) {
        if (ret == 'a' || ret == 'r') {
            groups = poptGetOptArg(pc);
            if (!groups) {
                ret = -1;
                break;
            }

            ret = parse_groups(ctx,
                    groups,
                    (ret == 'a') ? (&user_ctx->addgroups) : (&user_ctx->rmgroups));

            free(groups);
            if (ret != EOK) {
                break;
            }
        } else if (ret == 'L') {
            pc_lock = DO_LOCK;
        } else if (ret == 'U') {
            pc_lock = DO_UNLOCK;
        }
    }

    debug_level = pc_debug;

    if(ret != -1) {
        usage(pc, poptStrerror(ret));
        ret = EXIT_FAILURE;
        goto fini;
    }

    /* username is an argument without --option */
    user_ctx->username = poptGetArg(pc);
    if (user_ctx->username == NULL) {
        usage(pc, "Specify user to modify\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    pwd_info = getpwnam(user_ctx->username);
    if (pwd_info) {
        old_uid = pwd_info->pw_uid;
    }

    ret = find_domain_for_id(ctx, old_uid, &dom);
    switch (ret) {
        case ID_IN_LOCAL:
            user_ctx->domain = dom;
            break;

        case ID_IN_LEGACY_LOCAL:
            user_ctx->domain = dom;
        case ID_OUTSIDE:
            ret = usermod_legacy(ctx, user_ctx, pc_uid, pc_gid, pc_gecos,
                                 pc_home, pc_shell, pc_lock, ret);
            goto fini;

        case ID_IN_OTHER:
            DEBUG(0, ("Cannot delete user from domain %s\n", dom->name));
            ret = EXIT_FAILURE;
            goto fini;

        default:
            DEBUG(0, ("Unknown return code from find_domain_for_id"));
            ret = EXIT_FAILURE;
            goto fini;
    }

    /* add parameters to changeset */
    /* FIXME - might want to do this via attr:pc_var mapping in a loop */

    if(pc_shell) {
        ret = sysdb_attrs_add_string(user_ctx->attrs,
                                     SYSDB_SHELL,
                                     pc_shell);
        VAR_CHECK(ret, EOK, "Could not add attribute to changeset\n");
    }

    if(pc_home) {
        ret = sysdb_attrs_add_string(user_ctx->attrs,
                                     SYSDB_HOMEDIR,
                                     pc_home);
        VAR_CHECK(ret, EOK, "Could not add attribute to changeset\n");
    }

    if(pc_gecos) {
        ret = sysdb_attrs_add_string(user_ctx->attrs,
                                     SYSDB_GECOS,
                                     pc_gecos);
        VAR_CHECK(ret, EOK, "Could not add attribute to changeset\n");
    }

    if(pc_uid) {
        ret = sysdb_attrs_add_long(user_ctx->attrs,
                                   SYSDB_UIDNUM,
                                   pc_uid);
        VAR_CHECK(ret, EOK, "Could not add attribute to changeset\n");
    }

    if(pc_gid) {
        ret = sysdb_attrs_add_long(user_ctx->attrs,
                                   SYSDB_GIDNUM,
                                   pc_gid);
        VAR_CHECK(ret, EOK, "Could not add attribute to changeset\n");
    }

    if(pc_lock == DO_LOCK) {
        ret = sysdb_attrs_add_string(user_ctx->attrs,
                                     SYSDB_DISABLED,
                                     "true");
        VAR_CHECK(ret, EOK, "Could not add attribute to changeset\n");
    }

    if(pc_lock == DO_UNLOCK) {
        /* PAM code checks for 'false' value in SYSDB_DISABLED attribute */
        ret = sysdb_attrs_add_string(user_ctx->attrs,
                                     SYSDB_DISABLED,
                                     "false");
        VAR_CHECK(ret, EOK, "Could not add attribute to changeset\n");
    }


    /* arguments processed, go on to actual work */
    for (dom = ctx->domains; dom; dom = dom->next) {
        if (strcasecmp(dom->name, "LOCAL") == 0) break;
    }
    if (dom == NULL) {
        DEBUG(0, ("Could not get domain info\n"));
        ret = EXIT_FAILURE;
        goto fini;
    }
    user_ctx->domain = dom;

    ret = sysdb_transaction(ctx, ctx->sysdb, mod_user, user_ctx);
    if (ret != EOK) {
        DEBUG(0, ("Could not start transaction (%d)[%s]\n",
                  ret, strerror(ret)));
        ret = EXIT_FAILURE;
        goto fini;
    }

    while (!user_ctx->done) {
        tevent_loop_once(ctx->ev);
    }

    if (user_ctx->error) {
        ret = user_ctx->error;
        DEBUG(0, ("Operation failed (%d)[%s]\n", ret, strerror(ret)));
        ret = EXIT_FAILURE;
        goto fini;
    }

    ret = EXIT_SUCCESS;

fini:
    poptFreeContext(pc);
    talloc_free(ctx);
    exit(ret);
}
