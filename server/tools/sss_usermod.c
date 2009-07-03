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
#include <unistd.h>

#include "util/util.h"
#include "db/sysdb.h"
#include "tools/tools_util.h"

#define DO_LOCK     1
#define DO_UNLOCK   2

#define VAR_CHECK(var, val, attr, msg) do { \
        if (var != (val)) { \
            DEBUG(1, (msg" attribute: %s", attr)); \
            ERROR(msg); \
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
    struct tevent_context *ev;
    struct sysdb_handle *handle;

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

static void mod_user_req_done(struct tevent_req *req)
{
    struct user_mod_ctx *data = tevent_req_callback_data(req,
                                                         struct user_mod_ctx);

    data->error = sysdb_transaction_commit_recv(req);
    data->done = true;

    talloc_zfree(data->handle);
}

static void mod_user_done(struct user_mod_ctx *data, int error)
{
    struct tevent_req *req;

    if (error != EOK) {
        goto fail;
    }

    req = sysdb_transaction_commit_send(data, data->ev, data->handle);
    if (!req) {
        error = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(req, mod_user_req_done, data);

    return;

fail:
    /* free transaction */
    talloc_zfree(data->handle);

    data->error = error;
    data->done = true;
}

static void mod_user_attr_done(struct tevent_req *req);
static void mod_user_cont(struct user_mod_ctx *data);
static void remove_from_groups(struct user_mod_ctx *data);
static void remove_from_groups_done(struct tevent_req *req);
static void add_to_groups(struct user_mod_ctx *data);
static void add_to_groups_done(struct tevent_req *req);

static void mod_user(struct tevent_req *req)
{
    struct user_mod_ctx *data;
    struct tevent_req *subreq;
    int ret;

    data = tevent_req_callback_data(req, struct user_mod_ctx);

    ret = sysdb_transaction_recv(req, data, &data->handle);
    if (ret != EOK) {
        return mod_user_done(data, ret);
    }

    if (data->attrs->num != 0) {
        subreq = sysdb_set_user_attr_send(data, data->ev, data->handle,
                                          data->domain, data->username,
                                          data->attrs, SYSDB_MOD_REP);
        if (!subreq) {
            return mod_user_done(data, ret);
        }
        tevent_req_set_callback(subreq, mod_user_attr_done, data);
        return;
    }

    return mod_user_cont(data);
}

static void mod_user_attr_done(struct tevent_req *subreq)
{
    struct user_mod_ctx *data = tevent_req_callback_data(subreq,
                                                         struct user_mod_ctx);
    int ret;

    ret = sysdb_set_user_attr_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        return mod_user_done(data, ret);
    }

    mod_user_cont(data);
}

static void mod_user_cont(struct user_mod_ctx *data)
{
    if (data->rmgroups != NULL) {
        return remove_from_groups(data);
    }

    if (data->addgroups != NULL) {
        return add_to_groups(data);
    }

    return mod_user_done(data, EOK);
}

static void remove_from_groups(struct user_mod_ctx *data)
{
    struct ldb_dn *parent_dn;
    struct ldb_dn *member_dn;
    struct tevent_req *req;

    member_dn = sysdb_group_dn(data->ctx->sysdb, data,
                              data->domain->name, data->username);
    if (!member_dn) {
        return mod_user_done(data, ENOMEM);
    }

    parent_dn = sysdb_group_dn(data->ctx->sysdb, data,
                               data->domain->name,
                               data->rmgroups[data->cur]);
    if (!parent_dn) {
        return mod_user_done(data, ENOMEM);
    }

    req = sysdb_mod_group_member_send(data,
                                      data->ev,
                                      data->handle,
                                      member_dn,
                                      parent_dn,
                                      LDB_FLAG_MOD_DELETE);
    if (!req) {
        return mod_user_done(data, ENOMEM);
    }
    tevent_req_set_callback(req, remove_from_groups_done, data);
}

static void remove_from_groups_done(struct tevent_req *req)
{
    struct user_mod_ctx *data = tevent_req_callback_data(req,
                                                 struct user_mod_ctx);
    int ret;

    ret = sysdb_mod_group_member_recv(req);
    if (ret) {
        return mod_user_done(data, ret);
    }
    talloc_zfree(req);

    /* go on to next group */
    data->cur++;

    /* check if we added all of them */
    if (data->rmgroups[data->cur] == NULL) {
        data->cur = 0;
        if (data->addgroups != NULL) {
            return remove_from_groups(data);
        }
        return mod_user_done(data, EOK);
    }

    return remove_from_groups(data);
}

static void add_to_groups(struct user_mod_ctx *data)
{
    struct ldb_dn *parent_dn;
    struct ldb_dn *member_dn;
    struct tevent_req *req;

    member_dn = sysdb_group_dn(data->ctx->sysdb, data,
                              data->domain->name, data->username);
    if (!member_dn) {
        return mod_user_done(data, ENOMEM);
    }

    parent_dn = sysdb_group_dn(data->ctx->sysdb, data,
                              data->domain->name,
                              data->addgroups[data->cur]);
    if (!parent_dn) {
        return mod_user_done(data, ENOMEM);
    }

    req = sysdb_mod_group_member_send(data,
                                      data->ev,
                                      data->handle,
                                      member_dn,
                                      parent_dn,
                                      LDB_FLAG_MOD_ADD);
    if (!req) {
        return mod_user_done(data, ENOMEM);
    }
    tevent_req_set_callback(req, add_to_groups_done, data);
}

static void add_to_groups_done(struct tevent_req *req)
{
    struct user_mod_ctx *data = tevent_req_callback_data(req,
                                                 struct user_mod_ctx);
    int ret;

    ret = sysdb_mod_group_member_recv(req);
    if (ret) {
        return mod_user_done(data, ret);
    }
    talloc_zfree(req);

    /* go on to next group */
    data->cur++;

    /* check if we added all of them */
    if (data->addgroups[data->cur] == NULL) {
        return mod_user_done(data, EOK);
    }

    return add_to_groups(data);
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
            ERROR("Changing uid only allowed inside the same domain\n");
            talloc_free(command);
            return EINVAL;
        }
    }

    if (gid) {
        ret = find_domain_for_id(tools_ctx, gid, &dom);
        if (ret == old_domain) {
            APPEND_PARAM(command, USERMOD_GID, gid);
        } else {
            ERROR("Changing gid only allowed inside the same domain\n");
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
            DEBUG(1, ("system(3) failed\n"));
        } else {
            DEBUG(1, ("Could not exec '%s', return code: %d\n", command, WEXITSTATUS(ret)));
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
        { "debug", '\0', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &pc_debug, 0, _("The debug level to run with"), NULL },
        { "uid",   'u', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &pc_uid, 0, _("The UID of the user"), NULL },
        { "gid",   'g', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &pc_gid, 0, _("The GID of the user"), NULL },
        { "gecos", 'c', POPT_ARG_STRING, &pc_gecos, 0, _("The comment string"), NULL },
        { "home",  'h', POPT_ARG_STRING, &pc_home, 0, _("Home directory"), NULL },
        { "shell", 's', POPT_ARG_STRING, &pc_shell, 0, _("Login shell"), NULL },
        { "append-group", 'a', POPT_ARG_STRING, NULL, 'a', _("Groups to add this user to"), NULL },
        { "remove-group", 'r', POPT_ARG_STRING, NULL, 'r', _("Groups to remove this user from"), NULL },
        { "lock", 'L', POPT_ARG_NONE, NULL, 'L', _("Lock the account"), NULL },
        { "unlock", 'U', POPT_ARG_NONE, NULL, 'U', _("Unlock the account"), NULL },
        POPT_TABLEEND
    };
    poptContext pc = NULL;
    struct sss_domain_info *dom;
    struct user_mod_ctx *user_ctx = NULL;
    struct tools_ctx *ctx = NULL;
    struct tevent_req *req;
    char *groups;
    int ret;
    struct passwd *pwd_info;
    uid_t old_uid = 0;

    debug_prg_name = argv[0];

    ret = set_locale();
    if (ret != EOK) {
        DEBUG(1, ("set_locale failed (%d): %s\n", ret, strerror(ret)));
        ERROR("Error setting the locale\n");
        ret = EXIT_FAILURE;
        goto fini;
    }
    CHECK_ROOT(ret, debug_prg_name);

    ret = init_sss_tools(&ctx);
    if (ret != EOK) {
        DEBUG(1, ("init_sss_tools failed (%d): %s\n", ret, strerror(ret)));
        ERROR("Error initializing the tools\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    user_ctx = talloc_zero(ctx, struct user_mod_ctx);
    if (user_ctx == NULL) {
        DEBUG(1, ("Could not allocate memory for user_ctx context\n"));
        ERROR("Out of memory\n");
        return ENOMEM;
    }
    user_ctx->ctx = ctx;

    user_ctx->attrs = sysdb_new_attrs(ctx);
    if (user_ctx->attrs == NULL) {
        DEBUG(1, ("Could not allocate memory for sysdb_attrs context\n"));
        ERROR("Out of memory\n");
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
        usage(pc, _("Specify user to modify\n"));
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
            if(ret != EOK) {
                ERROR("Cannot delete user from domain using the legacy tools\n");
            }
            goto fini;

        case ID_IN_OTHER:
            DEBUG(1, ("Cannot modify user from domain %s\n", dom->name));
            ERROR("Unsupported domain type\n");
            ret = EXIT_FAILURE;
            goto fini;

        default:
            DEBUG(1, ("Unknown return code %d from find_domain_for_id\n", ret));
            ERROR("Error looking up domain\n");
            ret = EXIT_FAILURE;
            goto fini;
    }

    /* add parameters to changeset */
    /* FIXME - might want to do this via attr:pc_var mapping in a loop */

    if(pc_shell) {
        ret = sysdb_attrs_add_string(user_ctx->attrs,
                                     SYSDB_SHELL,
                                     pc_shell);
        VAR_CHECK(ret, EOK, SYSDB_SHELL,
                  "Could not add attribute to changeset\n");
    }

    if(pc_home) {
        ret = sysdb_attrs_add_string(user_ctx->attrs,
                                     SYSDB_HOMEDIR,
                                     pc_home);
        VAR_CHECK(ret, EOK, SYSDB_HOMEDIR,
                  "Could not add attribute to changeset\n");
    }

    if(pc_gecos) {
        ret = sysdb_attrs_add_string(user_ctx->attrs,
                                     SYSDB_GECOS,
                                     pc_gecos);
        VAR_CHECK(ret, EOK, SYSDB_GECOS,
                  "Could not add attribute to changeset\n");
    }

    if(pc_uid) {
        ret = sysdb_attrs_add_long(user_ctx->attrs,
                                   SYSDB_UIDNUM,
                                   pc_uid);
        VAR_CHECK(ret, EOK, SYSDB_UIDNUM,
                  "Could not add attribute to changeset\n");
    }

    if(pc_gid) {
        ret = sysdb_attrs_add_long(user_ctx->attrs,
                                   SYSDB_GIDNUM,
                                   pc_gid);
        VAR_CHECK(ret, EOK, SYSDB_GIDNUM,
                  "Could not add attribute to changeset\n");
    }

    if(pc_lock == DO_LOCK) {
        ret = sysdb_attrs_add_string(user_ctx->attrs,
                                     SYSDB_DISABLED,
                                     "true");
        VAR_CHECK(ret, EOK, SYSDB_DISABLED,
                  "Could not add attribute to changeset\n");
    }

    if(pc_lock == DO_UNLOCK) {
        /* PAM code checks for 'false' value in SYSDB_DISABLED attribute */
        ret = sysdb_attrs_add_string(user_ctx->attrs,
                                     SYSDB_DISABLED,
                                     "false");
        VAR_CHECK(ret, EOK, SYSDB_DISABLED,
                  "Could not add attribute to changeset\n");
    }


    /* arguments processed, go on to actual work */
    for (dom = ctx->domains; dom; dom = dom->next) {
        if (strcasecmp(dom->name, "LOCAL") == 0) break;
    }
    if (dom == NULL) {
        ERROR("Could not get LOCAL domain info\n");
        ret = EXIT_FAILURE;
        goto fini;
    }
    user_ctx->domain = dom;

    req = sysdb_transaction_send(ctx, ctx->ev, ctx->sysdb);
    if (!req) {
        DEBUG(1, ("Could not start transaction (%d)[%s]\n", ret, strerror(ret)));
        ERROR("Transaction error. Could not modify user.\n");
        ret = EXIT_FAILURE;
        goto fini;
    }
    tevent_req_set_callback(req, mod_user, user_ctx);

    while (!user_ctx->done) {
        tevent_loop_once(ctx->ev);
    }

    if (user_ctx->error) {
        ret = user_ctx->error;
        DEBUG(1, ("sysdb operation failed (%d)[%s]\n", ret, strerror(ret)));
        ERROR("Transaction error. Could not modify user.\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    ret = EXIT_SUCCESS;

fini:
    poptFreeContext(pc);
    talloc_free(ctx);
    exit(ret);
}
