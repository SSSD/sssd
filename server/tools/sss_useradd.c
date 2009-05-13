/*
   SSSD

   sss_useradd

   Copyright (C) Jakub Hrozek <jhrozek@redhat.com>        2009
   Copyright (C) Simo Sorce <ssorce@redhat.com>           2009

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
#include <sys/types.h>
#include <sys/wait.h>

#include "util/util.h"
#include "db/sysdb.h"
#include "tools/tools_util.h"

/* Define default command strings if not redefined by user */
#ifndef USERADD
#define USERADD SHADOW_UTILS_PATH"/useradd "
#endif

#ifndef USERADD_UID
#define USERADD_UID "-u %u "
#endif

#ifndef USERADD_GID
#define USERADD_GID "-g %u "
#endif

#ifndef USERADD_GECOS
#define USERADD_GECOS "-c %s "
#endif

#ifndef USERADD_HOME
#define USERADD_HOME "-d %s "
#endif

#ifndef USERADD_SHELL
#define USERADD_SHELL "-s %s "
#endif

#ifndef USERADD_GROUPS
#define USERADD_GROUPS "-G %s "
#endif

#ifndef USERADD_UID_MIN
#define USERADD_UID_MIN "-K UID_MIN=%d "
#endif

#ifndef USERADD_UID_MAX
#define USERADD_UID_MAX "-K UID_MAX=%d "
#endif

#ifndef USERADD_USERNAME
#define USERADD_USERNAME "%s "
#endif


struct user_add_ctx {
    struct sysdb_req *sysreq;

    struct sss_domain_info *domain;
    struct tools_ctx *ctx;

    const char *username;
    uid_t uid;
    gid_t gid;
    char *gecos;
    char *home;
    char *shell;

    char **groups;
    int cur;

    int error;
    bool done;
};

struct fetch_group {
    gid_t gid;
    int error;
    bool done;
};

static void get_gid_callback(void *ptr, int error, struct ldb_result *res)
{
    struct fetch_group *data = talloc_get_type(ptr, struct fetch_group);

    data->done = true;

    if (error) {
        data->error = error;
        return;
    }

    switch (res->count) {
    case 0:
        data->error = ENOENT;
        break;

    case 1:
        data->gid = ldb_msg_find_attr_as_uint(res->msgs[0], SYSDB_GIDNUM, 0);
        break;

    default:
        data->error = EFAULT;
        break;
    }
}

/* Returns a gid for a given groupname. If a numerical gid
 * is given, returns that as integer (rationale: shadow-utils)
 * On error, returns -EINVAL
 */
static int get_gid(struct user_add_ctx *user_ctx, const char *groupname)
{
    struct tools_ctx *ctx = user_ctx->ctx;
    struct fetch_group *data = NULL;
    char *end_ptr;
    gid_t gid;
    int ret;

    errno = 0;
    gid = strtoul(groupname, &end_ptr, 10);
    if (groupname == '\0' || *end_ptr != '\0' || errno != 0) {
        /* Does not look like a gid - find the group name */

        data = talloc_zero(ctx, struct fetch_group);
        if (!data) return ENOMEM;

        ret = sysdb_getgrnam(data, ctx->sysdb,
                             user_ctx->domain, groupname,
                             get_gid_callback, data);
        if (ret != EOK) {
            DEBUG(0, ("sysdb_getgrnam failed: %d\n", ret));
            goto done;
        }

        while (!data->done) {
            tevent_loop_once(ctx->ev);
        }

        if (data->error) {
            ret = data->error;
            goto done;
        }

        gid = data->gid;
    }

    if (gid == 0) {
        ret = ERANGE;
    } else {
        user_ctx->gid = gid;
    }

done:
    talloc_free(data);
    return ret;
}

static void add_to_groups(void *, int, struct ldb_result *);

/* sysdb callback */
static void add_user_done(void *pvt, int error, struct ldb_result *ignore)
{
    struct user_add_ctx *data = talloc_get_type(pvt, struct user_add_ctx);

    data->done = true;

    sysdb_transaction_done(data->sysreq, error);

    if (error)
        data->error = error;
}

/* sysdb_req_fn_t */
static void add_user(struct sysdb_req *req, void *pvt)
{
    struct user_add_ctx *user_ctx;
    int ret;

    user_ctx = talloc_get_type(pvt, struct user_add_ctx);
    user_ctx->sysreq = req;

    ret = sysdb_add_user(req, user_ctx->domain,
                         user_ctx->username,
                         user_ctx->uid,
                         user_ctx->gid,
                         user_ctx->gecos,
                         user_ctx->home,
                         user_ctx->shell,
                         add_to_groups, user_ctx);

    if (ret != EOK)
        add_user_done(user_ctx, ret, NULL);
}

static void add_to_groups(void *pvt, int error, struct ldb_result *ignore)
{
    struct user_add_ctx *user_ctx = talloc_get_type(pvt, struct user_add_ctx);
    struct ldb_dn *group_dn;
    struct ldb_dn *user_dn;
    int ret;

    if (error) {
        add_user_done(pvt, error, NULL);
        return;
    }

    /* check if we added all of them */
    if (user_ctx->groups == NULL ||
        user_ctx->groups[user_ctx->cur] == NULL) {
        add_user_done(user_ctx, EOK, NULL);
        return;
    }

    user_dn = sysdb_user_dn(user_ctx->ctx->sysdb, user_ctx,
                            user_ctx->domain->name, user_ctx->username);
    if (!user_dn) {
        add_user_done(pvt, ENOMEM, NULL);
        return;
    }

    group_dn = sysdb_group_dn(user_ctx->ctx->sysdb, user_ctx,
                              user_ctx->domain->name,
                              user_ctx->groups[user_ctx->cur]);
    if (!group_dn) {
        add_user_done(pvt, ENOMEM, NULL);
        return;
    }

    ret = sysdb_add_group_member(user_ctx->sysreq,
                                 user_dn, group_dn,
                                 add_to_groups, user_ctx);
    if (ret != EOK)
        add_user_done(user_ctx, ret, NULL);

    /* go on to next group */
    user_ctx->cur++;
}

static int useradd_legacy(struct user_add_ctx *ctx, char *grouplist)
{
    int ret = EOK;
    char *command = NULL;

    APPEND_STRING(command, USERADD);

    APPEND_PARAM(command, USERADD_SHELL, ctx->shell);

    APPEND_PARAM(command, USERADD_GECOS, ctx->gecos);

    APPEND_PARAM(command, USERADD_HOME, ctx->home);

    APPEND_PARAM(command, USERADD_UID, ctx->uid);

    APPEND_PARAM(command, USERADD_GID, ctx->gid);

    APPEND_PARAM(command, USERADD_UID_MIN, ctx->domain->id_min);

    APPEND_PARAM(command, USERADD_UID_MAX, ctx->domain->id_max);

    APPEND_PARAM(command, USERADD_GROUPS, grouplist);

    APPEND_PARAM(command, USERADD_USERNAME, ctx->username);

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
    uid_t pc_uid = 0;
    const char *pc_group = NULL;
    const char *pc_gecos = NULL;
    const char *pc_home = NULL;
    const char *pc_shell = NULL;
    int pc_debug = 0;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        { "debug", '\0', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &pc_debug, 0, "The debug level to run with", NULL },
        { "uid",   'u', POPT_ARG_INT, &pc_uid, 0, "The UID of the user", NULL },
        { "gid",   'g', POPT_ARG_STRING, &pc_group, 0, "The GID or group name of the user", NULL },
        { "gecos", 'c', POPT_ARG_STRING, &pc_gecos, 0, "The comment string", NULL },
        { "home",  'h', POPT_ARG_STRING, &pc_home, 0, "Home directory", NULL },
        { "shell", 's', POPT_ARG_STRING, &pc_shell, 0, "Login shell", NULL },
        { "groups", 'G', POPT_ARG_STRING, NULL, 'G', "Groups", NULL },
        POPT_TABLEEND
    };
    poptContext pc = NULL;
    struct sss_domain_info *dom = NULL;
    struct user_add_ctx *user_ctx = NULL;
    struct tools_ctx *ctx = NULL;
    char *groups = NULL;
    int ret;

    debug_prg_name = argv[0];

    ret = setup_db(&ctx);
    if (ret != EOK) {
        DEBUG(0, ("Could not set up database\n"));
        ret = EXIT_FAILURE;
        goto fini;
    }

    user_ctx = talloc_zero(ctx, struct user_add_ctx);
    if (user_ctx == NULL) {
        DEBUG(0, ("Could not allocate memory for user_ctx context\n"));
        return ENOMEM;
    }
    user_ctx->ctx = ctx;

    /* parse user_ctx */
    pc = poptGetContext(NULL, argc, argv, long_options, 0);
    poptSetOtherOptionHelp(pc, "USERNAME");
    while ((ret = poptGetNextOpt(pc)) > 0) {
        if (ret == 'G') {
            groups = poptGetOptArg(pc);
            if (!groups) {
                ret = -1;
                break;
            }

            ret = parse_groups(ctx, groups, &user_ctx->groups);
            if (ret != EOK) {
                break;
            }
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
        usage(pc, "Specify user to add\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    /* Same as shadow-utils useradd, -g can specify gid or group name */
    if (pc_group != NULL) {
        ret = get_gid(user_ctx, pc_group);
        if (ret != EOK) {
            ret = EXIT_FAILURE;
            goto fini;
        }
    }

    user_ctx->uid = pc_uid;

    /*
     * Fills in defaults for user_ctx user did not specify.
     * FIXME - Should this originate from the confdb or another config?
     */
    if (!pc_gecos) {
        pc_gecos = user_ctx->username;
    }
    user_ctx->gecos = talloc_strdup(user_ctx, pc_gecos);
    if (!user_ctx->gecos) {
        ret = EXIT_FAILURE;
        goto fini;
    }

    if (pc_home) {
        user_ctx->home = talloc_strdup(user_ctx, pc_home);
    } else {
        user_ctx->home = talloc_asprintf(user_ctx, "/home/%s", user_ctx->username);
    }
    if (!user_ctx->home) {
        ret = EXIT_FAILURE;
        goto fini;
    }

    if (!pc_shell) {
        pc_shell = "/bin/bash";
    }
    user_ctx->shell = talloc_strdup(user_ctx, pc_shell);
    if (!user_ctx->shell) {
        ret = EXIT_FAILURE;
        goto fini;
    }

    /* arguments processed, go on to actual work */
    ret = find_domain_for_id(ctx, user_ctx->uid, &dom);
    switch (ret) {
        case ID_IN_LOCAL:
            user_ctx->domain = dom;
            break;

        case ID_IN_LEGACY_LOCAL:
            user_ctx->domain = dom;
        case ID_OUTSIDE:
            ret = useradd_legacy(user_ctx, groups);
            goto fini;

        case ID_IN_OTHER:
            DEBUG(0, ("Cannot add user to domain %s\n", dom->name));
            ret = EXIT_FAILURE;
            goto fini;

        default:
            DEBUG(0, ("Unknown return code from find_domain_for_id"));
            ret = EXIT_FAILURE;
            goto fini;
    }

    /* useradd */
    ret = sysdb_transaction(ctx, ctx->sysdb, add_user, user_ctx);
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
        switch (ret) {
            case EEXIST:
                DEBUG(0, ("The user %s already exists\n", user_ctx->username));
                break;

            default:
                DEBUG(0, ("Operation failed (%d)[%s]\n", ret, strerror(ret)));
                break;
        }
        ret = EXIT_FAILURE;
        goto fini;
    }

    ret = EXIT_SUCCESS;

fini:
    poptFreeContext(pc);
    talloc_free(ctx);
    free(groups);
    exit(ret);
}
