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
#include <unistd.h>

#include "util/util.h"
#include "db/sysdb.h"
#include "tools/tools_util.h"
#include "util/sssd-i18n.h"

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

/* Default settings for user attributes */
#define CONFDB_DFL_SECTION "config/user_defaults"

#define DFL_SHELL_ATTR     "defaultShell"
#define DFL_BASEDIR_ATTR   "baseDirectory"

#define DFL_SHELL_VAL      "/bin/bash"
#define DFL_BASEDIR_VAL    "/home"

static void get_gid_callback(void *ptr, int error, struct ldb_result *res)
{
    struct ops_ctx *data = talloc_get_type(ptr, struct ops_ctx);

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
        if (data->gid == 0) {
            data->error = ERANGE;
        }
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
static int get_gid(struct ops_ctx *data, const char *groupname)
{
    char *end_ptr;
    int ret;

    errno = 0;
    data->gid = strtoul(groupname, &end_ptr, 10);
    if (groupname == '\0' || *end_ptr != '\0' ||
        errno != 0 || data->gid == 0) {
        /* Does not look like a gid - find the group name */

        ret = sysdb_getgrnam(data, data->ctx->sysdb,
                             data->domain, groupname,
                             get_gid_callback, data);
        if (ret != EOK) {
            DEBUG(1, ("sysdb_getgrnam failed: %d\n", ret));
            goto done;
        }

        data->error = EOK;
        data->gid = 0;
        while ((data->error == EOK) && (data->gid == 0)) {
            tevent_loop_once(data->ctx->ev);
        }

        if (data->error) {
            DEBUG(1, ("sysdb_getgrnam failed: %d\n", ret));
            goto done;
        }
    }

done:
    return ret;
}

static void add_user_req_done(struct tevent_req *req)
{
    struct ops_ctx *data = tevent_req_callback_data(req, struct ops_ctx);

    data->error = sysdb_transaction_commit_recv(req);
    data->done = true;
}

static void add_user_terminate(struct ops_ctx *data, int error)
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
    tevent_req_set_callback(req, add_user_req_done, data);

    return;

fail:
    /* free transaction */
    talloc_zfree(data->handle);

    data->error = error;
    data->done = true;
}

static void add_user_done(struct tevent_req *subreq);
static void add_to_groups(struct ops_ctx *data);
static void add_to_groups_done(struct tevent_req *req);

static void add_user(struct tevent_req *req)
{
    struct ops_ctx *data = tevent_req_callback_data(req, struct ops_ctx);
    struct tevent_req *subreq;
    int ret;

    ret = sysdb_transaction_recv(req, data, &data->handle);
    if (ret != EOK) {
        return add_user_terminate(data, ret);
    }

    subreq = sysdb_add_user_send(data, data->ev, data->handle,
                                 data->domain, data->name,
                                 data->uid, data->gid,
                                 data->gecos, data->home,
                                 data->shell, NULL);
    if (!subreq) {
        add_user_terminate(data, ENOMEM);
    }
    tevent_req_set_callback(subreq, add_user_done, data);
}

static void add_user_done(struct tevent_req *subreq)
{
    struct ops_ctx *data = tevent_req_callback_data(subreq, struct ops_ctx);
    int ret;

    ret = sysdb_add_user_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        return add_user_terminate(data, ret);
    }

    if (data->groups) {
        return add_to_groups(data);
    }

    return add_user_terminate(data, ret);
}

static void add_to_groups(struct ops_ctx *data)
{
    struct ldb_dn *parent_dn;
    struct ldb_dn *member_dn;
    struct tevent_req *subreq;

    member_dn = sysdb_user_dn(data->ctx->sysdb, data,
                              data->domain->name, data->name);
    if (!member_dn) {
        return add_user_terminate(data, ENOMEM);
    }

    parent_dn = sysdb_group_dn(data->ctx->sysdb, data,
                              data->domain->name,
                              data->groups[data->cur]);
    if (!parent_dn) {
        return add_user_terminate(data, ENOMEM);
    }

    subreq = sysdb_mod_group_member_send(data, data->ev, data->handle,
                                         member_dn, parent_dn,
                                         LDB_FLAG_MOD_ADD);
    if (!subreq) {
        return add_user_terminate(data, ENOMEM);
    }
    tevent_req_set_callback(subreq, add_to_groups_done, data);
}

static void add_to_groups_done(struct tevent_req *subreq)
{
    struct ops_ctx *data = tevent_req_callback_data(subreq, struct ops_ctx);
    int ret;

    ret = sysdb_mod_group_member_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        return add_user_terminate(data, ret);
    }

    /* go on to next group */
    data->cur++;

    /* check if we added all of them */
    if (data->groups[data->cur] == NULL) {
        return add_user_terminate(data, EOK);
    }

    return add_to_groups(data);
}

static int useradd_legacy(struct ops_ctx *ctx, char *grouplist)
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

    APPEND_PARAM(command, USERADD_USERNAME, ctx->name);

    ret = system(command);
    if (ret) {
        if (ret == -1) {
            DEBUG(1, ("system(3) failed\n"));
        } else {
            DEBUG(1, ("Could not exec '%s', return code: %d\n",
                      command, WEXITSTATUS(ret)));
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
    char *pc_shell = NULL;
    char *basedir = NULL;
    int pc_debug = 0;
    const char *pc_username = NULL;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        { "debug", '\0', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &pc_debug, 0, _("The debug level to run with"), NULL },
        { "uid",   'u', POPT_ARG_INT, &pc_uid, 0, _("The UID of the user"), NULL },
        { "gid",   'g', POPT_ARG_STRING, &pc_group, 0, _("The GID or group name of the user"), NULL },
        { "gecos", 'c', POPT_ARG_STRING, &pc_gecos, 0, _("The comment string"), NULL },
        { "home",  'h', POPT_ARG_STRING, &pc_home, 0, _("Home directory"), NULL },
        { "shell", 's', POPT_ARG_STRING, &pc_shell, 0, _("Login shell"), NULL },
        { "groups", 'G', POPT_ARG_STRING, NULL, 'G', _("Groups"), NULL },
        POPT_TABLEEND
    };
    poptContext pc = NULL;
    struct sss_domain_info *dom = NULL;
    struct ops_ctx *data = NULL;
    struct tools_ctx *ctx = NULL;
    struct tevent_req *req;
    char *groups = NULL;
    int ret;

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

    data = talloc_zero(ctx, struct ops_ctx);
    if (data == NULL) {
        DEBUG(1, ("Could not allocate memory for ops_ctx context\n"));
        ERROR("Out of memory\n");
        return ENOMEM;
    }
    data->ctx = ctx;
    data->ev = ctx->ev;

    /* parse ops_ctx */
    pc = poptGetContext(NULL, argc, argv, long_options, 0);
    poptSetOtherOptionHelp(pc, "USERNAME");
    while ((ret = poptGetNextOpt(pc)) > 0) {
        if (ret == 'G') {
            groups = poptGetOptArg(pc);
            if (!groups) {
                ret = -1;
                break;
            }

            ret = parse_groups(ctx, groups, &data->groups);
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
    pc_username = poptGetArg(pc);
    if (pc_username == NULL) {
        usage(pc, (_("Specify user to add\n")));
        ret = EXIT_FAILURE;
        goto fini;
    }

    ret = parse_name_domain(data, pc_username);
    if (ret != EOK) {
        ret = EXIT_FAILURE;
        goto fini;
    }

    /* Same as shadow-utils useradd, -g can specify gid or group name */
    if (pc_group != NULL) {
        ret = get_gid(data, pc_group);
        if (ret != EOK) {
            ERROR("Cannot get group information for the user\n");
            ret = EXIT_FAILURE;
            goto fini;
        }
    }

    data->uid = pc_uid;

    /*
     * Fills in defaults for ops_ctx user did not specify.
     * FIXME - Should this originate from the confdb or another config?
     */
    if (!pc_gecos) {
        pc_gecos = data->name;
    }
    data->gecos = talloc_strdup(data, pc_gecos);
    if (!data->gecos) {
        ret = EXIT_FAILURE;
        goto fini;
    }

    if (pc_home) {
        data->home = talloc_strdup(data, pc_home);
    } else {
        ret = confdb_get_string(data->ctx->confdb, data,
                                CONFDB_DFL_SECTION, DFL_BASEDIR_ATTR,
                                DFL_BASEDIR_VAL, &basedir);
        if (ret != EOK) {
            ret = EXIT_FAILURE;
            goto fini;
        }
        data->home = talloc_asprintf(data, "%s/%s", basedir, data->name);
        if (!data->home) {
            ret = EXIT_FAILURE;
            goto fini;
        }
    }
    if (!data->home) {
        ret = EXIT_FAILURE;
        goto fini;
    }

    if (!pc_shell) {
        ret = confdb_get_string(data->ctx->confdb, data,
                                CONFDB_DFL_SECTION, DFL_SHELL_ATTR,
                                DFL_SHELL_VAL, &pc_shell);
        if (ret != EOK) {
            ret = EXIT_FAILURE;
            goto fini;
        }
    }
    data->shell = talloc_strdup(data, pc_shell);
    if (!data->shell) {
        ret = EXIT_FAILURE;
        goto fini;
    }

    /* arguments processed, go on to actual work */
    ret = get_domain_by_id(data->ctx, data->uid, &dom);
    if (ret != EOK) {
        ERROR("Cannot get domain info\n");
        ret = EXIT_FAILURE;
        goto fini;
    }
    if (data->domain && data->uid && data->domain != dom) {
        ERROR("Selected domain %s conflicts with selected UID %llu\n",
                data->domain->name, (unsigned long long int) data->uid);
        ret = EXIT_FAILURE;
        goto fini;
    }
    if (data->domain == NULL && dom) {
        data->domain = dom;
    }

    ret = get_domain_type(data->ctx, data->domain);
    switch (ret) {
        case ID_IN_LOCAL:
            break;

        case ID_IN_LEGACY_LOCAL:
        case ID_OUTSIDE:
            ret = useradd_legacy(data, groups);
            if(ret != EOK) {
                ERROR("Cannot add user to domain using the legacy tools\n");
            }
            goto fini;

        case ID_IN_OTHER:
            DEBUG(1, ("Cannot add user to domain %s\n", dom->name));
            ERROR("Unsupported domain type\n");
            ret = EXIT_FAILURE;
            goto fini;

        default:
            DEBUG(1, ("Unknown return code %d from get_domain_type\n", ret));
            ERROR("Error looking up domain\n");
            ret = EXIT_FAILURE;
            goto fini;
    }

    /* useradd */
    req = sysdb_transaction_send(ctx, ctx->ev, ctx->sysdb);
    if (!req) {
        DEBUG(1, ("Could not start transaction (%d)[%s]\n", ret, strerror(ret)));
        ERROR("Transaction error. Could not modify user.\n");
        ret = EXIT_FAILURE;
        goto fini;
    }
    tevent_req_set_callback(req, add_user, data);

    while (!data->done) {
        tevent_loop_once(ctx->ev);
    }

    if (data->error) {
        ret = data->error;
        switch (ret) {
            case EEXIST:
                ERROR("A user with the same name or UID already exists\n");
                break;

            default:
                DEBUG(1, ("sysdb operation failed (%d)[%s]\n",
                          ret, strerror(ret)));
                ERROR("Transaction error. Could not add user.\n");
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
