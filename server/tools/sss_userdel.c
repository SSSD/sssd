/*
   SSSD

   sss_userdel

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
#include <pwd.h>
#include <unistd.h>

#include "db/sysdb.h"
#include "util/util.h"
#include "tools/tools_util.h"

static void userdel_req_done(struct tevent_req *req)
{
    struct ops_ctx *data = tevent_req_callback_data(req, struct ops_ctx);

    data->error = sysdb_transaction_commit_recv(req);
    data->done = true;
}

/* sysdb callback */
static void userdel_done(void *pvt, int error, struct ldb_result *ignore)
{
    struct ops_ctx *data = talloc_get_type(pvt, struct ops_ctx);
    struct tevent_req *req;

    if (error != EOK) {
        goto fail;
    }

    req = sysdb_transaction_commit_send(data, data->ctx->ev, data->handle);
    if (!req) {
        error = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(req, userdel_req_done, data);

    return;

fail:
    /* free transaction */
    talloc_zfree(data->handle);

    data->error = error;
    data->done = true;
}

static void user_del_done(struct tevent_req *subreq);

static void user_del(struct tevent_req *req)
{
    struct ops_ctx *data;
    struct tevent_req *subreq;
    struct ldb_dn *user_dn;
    int ret;

    data = tevent_req_callback_data(req, struct ops_ctx);

    ret = sysdb_transaction_recv(req, data, &data->handle);
    if (ret != EOK) {
        return userdel_done(data, ret, NULL);
    }

    user_dn = sysdb_user_dn(data->ctx->sysdb, data,
                            data->domain->name, data->name);
    if (!user_dn) {
        DEBUG(1, ("Could not construct a user DN\n"));
        return userdel_done(data, ENOMEM, NULL);
    }

    subreq = sysdb_delete_entry_send(data, data->ctx->ev, data->handle, user_dn, false);
    if (!subreq)
        return userdel_done(data, ENOMEM, NULL);

    tevent_req_set_callback(subreq, user_del_done, data);
}

static void user_del_done(struct tevent_req *subreq)
{
    struct ops_ctx *data = tevent_req_callback_data(subreq, struct ops_ctx);
    int ret;

    ret = sysdb_delete_entry_recv(subreq);

    return userdel_done(data, ret, NULL);
}

int main(int argc, const char **argv)
{
    int ret = EXIT_SUCCESS;
    struct ops_ctx *data = NULL;
    struct tevent_req *req;
    struct passwd *pwd_info;
    const char *pc_username = NULL;

    int pc_debug = 0;
    poptContext pc = NULL;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        { "debug", '\0', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &pc_debug,
                    0, _("The debug level to run with"), NULL },
        POPT_TABLEEND
    };

    debug_prg_name = argv[0];

    ret = set_locale();
    if (ret != EOK) {
        DEBUG(1, ("set_locale failed (%d): %s\n", ret, strerror(ret)));
        ERROR("Error setting the locale\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    /* parse parameters */
    pc = poptGetContext(NULL, argc, argv, long_options, 0);
    poptSetOtherOptionHelp(pc, "USERNAME");
    if ((ret = poptGetNextOpt(pc)) < -1) {
        usage(pc, poptStrerror(ret));
        ret = EXIT_FAILURE;
        goto fini;
    }

    debug_level = pc_debug;

    pc_username = poptGetArg(pc);
    if (pc_username == NULL) {
        usage(pc, _("Specify user to delete\n"));
        ret = EXIT_FAILURE;
        goto fini;
    }

    CHECK_ROOT(ret, debug_prg_name);

    ret = init_sss_tools(&data);
    if (ret != EOK) {
        DEBUG(1, ("init_sss_tools failed (%d): %s\n", ret, strerror(ret)));
        ERROR("Error initializing the tools\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    /* if the domain was not given as part of FQDN, default to local domain */
    ret = get_domain(data, pc_username);
    if (ret != EOK) {
        ERROR("Cannot get domain information\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    /* arguments processed, go on to actual work */
    pwd_info = getpwnam(data->name);
    if (pwd_info) {
        data->uid = pwd_info->pw_uid;
    }

    if (id_in_range(data->uid, data->domain) != EOK) {
        ERROR("The selected UID is outside the allowed range\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    /* userdel */
    req = sysdb_transaction_send(data, data->ctx->ev, data->ctx->sysdb);
    if (!req) {
        DEBUG(1, ("Could not start transaction (%d)[%s]\n", ret, strerror(ret)));
        ERROR("Transaction error. Could not remove user.\n");
        ret = EXIT_FAILURE;
        goto fini;
    }
    tevent_req_set_callback(req, user_del, data);

    while (!data->done) {
        tevent_loop_once(data->ctx->ev);
    }

    if (data->error) {
        ret = data->error;
        DEBUG(1, ("sysdb operation failed (%d)[%s]\n", ret, strerror(ret)));
        switch (ret) {
            case ENOENT:
                ERROR("No such user\n");
                break;

            default:
                ERROR("Internal error. Could not remove user.\n");
                break;
        }
        ret = EXIT_FAILURE;
        goto fini;
    }

    ret = EXIT_SUCCESS;

fini:
    talloc_free(data);
    poptFreeContext(pc);
    exit(ret);
}

