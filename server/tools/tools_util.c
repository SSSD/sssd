/*
   SSSD

   tools_utils.c

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

#include <talloc.h>
#include <tevent.h>
#include <popt.h>

#include "util/util.h"
#include "confdb/confdb.h"
#include "db/sysdb.h"
#include "tools/tools_util.h"

/* Even in LOCAL database, we must enforce MPG. That means enforcing the following rules:
 *
 * 1. Users and groups must share the same name space. There can never be
 *    a real group that has the same name of a real user.
 * 2. Users and Groups must share the same ID space a group can never have
 *    a gidNumber that is numerically equal to a uidNumber Otherwise the
 *    user MPG will conflict with said group.
 */

struct ucheck {
    bool done;
    bool dup;
    int error;
};

void check_unique_callback(void *ptr, int error, struct ldb_result *res)
{
    struct ucheck *data = talloc_get_type(ptr, struct ucheck);

    data->done = true;

    if (error) {
        data->error = error;
    }

    if (res->count != 0) {
        data->dup = true;
    }
}

int check_user_name_unique(struct tools_ctx *ctx, const char *name)
{
    struct ucheck *data;
    int ret = EOK;

    data = talloc_zero(NULL, struct ucheck);
    if (!data) return ENOMEM;

    ret = sysdb_getgrnam(data, ctx->sysdb,
                         "LOCAL", name, false,
                         check_unique_callback, data);
    if (ret != EOK) {
        DEBUG(1, ("sysdb_getgrnam failed: %d\n", ret));
        goto done;
    }

    while (!data->done) {
        tevent_loop_once(ctx->ev);
    }

    if (data->error) {
        ret = data->error;
        goto done;
    }

    if (data->dup) {
        ret = EEXIST;
    }

done:
    talloc_free(data);
    return ret;
}

int check_group_name_unique(struct tools_ctx *ctx, const char *name)
{
    struct ucheck *data;
    int ret;

    data = talloc_zero(NULL, struct ucheck);
    if (!data) return ENOMEM;

    ret = sysdb_getpwnam(data, ctx->sysdb,
                         "LOCAL", name, false,
                         check_unique_callback, data);
    if (ret != EOK) {
        DEBUG(1, ("sysdb_getgrnam failed: %d\n", ret));
        goto done;
    }

    while (!data->done) {
        tevent_loop_once(ctx->ev);
    }

    if (data->error) {
        ret = data->error;
        goto done;
    }

    if (data->dup) {
        ret = EEXIST;
    }

done:
    talloc_free(data);
    return ret;
}

int setup_db(struct tools_ctx **tools_ctx)
{
    TALLOC_CTX *tmp_ctx;
    char *confdb_path;
    struct tools_ctx *ctx;
    int ret;

    ctx = talloc_zero(NULL, struct tools_ctx);
    if (ctx == NULL) {
        DEBUG(1, ("Could not allocate memory for tools context"));
        return ENOMEM;
    }

    /* Create the event context */
    ctx->ev = tevent_context_init(ctx);
    if (ctx->ev == NULL) {
        DEBUG(1, ("Could not create event context"));
        talloc_free(ctx);
        return EIO;
    }

    tmp_ctx = talloc_new(ctx);
    if (!tmp_ctx)
        return ENOMEM;

    confdb_path = talloc_asprintf(tmp_ctx, "%s/%s", DB_PATH, CONFDB_FILE);
    if (confdb_path == NULL) {
        talloc_free(ctx);
        return ENOMEM;
    }

    /* Connect to the conf db */
    ret = confdb_init(ctx, ctx->ev, &ctx->confdb, confdb_path);
    if (ret != EOK) {
        DEBUG(1, ("Could not initialize connection to the confdb"));
        talloc_free(ctx);
        return ret;
    }

    ret = confdb_get_domains(ctx->confdb, ctx, &ctx->domains);
    if (ret != EOK) {
        DEBUG(1, ("Could not get domains"));
        talloc_free(ctx);
        return ret;
    }

    /* open sysdb at default path */
    ret = sysdb_init(ctx, ctx->ev, ctx->confdb, NULL, &ctx->sysdb);
    if (ret != EOK) {
        DEBUG(1, ("Could not initialize connection to the sysdb"));
        talloc_free(ctx);
        return ret;
    }

    talloc_free(tmp_ctx);
    *tools_ctx = ctx;
    return EOK;
}

/*
 * Print poptUsage as well as our error message
 */
void usage(poptContext pc, const char *error)
{
    poptPrintUsage(pc, stderr, 0);
    if (error) fprintf(stderr, "%s", error);
}

