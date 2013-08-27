/*
    SSSD

    LDAP Identity Enumeration

    Authors:
        Simo Sorce <ssorce@redhat.com>

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

#include <errno.h>
#include <time.h>
#include <sys/time.h>

#include "util/util.h"
#include "db/sysdb.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ldap/sdap_idmap.h"
#include "providers/ldap/sdap_async_enum.h"

extern struct tevent_req *ldap_id_cleanup_send(TALLOC_CTX *memctx,
                                               struct tevent_context *ev,
                                               struct sdap_id_ctx *ctx);

/* ==Enumeration-Task===================================================== */

static void ldap_id_enumerate_reschedule(struct tevent_req *req);

static void ldap_id_enumerate_timeout(struct tevent_context *ev,
                                      struct tevent_timer *te,
                                      struct timeval tv, void *pvt);

static void ldap_id_enumerate_timer(struct tevent_context *ev,
                                    struct tevent_timer *tt,
                                    struct timeval tv, void *pvt)
{
    struct sdap_id_ctx *ctx = talloc_get_type(pvt, struct sdap_id_ctx);
    struct tevent_timer *timeout;
    struct tevent_req *req;
    int delay;
    errno_t ret;

    if (be_is_offline(ctx->be)) {
        DEBUG(4, ("Backend is marked offline, retry later!\n"));
        /* schedule starting from now, not the last run */
        delay = dp_opt_get_int(ctx->opts->basic, SDAP_ENUM_REFRESH_TIMEOUT);
        tv = tevent_timeval_current_ofs(delay, 0);
        ldap_id_enumerate_set_timer(ctx, tv);
        return;
    }

    req = sdap_dom_enum_send(ctx, ev, ctx, ctx->opts->sdom, ctx->conn);
    if (!req) {
        DEBUG(1, ("Failed to schedule enumeration, retrying later!\n"));
        /* schedule starting from now, not the last run */
        delay = dp_opt_get_int(ctx->opts->basic, SDAP_ENUM_REFRESH_TIMEOUT);
        tv = tevent_timeval_current_ofs(delay, 0);
        ret = ldap_id_enumerate_set_timer(ctx, tv);
        if (ret != EOK) {
            DEBUG(1, ("Error setting up enumerate timer\n"));
        }
        return;
    }
    tevent_req_set_callback(req, ldap_id_enumerate_reschedule, ctx);

    /* if enumeration takes so long, either we try to enumerate too
     * frequently, or something went seriously wrong */
    delay = dp_opt_get_int(ctx->opts->basic, SDAP_ENUM_REFRESH_TIMEOUT);
    tv = tevent_timeval_current_ofs(delay, 0);
    timeout = tevent_add_timer(ctx->be->ev, req, tv,
                               ldap_id_enumerate_timeout, req);
    if (timeout == NULL) {
        /* If we can't guarantee a timeout, we
         * need to cancel the request, to avoid
         * the possibility of starting another
         * concurrently
         */
        talloc_zfree(req);

        DEBUG(1, ("Failed to schedule enumeration, retrying later!\n"));
        /* schedule starting from now, not the last run */
        delay = dp_opt_get_int(ctx->opts->basic, SDAP_ENUM_REFRESH_TIMEOUT);
        tv = tevent_timeval_current_ofs(delay, 0);
        ret = ldap_id_enumerate_set_timer(ctx, tv);
        if (ret != EOK) {
            DEBUG(1, ("Error setting up enumerate timer\n"));
        }
        return;
    }
    return;
}

static void ldap_id_enumerate_timeout(struct tevent_context *ev,
                                      struct tevent_timer *te,
                                      struct timeval tv, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct sdap_id_ctx *ctx = tevent_req_callback_data(req,
                                                       struct sdap_id_ctx);
    int delay;

    delay = dp_opt_get_int(ctx->opts->basic, SDAP_ENUM_REFRESH_TIMEOUT);
    DEBUG(1, ("Enumeration timed out! Timeout too small? (%ds)!\n", delay));

    tv = tevent_timeval_current_ofs(delay, 0);
    ldap_id_enumerate_set_timer(ctx, tv);

    talloc_zfree(req);
}

static void ldap_id_enumerate_reschedule(struct tevent_req *req)
{
    struct sdap_id_ctx *ctx = tevent_req_callback_data(req,
                                                       struct sdap_id_ctx);
    struct timeval tv;
    int delay;
    errno_t ret;

    ret = sdap_dom_enum_recv(req);
    talloc_zfree(req);
    if (ret != EOK) {
        /* On error schedule starting from now, not the last run */
        tv = tevent_timeval_current();
    } else {
        tv = ctx->opts->sdom->last_enum;

    }

    delay = dp_opt_get_int(ctx->opts->basic, SDAP_ENUM_REFRESH_TIMEOUT);
    tv = tevent_timeval_add(&tv, delay, 0);
    ldap_id_enumerate_set_timer(ctx, tv);
}

int ldap_id_enumerate_set_timer(struct sdap_id_ctx *ctx, struct timeval tv)
{
    struct tevent_timer *enum_task;

    DEBUG(6, ("Scheduling next enumeration at %ld.%ld\n",
              (long)tv.tv_sec, (long)tv.tv_usec));

    enum_task = tevent_add_timer(ctx->be->ev, ctx,
                                 tv, ldap_id_enumerate_timer, ctx);
    if (!enum_task) {
        DEBUG(0, ("FATAL: failed to setup enumeration task!\n"));
        return EFAULT;
    }

    return EOK;
}
