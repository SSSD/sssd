/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2011 Red Hat

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
#include <tevent.h>

#include "util/util.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_sudo_timer.h"
#include "providers/ldap/sdap_sudo.h"
#include "db/sysdb_sudo.h"

struct sdap_sudo_refresh_ctx {
    struct be_ctx *be_ctx;
    struct sdap_id_ctx *id_ctx;
    struct sdap_options *opts;

    struct timeval last_refresh;
};

static void sdap_sudo_refresh_timer(struct tevent_context *ev,
                                   struct tevent_timer *tt,
                                   struct timeval tv, void *pvt);

static void sdap_sudo_refresh_reschedule(struct tevent_req *req);

static void sdap_sudo_refresh_timeout(struct tevent_context *ev,
                                      struct tevent_timer *te,
                                      struct timeval tv, void *pvt);

struct sdap_sudo_refresh_ctx *
sdap_sudo_refresh_ctx_init(TALLOC_CTX *mem_ctx,
                           struct be_ctx *be_ctx,
                           struct sdap_id_ctx *id_ctx,
                           struct sdap_options *opts,
                           struct timeval last_refresh)
{
    struct sdap_sudo_refresh_ctx *refresh_ctx = NULL;

    refresh_ctx = talloc_zero(mem_ctx, struct sdap_sudo_refresh_ctx);
    if (refresh_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_zero() failed!\n"));
        return NULL;
    }

    refresh_ctx->be_ctx = be_ctx;
    refresh_ctx->id_ctx = id_ctx;
    refresh_ctx->opts = opts;
    refresh_ctx->last_refresh = last_refresh;

    return refresh_ctx;
}

int sdap_sudo_refresh_set_timer(struct sdap_sudo_refresh_ctx *ctx,
                                struct timeval tv)
{
    struct tevent_timer *enum_task;

    DEBUG(SSSDBG_TRACE_FUNC, ("Scheduling next refresh of SUDO rules at "
          "%ld.%ld\n", (long)tv.tv_sec, (long)tv.tv_usec));

    enum_task = tevent_add_timer(ctx->be_ctx->ev, ctx,
                                 tv, sdap_sudo_refresh_timer, ctx);
    if (!enum_task) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              ("FATAL: failed to setup SUDO rules refresh task!\n"));
        return EFAULT;
    }

    return EOK;
}

static void sdap_sudo_refresh_timer(struct tevent_context *ev,
                                    struct tevent_timer *tt,
                                    struct timeval tv, void *pvt)
{
    struct sdap_sudo_refresh_ctx *refresh_ctx = NULL;
    struct be_sudo_req *sudo_req = NULL;
    struct tevent_timer *timeout = NULL;
    struct tevent_req *req = NULL;
    int delay = 0;
    int ret;

    refresh_ctx = talloc_get_type(pvt, struct sdap_sudo_refresh_ctx);

    delay = dp_opt_get_int(refresh_ctx->opts->basic, SDAP_SUDO_REFRESH_TIMEOUT);

    if (be_is_offline(refresh_ctx->be_ctx)) {
        DEBUG(SSSDBG_TRACE_FUNC, ("Backend is marked offline, retry later!\n"));
        tv = tevent_timeval_current_ofs(delay, 0);
        ret = sdap_sudo_refresh_set_timer(refresh_ctx, tv);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Error setting up SUDO refresh timer\n"));
        }
        return;
    }

    /* create sudo context */
    sudo_req = talloc_zero(refresh_ctx, struct be_sudo_req);
    if (sudo_req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_zero() failed!\n"));
        tv = tevent_timeval_current_ofs(delay, 0);
        ret = sdap_sudo_refresh_set_timer(refresh_ctx, tv);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Error setting up SUDO refresh timer\n"));
        }

        return;
    }

    sudo_req->type = BE_REQ_SUDO_ALL;
    sudo_req->username = NULL;

    /* send request */
    req = sdap_sudo_refresh_send(refresh_ctx, refresh_ctx->id_ctx->be, sudo_req,
                                 refresh_ctx->id_ctx->opts,
                                 refresh_ctx->id_ctx->conn_cache);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to schedule refresh of SUDO rules, "
              "retrying later!\n"));
        tv = tevent_timeval_current_ofs(delay, 0);
        ret = sdap_sudo_refresh_set_timer(refresh_ctx, tv);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Error setting up SUDO refresh timer\n"));
        }

        talloc_free(sudo_req);
        return;
    }
    refresh_ctx->last_refresh = tevent_timeval_current();
    talloc_steal(req, sudo_req); /* make it free with req */

    tevent_req_set_callback(req, sdap_sudo_refresh_reschedule, refresh_ctx);

    /* schedule timeout */
    tv = tevent_timeval_current_ofs(delay, 0);
    timeout = tevent_add_timer(refresh_ctx->be_ctx->ev, req, tv,
                               sdap_sudo_refresh_timeout, req);
    if (timeout == NULL) {
        /* If we can't guarantee a timeout, we
         * need to cancel the request, to avoid
         * the possibility of starting another
         * concurrently
         */
        talloc_zfree(req);

        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to schedule refresh of SUDO rules, "
              "retrying later!\n"));
        tv = tevent_timeval_current_ofs(delay, 0);
        ret = sdap_sudo_refresh_set_timer(refresh_ctx, tv);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Error setting up SUDO refresh timer\n"));
        }
    }

    return;
}

static void sdap_sudo_refresh_reschedule(struct tevent_req *req)
{
    struct sdap_sudo_refresh_ctx *refresh_ctx = NULL;
    struct timeval tv;
    int delay;
    int dp_error;
    int error;
    int ret;

    refresh_ctx = tevent_req_callback_data(req, struct sdap_sudo_refresh_ctx);
    ret = sdap_sudo_refresh_recv(req, &dp_error, &error);
    talloc_zfree(req);
    if (ret != EOK) {
        tv = tevent_timeval_current();
    } else {
        tv = refresh_ctx->last_refresh;

        /* Ok, we've completed a refresh. Save this to the
         * sysdb so we can postpone starting up the refresh
         * process on the next SSSD service restart (to avoid
         * slowing down system boot-up
         */
        ret = sysdb_sudo_set_refreshed(refresh_ctx->be_ctx->sysdb, true);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  ("Could not mark domain as having refreshed.\n"));
            /* This error is non-fatal, so continue */
        }
    }

    delay = dp_opt_get_int(refresh_ctx->opts->basic, SDAP_SUDO_REFRESH_TIMEOUT);
    tv = tevent_timeval_add(&tv, delay, 0);
    ret = sdap_sudo_refresh_set_timer(refresh_ctx, tv);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Error setting up SUDO refresh timer\n"));
    }
}

static void sdap_sudo_refresh_timeout(struct tevent_context *ev,
                                      struct tevent_timer *te,
                                      struct timeval tv, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct sdap_sudo_refresh_ctx *refresh_ctx = NULL;
    int delay;
    int ret;

    refresh_ctx = tevent_req_callback_data(req, struct sdap_sudo_refresh_ctx);

    delay = dp_opt_get_int(refresh_ctx->opts->basic, SDAP_SUDO_REFRESH_TIMEOUT);
    DEBUG(SSSDBG_CRIT_FAILURE, ("Refreshing SUDO rules timed out!"
          " Timeout too small? (%ds)!\n", delay));

    tv = tevent_timeval_current_ofs(delay, 0);
    ret = sdap_sudo_refresh_set_timer(refresh_ctx, tv);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Error setting up SUDO refresh timer\n"));
    }

    talloc_zfree(req);
}
