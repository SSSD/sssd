/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2015 Red Hat

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
#include <talloc.h>
#include <tevent.h>

#include "util/util.h"
#include "providers/dp_ptask.h"
#include "providers/ldap/sdap_sudo.h"
#include "db/sysdb_sudo.h"

static struct tevent_req *
sdap_sudo_ptask_full_refresh_send(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct be_ctx *be_ctx,
                                  struct be_ptask *be_ptask,
                                  void *pvt)
{
    struct sdap_sudo_ctx *sudo_ctx;
    sudo_ctx = talloc_get_type(pvt, struct sdap_sudo_ctx);

    return sdap_sudo_full_refresh_send(mem_ctx, sudo_ctx);
}

static errno_t
sdap_sudo_ptask_full_refresh_recv(struct tevent_req *req)
{
    int dp_error;
    int error;

    return sdap_sudo_full_refresh_recv(req, &dp_error, &error);
}

static struct tevent_req *
sdap_sudo_ptask_smart_refresh_send(TALLOC_CTX *mem_ctx,
                                   struct tevent_context *ev,
                                   struct be_ctx *be_ctx,
                                   struct be_ptask *be_ptask,
                                   void *pvt)
{
    struct sdap_sudo_ctx *sudo_ctx;
    sudo_ctx = talloc_get_type(pvt, struct sdap_sudo_ctx);

    return sdap_sudo_smart_refresh_send(mem_ctx, sudo_ctx);
}

static errno_t
sdap_sudo_ptask_smart_refresh_recv(struct tevent_req *req)
{
    int dp_error;
    int error;

    return sdap_sudo_smart_refresh_recv(req, &dp_error, &error);
}

errno_t
sdap_sudo_ptask_setup(struct be_ctx *be_ctx, struct sdap_sudo_ctx *sudo_ctx)
{
    struct dp_option *opts = sudo_ctx->id_ctx->opts->basic;
    time_t smart;
    time_t full;
    time_t delay;
    time_t last_refresh;
    errno_t ret;

    smart = dp_opt_get_int(opts, SDAP_SUDO_SMART_REFRESH_INTERVAL);
    full = dp_opt_get_int(opts, SDAP_SUDO_FULL_REFRESH_INTERVAL);

    if (smart == 0 && full == 0) {
        /* We don't allow both types to be disabled. At least smart refresh
         * needs to be enabled. In this case smart refresh will catch up new
         * and modified rules and deleted rules are caught when expired. */
        smart = opts[SDAP_SUDO_SMART_REFRESH_INTERVAL].def_val.number;

        DEBUG(SSSDBG_CONF_SETTINGS, "At least smart refresh needs to be "
              "enabled. Setting smart refresh interval to default value "
              "(%ld) seconds.\n", smart);
    } else if (full <= smart) {
        /* In this case it does not make any sense to run smart refresh. */
        smart = 0;

        DEBUG(SSSDBG_CONF_SETTINGS, "Smart refresh interval has to be lower "
              "than full refresh interval. Periodical smart refresh will be "
              "disabled.\n");
    }

    ret = sysdb_sudo_get_last_full_refresh(be_ctx->domain, &last_refresh);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Unable to obtain time of last full "
              "refresh. Assuming none was performed so far.\n");
        last_refresh = 0;
    }

    if (last_refresh == 0) {
        /* If this is the first startup, we need to kick off an refresh
         * immediately, to close a window where clients requesting sudo
         * information won't get an immediate reply with no entries */
        delay = 0;
    } else {
        /* At least one update has previously run, so clients will get cached
         * data. We will delay the refresh so we don't slow down the startup
         * process if this is happening during system boot. */
        delay = 10;
    }

    /* Full refresh.
     *
     * Disable when offline and run immediately when SSSD goes back online.
     * Since we have periodical online check we don't have to run this task
     * when offline. */
    ret = be_ptask_create(be_ctx, be_ctx, full, delay, 0, 0, full,
                          BE_PTASK_OFFLINE_DISABLE, 0,
                          sdap_sudo_ptask_full_refresh_send,
                          sdap_sudo_ptask_full_refresh_recv,
                          sudo_ctx, "SUDO Full Refresh", NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to setup full refresh ptask "
              "[%d]: %s\n", ret, sss_strerror(ret));
        return ret;
    }

    /* Smart refresh.
     *
     * Disable when offline and reschedule normally when SSSD goes back online.
     * Since we have periodical online check we don't have to run this task
     * when offline. */
    ret = be_ptask_create(be_ctx, be_ctx, smart, delay + smart, smart, 0, smart,
                          BE_PTASK_OFFLINE_DISABLE, 0,
                          sdap_sudo_ptask_smart_refresh_send,
                          sdap_sudo_ptask_smart_refresh_recv,
                          sudo_ctx, "SUDO Smart Refresh", NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to setup smart refresh ptask "
              "[%d]: %s\n", ret, sss_strerror(ret));
        return ret;
    }

    return EOK;
}
