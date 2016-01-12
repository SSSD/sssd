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
#include <time.h>
#include <talloc.h>

#include "util/util.h"
#include "providers/dp_ptask.h"
#include "providers/ldap/sdap.h"
#include "providers/ldap/sdap_sudo_shared.h"
#include "db/sysdb_sudo.h"

errno_t
sdap_sudo_ptask_setup_generic(struct be_ctx *be_ctx,
                              struct dp_option *opts,
                              be_ptask_send_t full_send_fn,
                              be_ptask_recv_t full_recv_fn,
                              be_ptask_send_t smart_send_fn,
                              be_ptask_recv_t smart_recv_fn,
                              void *pvt)
{
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
    if (full > 0) {
        ret = be_ptask_create(be_ctx, be_ctx, full, delay, 0, 0, full,
                              BE_PTASK_OFFLINE_DISABLE, 0,
                              full_send_fn, full_recv_fn, pvt,
                              "SUDO Full Refresh", NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to setup full refresh ptask "
                  "[%d]: %s\n", ret, sss_strerror(ret));
            return ret;
        }
    }

    /* Smart refresh.
     *
     * Disable when offline and reschedule normally when SSSD goes back online.
     * Since we have periodical online check we don't have to run this task
     * when offline. */
    if (smart > 0) {
        ret = be_ptask_create(be_ctx, be_ctx, smart, delay + smart, smart, 0,
                              smart, BE_PTASK_OFFLINE_DISABLE, 0,
                              smart_send_fn, smart_recv_fn, pvt,
                              "SUDO Smart Refresh", NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to setup smart refresh ptask "
                  "[%d]: %s\n", ret, sss_strerror(ret));
            return ret;
        }
    }

    return EOK;
}

void
sdap_sudo_set_usn(struct sdap_server_opts *srv_opts,
                  const char *usn)
{
    unsigned int usn_number;
    char *endptr = NULL;
    char *newusn;

    if (srv_opts == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, "Bug: srv_opts is NULL\n");
        return;
    }

    if (usn == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, "Bug: usn is NULL\n");
        return;
    }

    if (sysdb_compare_usn(usn, srv_opts->max_sudo_value) > 0) {
        newusn = talloc_strdup(srv_opts, usn);
        if (newusn == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup() failed\n");
            return;
        }

        talloc_zfree(srv_opts->max_sudo_value);
        srv_opts->max_sudo_value = newusn;
    }

    usn_number = strtoul(usn, &endptr, 10);
    if ((endptr == NULL || (*endptr == '\0' && endptr != usn))
         && (usn_number > srv_opts->last_usn)) {
         srv_opts->last_usn = usn_number;
    }

    DEBUG(SSSDBG_FUNC_DATA, "SUDO higher USN value: [%s]\n",
                             srv_opts->max_sudo_value);
}
