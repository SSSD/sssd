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
#include "providers/be_ptask.h"
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
    } else if (full > 0 && full <= smart) {
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
                              BE_PTASK_OFFLINE_DISABLE,
                              BE_PTASK_SCHEDULE_FROM_LAST,
                              0,
                              full_send_fn, full_recv_fn, pvt,
                              "SUDO Full Refresh", 0, NULL);
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
                              smart, BE_PTASK_OFFLINE_DISABLE,
                              BE_PTASK_SCHEDULE_FROM_LAST,
                              0,
                              smart_send_fn, smart_recv_fn, pvt,
                              "SUDO Smart Refresh", 0, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to setup smart refresh ptask "
                  "[%d]: %s\n", ret, sss_strerror(ret));
            return ret;
        }
    }

    return EOK;
}

static char *
sdap_sudo_new_usn(TALLOC_CTX *mem_ctx,
                  unsigned long usn,
                  const char *leftover,
                  bool supports_usn)
{
    const char *str = leftover == NULL ? "" : leftover;
    char *newusn;

    /* This is a fresh start and server uses modifyTimestamp. We need to
     * provide proper datetime value. */
    if (!supports_usn && usn == 0) {
        newusn = talloc_strdup(mem_ctx, "00000101000000Z");
        if (newusn == NULL) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Unable to change USN value (OOM)!\n");
            return NULL;
        }

        return newusn;
    }

    /* We increment USN number so that we can later use simplify filter
     * (just usn >= last+1 instead of usn >= last && usn != last).
     */
    usn++;

    /* Convert back to string appending non-converted values since it
     * is an indicator that modifyTimestamp is used instead of entryUSN.
     * modifyTimestamp contains also timezone specification, usually Z.
     * We can't really handle any errors here so we just use what we got. */
    newusn = talloc_asprintf(mem_ctx, "%lu%s", usn, str);
    if (newusn == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Unable to change USN value (OOM)!\n");
        return NULL;
    }

    return newusn;
}

void
sdap_sudo_set_usn(struct sdap_server_opts *srv_opts,
                  const char *usn)
{
    unsigned long usn_number;
    char *newusn;
    char *endptr = NULL;
    errno_t ret;

    if (srv_opts == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, "Bug: srv_opts is NULL\n");
        return;
    }

    if (usn == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, "Bug: usn is NULL\n");
        return;
    }

    errno = 0;
    usn_number = strtoul(usn, &endptr, 10);
    if (errno != 0) {
        ret = errno;
        DEBUG(SSSDBG_MINOR_FAILURE, "Unable to convert USN %s [%d]: %s\n",
              usn, ret, sss_strerror(ret));
        return;
    }

    if (usn_number > srv_opts->last_usn) {
        srv_opts->last_usn = usn_number;
    }

    newusn = sdap_sudo_new_usn(srv_opts, srv_opts->last_usn, endptr,
                               srv_opts->supports_usn);
    if (newusn == NULL) {
        return;
    }

    talloc_zfree(srv_opts->max_sudo_value);
    srv_opts->max_sudo_value = newusn;

    DEBUG(SSSDBG_FUNC_DATA, "SUDO higher USN value: [%s]\n",
                             srv_opts->max_sudo_value);
}
