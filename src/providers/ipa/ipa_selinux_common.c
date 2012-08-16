/*
    SSSD

    IPA Backend Module -- SELinux common routines

    Authors:
        Jan Zeleny <jzeleny@redhat.com>

    Copyright (C) 2012 Red Hat

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

#include "db/sysdb_selinux.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ipa/ipa_selinux_common.h"


errno_t ipa_save_user_maps(struct sysdb_ctx *sysdb,
                           size_t map_count,
                           struct sysdb_attrs **maps)
{
    errno_t ret;
    errno_t sret;
    bool in_transaction = false;
    int i;

    ret = sysdb_transaction_start(sysdb);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to start transaction\n"));
        goto done;
    }
    in_transaction = true;

    for (i = 0; i < map_count; i++) {
        ret = sysdb_store_selinux_usermap(sysdb, maps[i]);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, ("Failed to store user map %d. "
                                      "Ignoring.\n", i));
        } else {
            DEBUG(SSSDBG_TRACE_FUNC, ("User map %d processed.\n", i));
        }
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to commit transaction!\n"));
        goto done;
    }
    in_transaction = false;
    ret = EOK;

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to cancel transaction"));
        }
    }
    return ret;
}
