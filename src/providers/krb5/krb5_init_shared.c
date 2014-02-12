/*
    SSSD

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

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

#include <fcntl.h>

#include "providers/krb5/krb5_common.h"
#include "providers/krb5/krb5_auth.h"
#include "providers/krb5/krb5_init_shared.h"

errno_t krb5_child_init(struct krb5_ctx *krb5_auth_ctx,
                        struct be_ctx *bectx)
{
    errno_t ret;
    FILE *debug_filep;
    time_t renew_intv = 0;
    krb5_deltat renew_interval_delta;
    char *renew_interval_str;

    if (dp_opt_get_bool(krb5_auth_ctx->opts, KRB5_STORE_PASSWORD_IF_OFFLINE)) {
        ret = init_delayed_online_authentication(krb5_auth_ctx, bectx,
                                                 bectx->ev);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "init_delayed_online_authentication failed.\n");
            goto done;
        }
    }
    renew_interval_str = dp_opt_get_string(krb5_auth_ctx->opts,
                         KRB5_RENEW_INTERVAL);
    if (renew_interval_str != NULL) {
        ret = krb5_string_to_deltat(renew_interval_str, &renew_interval_delta);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                 "Reading krb5_renew_interval failed.\n");
            renew_interval_delta = 0;
        }
        renew_intv = renew_interval_delta;
    }

    if (renew_intv > 0) {
        ret = init_renew_tgt(krb5_auth_ctx, bectx, bectx->ev, renew_intv);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "init_renew_tgt failed.\n");
            goto done;
        }
    }

    ret = check_and_export_options(krb5_auth_ctx->opts, bectx->domain,
                                   krb5_auth_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "check_and_export_opts failed.\n");
        goto done;
    }

    ret = krb5_install_offline_callback(bectx, krb5_auth_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_install_offline_callback failed.\n");
        goto done;
    }

    ret = krb5_install_sigterm_handler(bectx->ev, krb5_auth_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_install_sigterm_handler failed.\n");
        goto done;
    }

    if (debug_to_file != 0) {
        ret = open_debug_file_ex(KRB5_CHILD_LOG_FILE, &debug_filep, false);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE, "Error setting up logging (%d) [%s]\n",
                    ret, strerror(ret));
            goto done;
        }

        krb5_auth_ctx->child_debug_fd = fileno(debug_filep);
        if (krb5_auth_ctx->child_debug_fd == -1) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "fileno failed [%d][%s]\n", errno, strerror(errno));
            ret = errno;
            goto done;
        }
    }

done:
    return ret;
}
