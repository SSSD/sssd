/*
    SSSD

    IPA Provider Initialization functions

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

#include "util/child_common.h"
#include "providers/ipa/ipa_common.h"
#include "providers/krb5/krb5_auth.h"
#include "providers/ipa/ipa_id.h"
#include "providers/ipa/ipa_auth.h"
#include "providers/ipa/ipa_access.h"
#include "providers/ipa/ipa_dyndns.h"
#include "providers/ipa/ipa_selinux.h"

struct bet_ops ipa_autofs_ops = {
    .handler = sdap_autofs_handler,
    .finalize = NULL,
    .check_online = sdap_check_online
};

int ipa_autofs_init(struct be_ctx *be_ctx,
                    struct ipa_id_ctx *id_ctx,
                    struct bet_ops **ops,
                    void **pvt_data)
{
    int ret;

    DEBUG(SSSDBG_TRACE_INTERNAL, ("Initializing autofs LDAP back end\n"));

    *ops = &ipa_autofs_ops;
    *pvt_data = id_ctx->sdap_id_ctx;

    ret = ipa_get_autofs_options(id_ctx->ipa_options, be_ctx->cdb,
                                 be_ctx->conf_path, &id_ctx->sdap_id_ctx->opts);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Cannot get IPA autofs options\n"));
        return ret;
    }

    return ret;
}
