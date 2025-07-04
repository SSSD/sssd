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

#include "providers/ipa/ipa_common.h"
#include "providers/krb5/krb5_auth.h"
#include "providers/ipa/ipa_id.h"
#include "providers/ipa/ipa_auth.h"
#include "providers/ipa/ipa_access.h"
#include "providers/ipa/ipa_dyndns.h"
#include "providers/ipa/ipa_selinux.h"

errno_t ipa_autofs_init(TALLOC_CTX *mem_ctx,
                        struct be_ctx *be_ctx,
                        struct ipa_id_ctx *id_ctx,
                        struct dp_method *dp_methods)
{
    int ret;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Initializing autofs IPA back end\n");

    ret = ipa_get_autofs_options(id_ctx->ipa_options,
                                 sysdb_ctx_get_ldb(be_ctx->domain->sysdb),
                                 be_ctx->cdb,
                                 be_ctx->conf_path, &id_ctx->sdap_id_ctx->opts);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot get IPA autofs options\n");
        return ret;
    }

    dp_set_method(dp_methods, DPM_AUTOFS_ENUMERATE,
                  sdap_autofs_enumerate_handler_send, sdap_autofs_enumerate_handler_recv, id_ctx->sdap_id_ctx,
                  struct sdap_id_ctx, struct dp_autofs_data, dp_no_output);

    dp_set_method(dp_methods, DPM_AUTOFS_GET_MAP,
                  sdap_autofs_get_map_handler_send, sdap_autofs_get_map_handler_recv, id_ctx->sdap_id_ctx,
                  struct sdap_id_ctx, struct dp_autofs_data, dp_no_output);

    dp_set_method(dp_methods, DPM_AUTOFS_GET_ENTRY,
                  sdap_autofs_get_entry_handler_send, sdap_autofs_get_entry_handler_recv, id_ctx->sdap_id_ctx,
                  struct sdap_id_ctx, struct dp_autofs_data, dp_no_output);

    return ret;
}
