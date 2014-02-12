/*
    SSSD

    IPA Provider Initialization functions

    Authors:
        Lukas Slebodnik <lslebodn@redhat.com>

    Copyright (C) 2013 Red Hat

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
#include "providers/ldap/sdap_sudo.h"

int ipa_sudo_init(struct be_ctx *be_ctx,
                  struct ipa_id_ctx *id_ctx,
                  struct bet_ops **ops,
                  void **pvt_data)
{
    int ret;
    struct ipa_options *ipa_options;
    struct sdap_options *ldap_options;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Initializing sudo IPA back end\n");

    /*
     * SDAP_SUDO_SEARCH_BASE has already been initialized in
     * function ipa_get_id_options
     */
    ret = sdap_sudo_init(be_ctx, id_ctx->sdap_id_ctx, ops, pvt_data);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot initialize LDAP SUDO [%d]: %s\n",
                                  ret, strerror(ret));
        return ret;
    }

    ipa_options = id_ctx->ipa_options;
    ldap_options = id_ctx->sdap_id_ctx->opts;

    ipa_options->id->sudorule_map = ldap_options->sudorule_map;
    return EOK;
}
