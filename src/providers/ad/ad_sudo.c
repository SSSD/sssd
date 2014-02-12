/*
    SSSD

    AD SUDO Provider Initialization functions

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2014 Red Hat

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

#include "providers/ad/ad_common.h"
#include "providers/ldap/sdap_sudo.h"

int ad_sudo_init(struct be_ctx *be_ctx,
                 struct ad_id_ctx *id_ctx,
                 struct bet_ops **ops,
                 void **pvt_data)
{
    int ret;
    struct ad_options *ad_options;
    struct sdap_options *ldap_options;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Initializing sudo AD back end\n");

    ret = sdap_sudo_init(be_ctx, id_ctx->sdap_id_ctx, ops, pvt_data);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot initialize LDAP SUDO [%d]: %s\n",
                                 ret, strerror(ret));
        return ret;
    }

    ad_options = id_ctx->ad_options;
    ldap_options = id_ctx->sdap_id_ctx->opts;

    ad_options->id->sudorule_map = ldap_options->sudorule_map;
    return EOK;
}
