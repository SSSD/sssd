/*
    SSSD

    AD autofs Provider Initialization functions

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

#include "providers/ad/ad_common.h"
#include "providers/ldap/sdap_autofs.h"

int ad_autofs_init(struct be_ctx *be_ctx,
                   struct ad_id_ctx *id_ctx,
                   struct bet_ops **ops,
                   void **pvt_data)
{
    int ret;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Initializing autofs AD back end\n");

    ret = sdap_autofs_init(be_ctx, id_ctx->sdap_id_ctx, ops, pvt_data);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot initialize AD autofs [%d]: %s\n",
                                 ret, sss_strerror(ret));
        return ret;
    }

    ret = ad_get_autofs_options(id_ctx->ad_options, be_ctx->cdb,
                                be_ctx->conf_path);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot initialize AD autofs [%d]: %s\n",
                                 ret, sss_strerror(ret));
        return ret;
    }

    return EOK;
}
