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
#include "util/util.h"
#include "providers/ad/ad_common.h"
#include "providers/ad/ad_id.h"

void
ad_account_info_handler(struct be_req *breq)
{
    struct ad_id_ctx *ad_ctx;
    struct sdap_id_ctx *sdap_id_ctx;

    ad_ctx = talloc_get_type(breq->be_ctx->bet_info[BET_ID].pvt_bet_data,
                             struct ad_id_ctx);
    sdap_id_ctx = ad_ctx->sdap_id_ctx;

    return sdap_handle_account_info(breq, sdap_id_ctx);
}
