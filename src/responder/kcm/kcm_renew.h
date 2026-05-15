/*
    SSSD

    KCM Renewal, private header file

    Authors:
        Justin Stephenson <jstephen@redhat.com>

    Copyright (C) 2020 Red Hat


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

#ifndef __KCM_RENEW_H__
#define __KCM_RENEW_H__

#include "providers/krb5/krb5_common.h"
#include "src/providers/krb5/krb5_ccache.h"
#include "responder/kcm/kcmsrv_pvt.h"
#include "util/sss_ptr_hash.h"

struct kcm_renew_tgt_ctx {
    struct kcm_ccache **cc_list;
    struct tevent_context *ev;
    struct krb5_ctx *krb5_ctx;
    struct resp_ctx *rctx;
    struct kcm_ccdb *db;
    time_t timer_interval;
    struct tevent_timer *te;
};


int kcm_get_renewal_config(struct kcm_ctx *kctx,
                           struct krb5_ctx **_krb5_ctx,
                           time_t *_renew_intv);

errno_t kcm_renewal_setup(struct resp_ctx *rctx, struct krb5_ctx *kctx,
                         struct tevent_context *ev, struct kcm_ccdb *db,
                         time_t renew_intv);

#endif /* __KCM_RENEW_H__ */
