/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2016 Red Hat

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

#ifndef _MOCK_DP_H_
#define _MOCK_DP_H_

#include <talloc.h>

#include "providers/backend.h"
#include "providers/data_provider/dp_private.h"

struct data_provider *mock_dp(TALLOC_CTX *mem_ctx,
                              struct be_ctx *be_ctx);

struct dp_method *mock_dp_get_methods(struct data_provider *provider,
                                      enum dp_targets target);

struct dp_req_params *mock_dp_req_params(TALLOC_CTX *mem_ctx,
                                         struct tevent_context *ev,
                                         struct be_ctx *be_ctx,
                                         struct sss_domain_info *domain,
                                         enum dp_targets target,
                                         enum dp_methods method);

#endif /* _MOCK_DP_H_ */
