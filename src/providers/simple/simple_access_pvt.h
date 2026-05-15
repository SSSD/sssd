/*
   SSSD

   Simple access control

   Copyright (C) Sumit Bose <sbose@redhat.com> 2010

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

#ifndef __SIMPLE_ACCESS_PVT_H__
#define __SIMPLE_ACCESS_PVT_H__

#include "providers/data_provider/dp.h"

/* We only 'export' the functions in a private header file to be able to call
 * them from unit tests
 */
struct tevent_req *
simple_access_handler_send(TALLOC_CTX *mem_ctx,
                           struct simple_ctx *simple_ctx,
                           struct pam_data *pd,
                           struct dp_req_params *params);

errno_t
simple_access_handler_recv(TALLOC_CTX *mem_ctx,
                           struct tevent_req *req,
                           struct pam_data **_data);

int simple_access_obtain_filter_lists(struct simple_ctx *ctx);

#endif /* __SIMPLE_ACCESS_PVT_H__ */
