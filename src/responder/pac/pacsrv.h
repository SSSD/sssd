/*
   SSSD

   PAC Responder, header file

   Copyright (C) Sumit Bose <sbose@redhat.com> 2011

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

#ifndef __PACSRV_H__
#define __PACSRV_H__

#include "config.h"

#include "responder/common/responder_packet.h"
#include "responder/common/responder.h"
#include "lib/idmap/sss_idmap.h"

struct pac_ctx {
    struct resp_ctx *rctx;
    struct sss_idmap_ctx *idmap_ctx;
    struct dom_sid *my_dom_sid;
    struct local_mapping_ranges *range_map;
    int pac_lifetime;
    uint32_t pac_check_opts;
};

struct sss_cmd_table *get_pac_cmds(void);

#endif /* __PACSRV_H__ */
