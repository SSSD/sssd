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

#include <stdbool.h>
#include <util/data_blob.h>
#include <ndr.h>
#include <gen_ndr/krb5pac.h>
#include <gen_ndr/ndr_krb5pac.h>

#include <stdint.h>
#include <sys/un.h>
#include <talloc.h>
#include <tevent.h>
#include <ldb.h>
#include <dbus/dbus.h>

#include "sbus/sssd_dbus.h"
#include "responder/common/responder_packet.h"
#include "responder/common/responder.h"
#include "responder/common/responder_sbus.h"
#include "lib/idmap/sss_idmap.h"
#include "util/sss_nss.h"
#include "db/sysdb.h"

#define PAC_PACKET_MAX_RECV_SIZE 1024

struct getent_ctx;
struct dom_sid;

struct pac_ctx {
    struct resp_ctx *rctx;
    struct sss_idmap_ctx *idmap_ctx;
    struct dom_sid *my_dom_sid;
    struct local_mapping_ranges *range_map;
};

struct grp_info {
    char *orig_dn;
    struct ldb_dn *dn;
};

struct sss_cmd_table *get_pac_cmds(void);

errno_t get_sids_from_pac(TALLOC_CTX *mem_ctx,
                          struct pac_ctx *pac_ctx,
                          struct PAC_LOGON_INFO *logon_info,
                          char **_user_sid_str,
                          char **_primary_group_sid_str,
                          hash_table_t **_sid_table);

errno_t get_data_from_pac(TALLOC_CTX *mem_ctx,
                          uint8_t *pac_blob, size_t pac_len,
                          struct PAC_LOGON_INFO **_logon_info);

errno_t get_pwd_from_pac(TALLOC_CTX *mem_ctx,
                         struct sss_domain_info *dom,
                         char *user_sid_str,
                         char *primary_group_sid_str,
                         hash_table_t *sid_table,
                         struct PAC_LOGON_INFO *logon_info,
                         struct passwd **_pwd,
                         struct sysdb_attrs **_attrs);
#endif /* __PACSRV_H__ */
