/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

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

#ifndef _AUTOFSSRV_PRIVATE_H_
#define _AUTOFSSRV_PRIVATE_H_

#define SSS_AUTOFS_SBUS_SERVICE_VERSION 0x0001
#define SSS_AUTOFS_SBUS_SERVICE_NAME    "autofs"

#define SSS_AUTOFS_PROTO_VERSION        0x001

struct autofs_ctx {
    struct resp_ctx *rctx;

    int neg_timeout;

    hash_table_t *maps;
};

struct autofs_cmd_ctx {
    struct cli_ctx *cctx;
    char *mapname;
    char *key;
    uint32_t cursor;
    uint32_t max_entries;
    bool check_next;
};

struct autofs_dom_ctx {
    struct autofs_cmd_ctx  *cmd_ctx;
    struct sss_domain_info *domain;
    bool check_provider;

    /* cache results */
    struct ldb_message *map;

    size_t entry_count;
    struct ldb_message **entries;

    struct autofs_map_ctx *map_ctx;
};

struct autofs_map_ctx {
    /* state of the map entry */
    bool ready;
    bool found;

    /* requests */
    struct setent_req_list *reqs;

    hash_table_t *map_table;
    char *mapname;

    /* map entry */
    struct ldb_message *map;
    size_t entry_count;
    struct ldb_message **entries;
};

struct sss_cmd_table *get_autofs_cmds(void);

enum sss_dp_autofs_type {
    SSS_DP_AUTOFS
};

struct tevent_req *
sss_dp_get_autofs_send(TALLOC_CTX *mem_ctx,
                       struct resp_ctx *rctx,
                       struct sss_domain_info *dom,
                       bool fast_reply,
                       enum sss_dp_autofs_type type,
                       const char *name);

errno_t
sss_dp_get_autofs_recv(TALLOC_CTX *mem_ctx,
                       struct tevent_req *req,
                       dbus_uint16_t *dp_err,
                       dbus_uint32_t *dp_ret,
                       char **err_msg);

#endif /* _AUTOFSSRV_PRIVATE_H_ */
