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

#include "responder/common/responder_sbus.h"

#define SSS_AUTOFS_PROTO_VERSION        0x001

struct autofs_ctx {
    struct resp_ctx *rctx;

    int neg_timeout;

    hash_table_t *maps;
};

struct autofs_state_ctx {
    char *automntmap_name;
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
int autofs_connection_setup(struct cli_ctx *cctx);

void autofs_map_hash_delete_cb(hash_entry_t *item,
                               hash_destroy_enum deltype, void *pvt);

errno_t autofs_orphan_maps(struct autofs_ctx *actx);

#endif /* _AUTOFSSRV_PRIVATE_H_ */
