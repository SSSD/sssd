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

#include <dhash.h>

#include "responder/common/responder.h"
#include "responder/common/cache_req/cache_req.h"

#define SSS_AUTOFS_PROTO_VERSION        0x001

struct autofs_ctx {
    struct resp_ctx *rctx;

    int neg_timeout;

    hash_table_t *maps;
};

struct autofs_cmd_ctx {
    struct autofs_ctx *autofs_ctx;
    struct cli_ctx *cli_ctx;

    const char *mapname;
    const char *keyname;
    uint32_t max_entries;
    uint32_t cursor;
};

struct autofs_enum_ctx {
    /* Results. First result is the map objects, next results are map entries. */
    struct cache_req_result *result;

    /* True if the map was found. */
    bool found;

    /* False if the result is being created. */
    bool ready;

    /* Enumeration context key. */
    const char *key;

    /* Hash table that contains this enumeration context. */
    hash_table_t *table;

    /* Requests that awaits the data. */
    struct setent_req_list *notify_list;
};

struct sss_cmd_table *get_autofs_cmds(void);
int autofs_connection_setup(struct cli_ctx *cctx);

void autofs_orphan_maps(struct autofs_ctx *actx);

#endif /* _AUTOFSSRV_PRIVATE_H_ */
