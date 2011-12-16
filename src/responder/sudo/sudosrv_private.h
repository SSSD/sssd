/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2011 Red Hat

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

#ifndef _SUDOSRV_PRIVATE_H_
#define _SUDOSRV_PRIVATE_H_

#include <stdint.h>
#include <talloc.h>

#include "src/db/sysdb.h"
#include "responder/common/responder.h"

#define SSS_SUDO_ERROR_OK 0
#define SSS_SUDO_SBUS_SERVICE_VERSION 0x0001
#define SSS_SUDO_SBUS_SERVICE_NAME "sudo"

struct sudo_ctx {
    struct resp_ctx *rctx;
};

struct sudo_cmd_ctx {
    struct cli_ctx *cli_ctx;
    char *username;
    bool check_next;
};

struct sudo_dom_ctx {
    struct sudo_cmd_ctx *cmd_ctx;
    struct sss_domain_info *domain;
    bool check_provider;

    /* cache results */
    struct ldb_result *user;
    struct sysdb_attrs **res;
    size_t res_count;
};

struct sudo_dp_request {
    struct cli_ctx *cctx;
    struct sss_domain_info *domain;
};

struct sss_cmd_table *get_sudo_cmds(void);

errno_t sudosrv_cmd_done(struct sudo_dom_ctx *dctx, int ret);

struct tevent_req * sudosrv_dp_refresh_send(struct resp_ctx *rctx,
                                            struct sss_domain_info *dom,
                                            const char *username);

errno_t sudosrv_dp_refresh_recv(struct tevent_req *req,
                                dbus_uint16_t *_err_maj,
                                dbus_uint32_t *_err_min);

errno_t sudosrv_get_sudorules(struct sudo_dom_ctx *dctx);

char * sudosrv_get_sudorules_parse_query(TALLOC_CTX *mem_ctx,
                                         const char *query_body,
                                         int query_len);

int sudosrv_get_sudorules_build_response(TALLOC_CTX *mem_ctx,
                                         uint32_t error,
                                         int rules_num,
                                         struct sysdb_attrs **rules,
                                         uint8_t **_response_body,
                                         size_t *_response_len);

int sudosrv_response_append_string(TALLOC_CTX *mem_ctx,
                                   const char *str,
                                   size_t str_len,
                                   uint8_t **_response_body,
                                   size_t *_response_len);

int sudosrv_response_append_uint32(TALLOC_CTX *mem_ctx,
                                   uint32_t number,
                                   uint8_t **_response_body,
                                   size_t *_response_len);

int sudosrv_response_append_rule(TALLOC_CTX *mem_ctx,
                                 int attrs_num,
                                 struct ldb_message_element *attrs,
                                 uint8_t **_response_body,
                                 size_t *_response_len);

int sudosrv_response_append_attr(TALLOC_CTX *mem_ctx,
                                 const char *name,
                                 unsigned int values_num,
                                 struct ldb_val *values,
                                 uint8_t **_response_body,
                                 size_t *_response_len);

#endif /* _SUDOSRV_PRIVATE_H_ */
