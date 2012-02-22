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

enum sss_dp_sudo_type {
    SSS_DP_SUDO_DEFAULTS,
    SSS_DP_SUDO_USER
};

struct sudo_ctx {
    struct resp_ctx *rctx;

    /*
     * options
     */
    int cache_timeout;
    bool timed;

    /*
     * Key: domain          for SSS_DP_SUDO_DEFAULTS
     *      domain:username for SSS_DP_SUDO_USER
     * Val: struct sudo_cache_entry *
     */
    hash_table_t *cache;
};

struct sudo_cmd_ctx {
    struct cli_ctx *cli_ctx;
    struct sudo_ctx *sudo_ctx;
    enum sss_dp_sudo_type type;
    char *username;
    bool check_next;
};

struct sudo_dom_ctx {
    struct sudo_cmd_ctx *cmd_ctx;
    struct sss_domain_info *domain;
    bool check_provider;
    const char *orig_username;
    const char *cased_username;

    /* cache results */
    struct sysdb_attrs **res;
    size_t res_count;
};

struct sudo_dp_request {
    struct cli_ctx *cctx;
    struct sss_domain_info *domain;
};

struct sss_cmd_table *get_sudo_cmds(void);

errno_t sudosrv_cmd_done(struct sudo_dom_ctx *dctx, int ret);

errno_t sudosrv_get_sudorules(struct sudo_dom_ctx *dctx);

errno_t sudosrv_get_rules(struct sudo_dom_ctx *dctx);

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

struct tevent_req *
sss_dp_get_sudoers_send(TALLOC_CTX *mem_ctx,
                        struct resp_ctx *rctx,
                        struct sss_domain_info *dom,
                        bool fast_reply,
                        enum sss_dp_sudo_type type,
                        const char *name);

errno_t
sss_dp_get_sudoers_recv(TALLOC_CTX *mem_ctx,
                        struct tevent_req *req,
                        dbus_uint16_t *err_maj,
                        dbus_uint32_t *err_min,
                        char **err_msg);

errno_t sudosrv_cache_init(TALLOC_CTX *mem_ctx,
                           unsigned long count,
                           hash_table_t **table);

errno_t sudosrv_cache_lookup(hash_table_t *table,
                             struct sudo_dom_ctx *dctx,
                             bool check_next,
                             const char *username,
                             size_t *res_count,
                             struct sysdb_attrs ***res);

errno_t sudosrv_cache_set_entry(struct tevent_context *ev,
                                struct sudo_ctx *sudo_ctx,
                                hash_table_t *table,
                                struct sss_domain_info *domain,
                                const char *username,
                                size_t res_count,
                                struct sysdb_attrs **res,
                                time_t timeout);

#endif /* _SUDOSRV_PRIVATE_H_ */
