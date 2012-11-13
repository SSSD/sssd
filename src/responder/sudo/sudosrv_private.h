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
#include <sys/types.h>

#include "src/db/sysdb.h"
#include "responder/common/responder.h"

#define SSS_SUDO_ERROR_OK 0
#define SSS_SUDO_SBUS_SERVICE_VERSION 0x0001
#define SSS_SUDO_SBUS_SERVICE_NAME "sudo"

enum sss_dp_sudo_type {
    SSS_DP_SUDO_REFRESH_RULES,
    SSS_DP_SUDO_FULL_REFRESH
};

enum sss_sudo_type {
    SSS_SUDO_DEFAULTS,
    SSS_SUDO_USER
};

struct sudo_ctx {
    struct resp_ctx *rctx;

    /*
     * options
     */
    bool timed;
};

struct sudo_cmd_ctx {
    struct cli_ctx *cli_ctx;
    struct sudo_ctx *sudo_ctx;
    enum sss_sudo_type type;

    /* input data */
    uid_t uid;
    char *username;
    const char *orig_username;
    const char *cased_username;
    struct sss_domain_info *domain;
    bool check_next;

    size_t expired_rules_num;

    /* output data */
    struct sysdb_attrs **rules;
    size_t num_rules;
};

struct sudo_dom_ctx {
    struct sudo_cmd_ctx *cmd_ctx;
    struct sss_domain_info *domain;
    bool check_provider;
};

struct sudo_dp_request {
    struct cli_ctx *cctx;
    struct sss_domain_info *domain;
};

struct sss_cmd_table *get_sudo_cmds(void);

errno_t sudosrv_cmd_done(struct sudo_cmd_ctx *cmd_ctx, int ret);

errno_t sudosrv_get_sudorules(struct sudo_dom_ctx *dctx);

errno_t sudosrv_get_rules(struct sudo_cmd_ctx *cmd_ctx);

struct tevent_req *sudosrv_parse_query_send(TALLOC_CTX *mem_ctx,
                                            struct resp_ctx *rctx,
                                            uint8_t *query_body,
                                            size_t query_len);

errno_t sudosrv_parse_query_recv(TALLOC_CTX *mem_ctx,
                                 struct tevent_req *req,
                                 uid_t *_uid,
                                 char **_username,
                                 struct sss_domain_info **_domain);

errno_t sudosrv_build_response(TALLOC_CTX *mem_ctx,
                               uint32_t error,
                               int rules_num,
                               struct sysdb_attrs **rules,
                               uint8_t **_response_body,
                               size_t *_response_len);

struct tevent_req *
sss_dp_get_sudoers_send(TALLOC_CTX *mem_ctx,
                        struct resp_ctx *rctx,
                        struct sss_domain_info *dom,
                        bool fast_reply,
                        enum sss_dp_sudo_type type,
                        const char *name,
                        size_t num_rules,
                        struct sysdb_attrs **rules);

errno_t
sss_dp_get_sudoers_recv(TALLOC_CTX *mem_ctx,
                        struct tevent_req *req,
                        dbus_uint16_t *err_maj,
                        dbus_uint32_t *err_min,
                        char **err_msg);

#endif /* _SUDOSRV_PRIVATE_H_ */
