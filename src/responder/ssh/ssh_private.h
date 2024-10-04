/*
    Authors:
        Jan Cholasta <jcholast@redhat.com>

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

#ifndef _SSHSRV_PRIVATE_H_
#define _SSHSRV_PRIVATE_H_

#include "responder/common/responder.h"
#include "responder/common/cache_req/cache_req.h"

#ifdef BUILD_SSH_KNOWN_HOSTS_PROXY
#define SSS_SSH_KNOWN_HOSTS_PATH PUBCONF_PATH"/known_hosts"
#define SSS_SSH_KNOWN_HOSTS_TEMP_TMPL PUBCONF_PATH"/.known_hosts.XXXXXX"
#endif

struct ssh_ctx {
    struct resp_ctx *rctx;
    struct sss_names_ctx *snctx;

#ifdef BUILD_SSH_KNOWN_HOSTS_PROXY
    bool hash_known_hosts;
    int known_hosts_timeout;
#endif
    char *ca_db;
    bool use_cert_keys;

    time_t certmap_last_read;
    struct sss_certmap_ctx *sss_certmap_ctx;
    char **cert_rules;
    bool cert_rules_error;
};

struct sss_cmd_table *get_ssh_cmds(void);

errno_t
ssh_protocol_parse_user(struct cli_ctx *cli_ctx,
                        const char **_name,
                        const char **_domain);

errno_t
ssh_protocol_parse_host(struct cli_ctx *cli_ctx,
                        const char **_name,
                        const char **_alias,
                        const char **_domain);

void ssh_protocol_reply(struct cli_ctx *cli_ctx,
                        struct cache_req_result *result);

errno_t
ssh_protocol_done(struct cli_ctx *cli_ctx, errno_t error);

struct tevent_req * ssh_get_output_keys_send(TALLOC_CTX *mem_ctx,
                                        struct tevent_context *ev,
                                        struct cli_ctx *cli_ctx,
                                        struct sss_domain_info *domain,
                                        struct ldb_message *msg);

errno_t ssh_get_output_keys_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                                 struct sized_string *name,
                                 struct ldb_message_element ***elements,
                                 uint32_t *num_keys);

errno_t
ssh_protocol_build_reply(struct sss_packet *packet,
                         struct sized_string name,
                         struct ldb_message_element **elements,
                         uint32_t num_keys);

#ifdef BUILD_SSH_KNOWN_HOSTS_PROXY
errno_t
ssh_update_known_hosts_file(struct sss_domain_info *domains,
                            struct sss_domain_info *domain,
                            const char *name,
                            bool hash_known_hosts,
                            int known_hosts_timeout);
#endif

struct tevent_req *cert_to_ssh_key_send(TALLOC_CTX *mem_ctx,
                                        struct tevent_context *ev,
                                        const char *logfile, time_t timeout,
                                        const char *ca_db,
                                        struct sss_certmap_ctx *sss_certmap_ctx,
                                        size_t cert_count,
                                        struct ldb_val *bin_certs,
                                        const char *verify_opts);

errno_t cert_to_ssh_key_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                             struct ldb_val **keys, size_t *valid_keys);
#endif /* _SSHSRV_PRIVATE_H_ */
