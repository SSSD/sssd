/*
    SSSD

    sdap_dyndns.c: LDAP specific dynamic DNS update

    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2013 Red Hat

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

#include <sys/wait.h>

#include "util/util.h"
#include "resolv/async_resolv.h"
#include "providers/backend.h"
#include "providers/be_dyndns.h"
#include "providers/ldap/sdap_async_private.h"
#include "providers/ldap/sdap_dyndns.h"
#include "providers/ldap/sdap_id_op.h"
#include "providers/ldap/ldap_common.h"

static struct tevent_req *
sdap_dyndns_get_addrs_send(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           struct sdap_id_ctx *sdap_ctx,
                           const char *iface,
                           const char *addrs);
static errno_t
sdap_dyndns_get_addrs_recv(struct tevent_req *req,
                           TALLOC_CTX *mem_ctx,
                           struct sss_iface_addr **_addresses);

struct sdap_dyndns_update_state {
    struct tevent_context *ev;
    struct be_resolv_ctx *be_res;
    struct dp_option *opts;

    const char *hostname;
    const char *realm;
    struct sss_parsed_dns_uri *server_uri;
    bool dot;
    int ttl;

    struct sss_iface_addr *addresses;
    struct sss_iface_addr *dns_addrlist;
    uint8_t remove_af;

    bool update_per_family;
    bool update_ptr;
    bool check_diff;
    enum be_nsupdate_auth auth_type;
    enum be_nsupdate_auth auth_ptr_type;
    bool fallback_mode;
    char *update_msg;
};

static void sdap_dyndns_update_addrs_done(struct tevent_req *subreq);
static void sdap_dyndns_dns_addrs_done(struct tevent_req *subreq);
static errno_t sdap_dyndns_addrs_diff(struct sdap_dyndns_update_state *state,
                                      bool *_do_update);
static errno_t sdap_dyndns_update_step(struct tevent_req *req);
static errno_t sdap_dyndns_update_ptr_step(struct tevent_req *req);
static void sdap_dyndns_update_done(struct tevent_req *subreq);
static void sdap_dyndns_update_ptr_done(struct tevent_req *subreq);

static bool should_retry(int nsupdate_ret, int child_status)
{
    if ((WIFEXITED(child_status) && WEXITSTATUS(child_status) != 0)
         || nsupdate_ret == ERR_DYNDNS_TIMEOUT) {
        return true;
    }

    return false;
}

struct tevent_req *
sdap_dyndns_update_send(TALLOC_CTX *mem_ctx,
                        struct tevent_context *ev,
                        struct be_ctx *be_ctx,
                        struct dp_option *opts,
                        struct sdap_id_ctx *sdap_ctx,
                        enum be_nsupdate_auth auth_type,
                        enum be_nsupdate_auth auth_ptr_type,
                        const char *ifname_filter,
                        const char *network_filter,
                        const char *hostname,
                        const char *realm,
                        const int ttl,
                        bool check_diff)
{
    errno_t ret;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct sdap_dyndns_update_state *state;
    const char *conf_servername;

    req = tevent_req_create(mem_ctx, &state, struct sdap_dyndns_update_state);
    if (req == NULL) {
        return NULL;
    }
    state->check_diff = check_diff;
    state->update_per_family = dp_opt_get_bool(opts, DP_OPT_DYNDNS_UPDATE_PER_FAMILY);
    state->update_ptr = dp_opt_get_bool(opts, DP_OPT_DYNDNS_UPDATE_PTR);
    state->hostname = hostname;
    state->realm = realm;
    state->server_uri = NULL;
    state->dot = false;
    state->fallback_mode = false;
    state->ttl = ttl;
    state->be_res = be_ctx->be_res;
    state->ev = ev;
    state->opts = opts;
    state->auth_type = auth_type;
    state->auth_ptr_type = auth_ptr_type;

    /* fallback servername is overridden by user option */
    conf_servername = dp_opt_get_string(opts, DP_OPT_DYNDNS_SERVER);
    if (conf_servername != NULL) {
        ret = sss_parse_dns_uri(mem_ctx, conf_servername, &state->server_uri);
        if (ret != EOK) {
            goto done;
        }
        state->dot = sss_is_dot_scheme(state->server_uri);
    }

    if (ifname_filter) {
       /* Unless one family is restricted, just replace all
        * address families during the update
        */
        switch (state->be_res->family_order) {
        case IPV4_ONLY:
            state->remove_af |= DYNDNS_REMOVE_A;
            break;
        case IPV6_ONLY:
            state->remove_af |= DYNDNS_REMOVE_AAAA;
            break;
        case IPV4_FIRST:
        case IPV6_FIRST:
            state->remove_af |= (DYNDNS_REMOVE_A |
                                 DYNDNS_REMOVE_AAAA);
            break;
        }
    } else {
        /* If the interface isn't specified, we ONLY want to have the address
         * that's connected to the LDAP server stored, so we need to check
         * (and later remove) both address families.
         */
        state->remove_af = (DYNDNS_REMOVE_A | DYNDNS_REMOVE_AAAA);
    }

    subreq = sdap_dyndns_get_addrs_send(state, state->ev, sdap_ctx,
                                        ifname_filter, network_filter);
    if (!subreq) {
        ret = EIO;
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_connect_send failed: [%d](%s)\n",
              ret, sss_strerror(ret));
        goto done;
    }
    tevent_req_set_callback(subreq, sdap_dyndns_update_addrs_done, req);

    ret = EOK;
done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }
    return req;
}

static void
sdap_dyndns_update_addrs_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req;
    struct sdap_dyndns_update_state *state;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_dyndns_update_state);

    ret = sdap_dyndns_get_addrs_recv(subreq, state, &state->addresses);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Can't get addresses for DNS update\n");
        tevent_req_error(req, ret);
        return;
    }

    if (state->check_diff || state->update_ptr) {
        /* Check if we need the update at all. In case we are updating the PTR
         * records as well, we need to know the old addresses to be able to
         * reliably delete the PTR records */
        subreq = nsupdate_get_addrs_send(state, state->ev,
                                         state->be_res, state->hostname);
        if (subreq == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Can't initiate address check\n");
            tevent_req_error(req, ret);
            return;
        }
        tevent_req_set_callback(subreq, sdap_dyndns_dns_addrs_done, req);
        return;
    }

    /* Perform update */
    ret = sdap_dyndns_update_step(req);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }
    /* Execution will resume in sdap_dyndns_update_done */
}

static void
sdap_dyndns_dns_addrs_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct sdap_dyndns_update_state *state;
    errno_t ret;
    bool do_update;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_dyndns_update_state);

    ret = nsupdate_get_addrs_recv(subreq, state, &state->dns_addrlist, NULL);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not receive list of current addresses [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    if (state->check_diff) {
        ret = sdap_dyndns_addrs_diff(state, &do_update);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not check the diff between DNS "
                  "and current addresses [%d]: %s\n", ret, strerror(ret));
            tevent_req_error(req, ret);
            return;
        }

        if (do_update == false) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "No DNS update needed, addresses did not change\n");
            tevent_req_done(req);
            return;
        }
        DEBUG(SSSDBG_TRACE_FUNC,
              "Detected IP addresses change, will perform an update\n");
    }

    /* Either we needed the addresses for updating PTR records only or
     * the addresses have changed (or both) */
    ret = sdap_dyndns_update_step(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not start the update [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
    }
    return;
}

static errno_t
sdap_dyndns_addrs_diff(struct sdap_dyndns_update_state *state, bool *_do_update)
{
    errno_t ret;
    int i;
    char **str_dnslist = NULL, **str_local_list = NULL;
    char **dns_only = NULL, **local_only = NULL;
    bool do_update = false;

    ret = sss_iface_addr_list_as_str_list(state,
                                          state->dns_addrlist, &str_dnslist);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
               "Converting DNS IP addresses to strings failed: [%d]: %s\n",
               ret, sss_strerror(ret));
        return ret;
    }

    ret = sss_iface_addr_list_as_str_list(state,
                                          state->addresses, &str_local_list);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
               "Converting local IP addresses to strings failed: [%d]: %s\n",
               ret, sss_strerror(ret));
        return ret;
    }

    /* Compare the lists */
    ret = diff_string_lists(state, str_dnslist, str_local_list,
                            &dns_only, &local_only, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "diff_string_lists failed: [%d]: %s\n", ret, sss_strerror(ret));
        return ret;
    }

    if (dns_only) {
        for (i=0; dns_only[i]; i++) {
            DEBUG(SSSDBG_TRACE_LIBS,
                  "Address in DNS only: %s\n", dns_only[i]);
            do_update = true;
        }
    }

    if (local_only) {
        for (i=0; local_only[i]; i++) {
            DEBUG(SSSDBG_TRACE_LIBS,
                  "Address on localhost only: %s\n", local_only[i]);
            do_update = true;
        }
    }

    *_do_update = do_update;
    return EOK;
}

static errno_t
sdap_dyndns_update_step(struct tevent_req *req)
{
    errno_t ret;
    struct sdap_dyndns_update_state *state;
    struct sss_parsed_dns_uri *server_uri;
    const char *realm;
    struct tevent_req *subreq;

    state = tevent_req_data(req, struct sdap_dyndns_update_state);

    server_uri = NULL;
    realm = NULL;
    if (state->dot) {
        /* in DoT we have to set the server */
        state->fallback_mode = true;
    }
    if (state->fallback_mode) {
        server_uri = state->server_uri;
        realm = state->realm;
    }

    ret = be_nsupdate_create_fwd_msg(state, realm, server_uri,
                                     state->hostname,
                                     state->ttl, state->remove_af,
                                     state->addresses,
                                     state->update_per_family,
                                     &state->update_msg);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Can't get addresses for DNS update\n");
        return ret;
    }

    /* Fork a child process to perform the DNS update */
    subreq = be_nsupdate_send(state, state->ev, state->auth_type,
                              state->update_msg,
                              dp_opt_get_bool(state->opts,
                                              DP_OPT_DYNDNS_FORCE_TCP),
                              state->server_uri,
                              dp_opt_get_string(state->opts,
                                                DP_OPT_DYNDNS_DOT_CACERT),
                              dp_opt_get_string(state->opts,
                                                DP_OPT_DYNDNS_DOT_CERT),
                              dp_opt_get_string(state->opts,
                                                DP_OPT_DYNDNS_DOT_KEY));
    if (subreq == NULL) {
        return EIO;
    }

    tevent_req_set_callback(subreq, sdap_dyndns_update_done, req);
    return EOK;
}

static void
sdap_dyndns_update_done(struct tevent_req *subreq)
{
    errno_t ret;
    int child_status;
    struct tevent_req *req;
    struct sdap_dyndns_update_state *state;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_dyndns_update_state);

    ret = be_nsupdate_recv(subreq, &child_status);
    talloc_zfree(subreq);
    if (ret != EOK) {
        /* If the update didn't succeed, we can retry using the server name */
        if (state->fallback_mode == false
                && should_retry(ret, child_status)) {
            state->fallback_mode = true;
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "nsupdate failed, retrying.\n");
            ret = sdap_dyndns_update_step(req);
            if (ret == EOK) {
                return;
            }
        }
    }

    if (state->update_ptr == false) {
        DEBUG(SSSDBG_TRACE_FUNC, "No PTR update requested, done\n");
        tevent_req_done(req);
        return;
    }

    talloc_free(state->update_msg);

    ret = sdap_dyndns_update_ptr_step(req);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }
    /* Execution will resume in sdap_dyndns_update_ptr_done */
}

static errno_t
sdap_dyndns_update_ptr_step(struct tevent_req *req)
{
    errno_t ret;
    struct sdap_dyndns_update_state *state;
    struct sss_parsed_dns_uri *server_uri;
    const char *realm;
    struct tevent_req *subreq;

    state = tevent_req_data(req, struct sdap_dyndns_update_state);

    server_uri = NULL;
    realm = NULL;
    if (state->dot == true) {
        /* in DoT we have to set the server */
        state->fallback_mode = true;
    }
    if (state->fallback_mode == true) {
        server_uri = state->server_uri;
        realm = state->realm;
    }

    ret = be_nsupdate_create_ptr_msg(state, realm, server_uri,
                                     state->hostname,
                                     state->ttl, state->remove_af,
                                     state->addresses,
                                     state->update_per_family,
                                     &state->update_msg);

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Can't get addresses for DNS update\n");
        return ret;
    }

    /* Fork a child process to perform the DNS update */
    subreq = be_nsupdate_send(state, state->ev, state->auth_ptr_type,
                              state->update_msg,
                              dp_opt_get_bool(state->opts,
                                              DP_OPT_DYNDNS_FORCE_TCP),
                              state->server_uri,
                              dp_opt_get_string(state->opts,
                                                DP_OPT_DYNDNS_DOT_CACERT),
                              dp_opt_get_string(state->opts,
                                                DP_OPT_DYNDNS_DOT_CERT),
                              dp_opt_get_string(state->opts,
                                                DP_OPT_DYNDNS_DOT_KEY));
    if (subreq == NULL) {
        return EIO;
    }

    tevent_req_set_callback(subreq, sdap_dyndns_update_ptr_done, req);
    return EOK;
}

static void
sdap_dyndns_update_ptr_done(struct tevent_req *subreq)
{
    errno_t ret;
    int child_status;
    struct tevent_req *req;
    struct sdap_dyndns_update_state *state;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_dyndns_update_state);

    ret = be_nsupdate_recv(subreq, &child_status);
    talloc_zfree(subreq);
    if (ret != EOK) {
        /* If the update didn't succeed, we can retry using the server name */
        if (state->fallback_mode == false
                && should_retry(ret, child_status)) {
            state->fallback_mode = true;
            DEBUG(SSSDBG_MINOR_FAILURE, "nsupdate failed, retrying\n");
            ret = sdap_dyndns_update_ptr_step(req);
            if (ret == EOK) {
                return;
            }
        }

        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t
sdap_dyndns_update_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

/* A request to get addresses to update with */
struct sdap_dyndns_get_addrs_state {
    struct sdap_id_op* sdap_op;
    struct sss_iface_addr *addresses;
    const char *network_filter;
};

static void sdap_dyndns_get_addrs_done(struct tevent_req *subreq);
static errno_t sdap_dyndns_add_ldap_conn(struct sdap_dyndns_get_addrs_state *state,
                                         struct sdap_handle *sh);

static errno_t get_ifaces_addrs(TALLOC_CTX *mem_ctx,
                                const char *iface_filter,
                                const char *network_filter,
                                struct sss_iface_addr **_result)
{
    struct sss_iface_addr *intf_addrs = NULL;
    TALLOC_CTX *tmp_ctx;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    *_result = NULL;
    ret = sss_iface_addr_list_get(tmp_ctx, iface_filter, network_filter, &intf_addrs);
    if (ret != EOK) {
        if (ret == ENOENT) {
            /* non-critical failure */
            DEBUG(SSSDBG_TRACE_FUNC,
                  "Cannot get addresses on interface [%s]. There is no address "
                  "bound to it or it is excluded due to filter [%s].\n",
                  iface_filter, network_filter);
            ret = EOK;
        } else {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Cannot get list of addresses from interface %s with filter [%s] - %d:[%s]\n",
                  iface_filter, network_filter, ret, sss_strerror(ret));
        }
        goto done;
    }

    *_result = talloc_steal(mem_ctx, intf_addrs);

done:
    talloc_free(tmp_ctx);
    return ret;
}

static struct tevent_req *
sdap_dyndns_get_addrs_send(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           struct sdap_id_ctx *sdap_ctx,
                           const char *iface_filter,
                           const char *network_filter)
{
    errno_t ret;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct sdap_dyndns_get_addrs_state *state;

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_dyndns_get_addrs_state);
    if (req == NULL) {
        return NULL;
    }

    if (iface_filter) {
        ret = get_ifaces_addrs(state, iface_filter, network_filter, &state->addresses);
        if (ret != EOK || state->addresses == NULL) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "get_ifaces_addrs() failed: %d:[%s]\n",
                  ret, sss_strerror(ret));
        }
        /* We're done. Just fake an async request completion */
        goto done;
    }

    /* Detect DYNDNS address from LDAP connection */
    state->sdap_op = sdap_id_op_create(state, sdap_ctx->conn->conn_cache);
    if (!state->sdap_op) {
        ret = ENOMEM;
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create failed\n");
        goto done;
    }
    state->network_filter = network_filter;

    subreq = sdap_id_op_connect_send(state->sdap_op, state, &ret);
    if (!subreq) {
        ret = EIO;
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_connect_send failed: [%d](%s)\n",
              ret, sss_strerror(ret));
        goto done;
    }
    tevent_req_set_callback(subreq, sdap_dyndns_get_addrs_done, req);

    ret = EAGAIN;
done:
    if (ret == EOK) {
        tevent_req_done(req);
        tevent_req_post(req, ev);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    /* EAGAIN - resolution in progress */
    return req;
}

static void
sdap_dyndns_get_addrs_done(struct tevent_req *subreq)
{
    errno_t ret;
    int dp_error;
    struct tevent_req *req;
    struct sdap_dyndns_get_addrs_state *state;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_dyndns_get_addrs_state);

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);
    if (ret != EOK) {
        if (dp_error == DP_ERR_OFFLINE) {
            DEBUG(SSSDBG_MINOR_FAILURE, "No LDAP server is available, "
                  "dynamic DNS update is skipped in offline mode.\n");
            ret = ERR_DYNDNS_OFFLINE;
        } else {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to connect to LDAP server: [%d](%s)\n",
                  ret, sss_strerror(ret));
        }
        tevent_req_error(req, ret);
        return;
    }

    ret = sdap_dyndns_add_ldap_conn(state, sdap_id_op_handle(state->sdap_op));
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Can't get addresses from LDAP connection\n");
        tevent_req_error(req, ret);
        return;
    }

    /* Got the address! Done! */
    tevent_req_done(req);
}

static errno_t
sdap_dyndns_add_ldap_conn(struct sdap_dyndns_get_addrs_state *state,
                          struct sdap_handle *sh)
{
    int ret;
    int fd;
    struct sockaddr_storage ss = {0};
    socklen_t ss_len = sizeof(ss);

    if (sh == NULL) {
        return EINVAL;
    }

    /* Get the file descriptor for the primary LDAP connection */
    ret = get_fd_from_ldap(sh->ldap, &fd);
    if (ret != EOK) {
        return ret;
    }

    errno = 0;
    ret = getsockname(fd, (struct sockaddr *) &ss, &ss_len);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to get socket name\n");
        return ret;
    }

    if (ss.ss_family != AF_INET && ss.ss_family != AF_INET6) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Connection to LDAP is neither IPv4 nor IPv6\n");
        return EIO;
    }

    ret = sss_get_dualstack_addresses(state, (struct sockaddr *) &ss,
                                      state->network_filter,
                                      &state->addresses);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "sss_get_dualstack_addresses failed: %d:[%s]\n",
              ret, sss_strerror(ret));
        return ret;
    }

    return EOK;
}

static errno_t
sdap_dyndns_get_addrs_recv(struct tevent_req *req,
                           TALLOC_CTX *mem_ctx,
                           struct sss_iface_addr **_addresses)
{
    struct sdap_dyndns_get_addrs_state *state;

    state = tevent_req_data(req, struct sdap_dyndns_get_addrs_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_addresses = talloc_steal(mem_ctx, state->addresses);
    return EOK;
}
