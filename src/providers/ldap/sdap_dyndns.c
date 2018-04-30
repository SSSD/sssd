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
                           const char *iface);
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
    const char *servername;
    int ttl;

    struct sss_iface_addr *addresses;
    struct sss_iface_addr *dns_addrlist;
    uint8_t remove_af;

    bool update_ptr;
    bool check_diff;
    enum be_nsupdate_auth auth_type;
    bool fallback_mode;
    char *update_msg;
    struct sss_iface_addr *ptr_addr_iter;
    bool del_phase;
};

static void sdap_dyndns_update_addrs_done(struct tevent_req *subreq);
static void sdap_dyndns_dns_addrs_done(struct tevent_req *subreq);
static errno_t sdap_dyndns_addrs_diff(struct sdap_dyndns_update_state *state,
                                      bool *_do_update);
static errno_t sdap_dyndns_update_step(struct tevent_req *req);
static errno_t sdap_dyndns_update_ptr_step(struct tevent_req *req);
static void sdap_dyndns_update_done(struct tevent_req *subreq);
static void sdap_dyndns_update_ptr_done(struct tevent_req *subreq);
static errno_t
sdap_dyndns_next_ptr_record(struct sdap_dyndns_update_state *state,
                            struct tevent_req *req);
static struct sss_iface_addr*
sdap_get_address_to_delete(struct sss_iface_addr *address_it,
                           uint8_t remove_af);

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
                        const char *ifname,
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
    state->update_ptr = dp_opt_get_bool(opts, DP_OPT_DYNDNS_UPDATE_PTR);
    state->hostname = hostname;
    state->realm = realm;
    state->servername = NULL;
    state->fallback_mode = false;
    state->ttl = ttl;
    state->be_res = be_ctx->be_res;
    state->ev = ev;
    state->opts = opts;
    state->auth_type = auth_type;
    state->ptr_addr_iter = NULL;
    state->del_phase = true;

    /* fallback servername is overriden by user option */
    conf_servername = dp_opt_get_string(opts, DP_OPT_DYNDNS_SERVER);
    if (conf_servername != NULL) {
        state->servername = conf_servername;
    }

    if (ifname) {
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

    subreq = sdap_dyndns_get_addrs_send(state, state->ev, sdap_ctx, ifname);
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
    const char *servername;
    const char *realm;
    struct tevent_req *subreq;

    state = tevent_req_data(req, struct sdap_dyndns_update_state);

    servername = NULL;
    realm = NULL;
    if (state->fallback_mode) {
        servername = state->servername;
        realm = state->realm;
    }

    ret = be_nsupdate_create_fwd_msg(state, realm, servername,
                                     state->hostname,
                                     state->ttl, state->remove_af,
                                     state->addresses,
                                     &state->update_msg);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Can't get addresses for DNS update\n");
        return ret;
    }

    /* Fork a child process to perform the DNS update */
    subreq = be_nsupdate_send(state, state->ev, state->auth_type,
                              state->update_msg,
                              dp_opt_get_bool(state->opts,
                                              DP_OPT_DYNDNS_FORCE_TCP));
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

    /* init iterator for addresses to be deleted */
    state->ptr_addr_iter = sdap_get_address_to_delete(state->dns_addrlist,
                                                      state->remove_af);
    if (state->ptr_addr_iter == NULL) {
        /* init iterator for addresses to be added */
        state->del_phase = false;
        state->ptr_addr_iter = state->addresses;
    }

    ret = sdap_dyndns_update_ptr_step(req);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }
    /* Execution will resume in sdap_dyndns_update_ptr_done */
}


static bool remove_addr(int address_family, uint8_t remove_af)
{
    bool ret = false;

    switch(address_family) {
    case AF_INET:
        if (remove_af & DYNDNS_REMOVE_A) {
            ret = true;
        }
        break;
    case AF_INET6:
        if (remove_af & DYNDNS_REMOVE_AAAA) {
            ret = true;
        }
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Unknown address family\n");
        ret = false;
    }

    return ret;
}

static struct sss_iface_addr*
sdap_get_address_to_delete(struct sss_iface_addr *address_it,
                           uint8_t remove_af)
{
    struct sockaddr_storage* address;

    while (address_it != NULL) {
        address = sss_iface_addr_get_address(address_it);

        /* skip addresses that are not to be deleted */
        if (remove_addr(address->ss_family, remove_af)) {
            break;
        }

        address_it = sss_iface_addr_get_next(address_it);
    }

    return address_it;
}

static errno_t
sdap_dyndns_update_ptr_step(struct tevent_req *req)
{
    errno_t ret;
    struct sdap_dyndns_update_state *state;
    const char *servername;
    const char *realm;
    struct tevent_req *subreq;
    struct sockaddr_storage *address;

    state = tevent_req_data(req, struct sdap_dyndns_update_state);

    servername = NULL;
    realm = NULL;
    if (state->fallback_mode == true) {
        servername = state->servername;
        realm = state->realm;
    }

    address = sss_iface_addr_get_address(state->ptr_addr_iter);
    if (address == NULL) {
        return EIO;
    }

    ret = be_nsupdate_create_ptr_msg(state, realm, servername, state->hostname,
                                     state->ttl, address, state->del_phase,
                                     &state->update_msg);

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Can't get addresses for DNS update\n");
        return ret;
    }

    /* Fork a child process to perform the DNS update */
    subreq = be_nsupdate_send(state, state->ev, state->auth_type,
                              state->update_msg,
                              dp_opt_get_bool(state->opts,
                                              DP_OPT_DYNDNS_FORCE_TCP));
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

        ret = sdap_dyndns_next_ptr_record(state, req);
        if (ret == EAGAIN) {
            return;
        }

        tevent_req_error(req, ret);
        return;
    }

    ret = sdap_dyndns_next_ptr_record(state, req);
    if (ret == EAGAIN) {
        return;
    }

    tevent_req_done(req);
}

static errno_t
sdap_dyndns_next_ptr_record(struct sdap_dyndns_update_state *state,
                            struct tevent_req *req)
{
    errno_t ret;

    if (state->del_phase) {
        /* iterate to next address to delete */
        state->ptr_addr_iter = sdap_get_address_to_delete(
            sss_iface_addr_get_next(state->ptr_addr_iter), state->remove_af);
        if (state->ptr_addr_iter == NULL) {
            /* init iterator for addresses to be added */
            state->del_phase = false;
            state->ptr_addr_iter = state->addresses;
        }
    } else {
        /* iterate to next address to add */
        state->ptr_addr_iter = sss_iface_addr_get_next(state->ptr_addr_iter);
    }

    if (state->ptr_addr_iter != NULL) {

        state->fallback_mode = false;
        ret = sdap_dyndns_update_ptr_step(req);
        if (ret == EOK) {
            return EAGAIN;
        }
    }

    return EOK;
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
};

static void sdap_dyndns_get_addrs_done(struct tevent_req *subreq);
static errno_t sdap_dyndns_add_ldap_conn(struct sdap_dyndns_get_addrs_state *state,
                                         struct sdap_handle *sh);

static errno_t get_ifaces_addrs(TALLOC_CTX *mem_ctx,
                                const char *iface,
                                struct sss_iface_addr **_result)
{
    struct sss_iface_addr *result_addrs = NULL;
    struct sss_iface_addr *intf_addrs;
    TALLOC_CTX *tmp_ctx;
    char **list_of_intfs;
    int num_of_intfs;
    errno_t ret;
    int i;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = split_on_separator(tmp_ctx, iface, ',', true, true, &list_of_intfs,
                             &num_of_intfs);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Parsing names of interfaces failed - %d:[%s].\n",
              ret, sss_strerror(ret));
        goto done;
    }

    for (i = 0; i < num_of_intfs; i++) {
        ret = sss_iface_addr_list_get(tmp_ctx, list_of_intfs[i], &intf_addrs);
        if (ret == EOK) {
            if (result_addrs != NULL) {
                /* If there is already an existing list, head of this existing
                 * list will be considered as parent talloc context for the
                 * new list.
                 */
                talloc_steal(result_addrs, intf_addrs);
            }
            sss_iface_addr_concatenate(&result_addrs, intf_addrs);
        } else if (ret == ENOENT) {
            /* non-critical failure */
            DEBUG(SSSDBG_TRACE_FUNC,
                  "Cannot get interface %s or there are no addresses "
                  "bind to it.\n", list_of_intfs[i]);
        } else {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Cannot get list of addresses from interface %s - %d:[%s]\n",
                  list_of_intfs[i], ret, sss_strerror(ret));
            goto done;
        }
    }

    ret = EOK;
    *_result = talloc_steal(mem_ctx, result_addrs);

done:
    talloc_free(tmp_ctx);
    return ret;
}

static struct tevent_req *
sdap_dyndns_get_addrs_send(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           struct sdap_id_ctx *sdap_ctx,
                           const char *iface)
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

    if (iface) {
        ret = get_ifaces_addrs(state, iface, &state->addresses);
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
    struct sockaddr_storage ss;
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

struct sdap_dyndns_timer_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *sdap_ctx;
    struct be_nsupdate_ctx *dyndns_ctx;

    struct sdap_id_op *sdap_op;
};

static void sdap_dyndns_timer_conn_done(struct tevent_req *req);

struct tevent_req *
sdap_dyndns_timer_conn_send(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct sdap_id_ctx *sdap_ctx,
                            struct be_nsupdate_ctx *dyndns_ctx)
{
    struct sdap_dyndns_timer_state *state;
    struct tevent_req *req;
    struct tevent_req *subreq;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct sdap_dyndns_timer_state);
    if (req == NULL) {
        return NULL;
    }
    state->ev = ev;
    state->sdap_ctx = sdap_ctx;
    state->dyndns_ctx = dyndns_ctx;

    /* In order to prevent the connection triggering an
     * online callback which would in turn trigger a concurrent DNS
     * update
     */
    state->dyndns_ctx->timer_in_progress = true;

    /* Make sure to have a valid LDAP connection */
    state->sdap_op = sdap_id_op_create(state, state->sdap_ctx->conn->conn_cache);
    if (state->sdap_op == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create failed\n");
        ret = ENOMEM;
        goto fail;
    }

    subreq = sdap_id_op_connect_send(state->sdap_op, state, &ret);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_connect_send failed: [%d](%s)\n",
              ret, sss_strerror(ret));
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, sdap_dyndns_timer_conn_done, req);
    return req;

fail:
    dyndns_ctx->timer_in_progress = false;
    be_nsupdate_timer_schedule(ev, dyndns_ctx);
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void
sdap_dyndns_timer_conn_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_dyndns_timer_state *state = tevent_req_data(req,
                                            struct sdap_dyndns_timer_state);
    errno_t ret;
    int dp_error;

    state->dyndns_ctx->timer_in_progress = false;

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);
    if (ret != EOK) {
        if (dp_error == DP_ERR_OFFLINE) {
            DEBUG(SSSDBG_MINOR_FAILURE, "No server is available, "
                  "dynamic DNS update is skipped in offline mode.\n");
            /* Another timer will be scheduled when provider goes online */
            tevent_req_error(req, ERR_DYNDNS_OFFLINE);
        } else {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to connect to LDAP server: [%d](%s)\n",
                  ret, sss_strerror(ret));

            /* Just schedule another dyndns retry */
            be_nsupdate_timer_schedule(state->ev, state->dyndns_ctx);
            tevent_req_error(req, ERR_NETWORK_IO);
        }
        return;
    }

    /* All OK, schedule another refresh and let the user call its
     * provider-specific update
     */
    be_nsupdate_timer_schedule(state->ev, state->dyndns_ctx);
    tevent_req_done(req);
}

errno_t
sdap_dyndns_timer_conn_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}
