/*
    SSSD

    dp_dyndns.h

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


#ifndef DP_DYNDNS_H_
#define DP_DYNDNS_H_

/* dynamic dns helpers */
struct sss_iface_addr;

typedef void (*nsupdate_timer_fn_t)(void *pvt);

enum be_nsupdate_auth {
    BE_NSUPDATE_AUTH_NONE,
    BE_NSUPDATE_AUTH_GSS_TSIG,
};

struct be_nsupdate_ctx {
    struct dp_option *opts;
    enum be_nsupdate_auth auth_type;

    time_t last_refresh;
    bool timer_in_progress;
    struct tevent_timer *refresh_timer;
    nsupdate_timer_fn_t timer_callback;
    void *timer_pvt;
};

enum dp_dyndns_opts {
    DP_OPT_DYNDNS_UPDATE,
    DP_OPT_DYNDNS_UPDATE_PER_FAMILY,
    DP_OPT_DYNDNS_REFRESH_INTERVAL,
    DP_OPT_DYNDNS_IFACE,
    DP_OPT_DYNDNS_TTL,
    DP_OPT_DYNDNS_UPDATE_PTR,
    DP_OPT_DYNDNS_FORCE_TCP,
    DP_OPT_DYNDNS_AUTH,
    DP_OPT_DYNDNS_SERVER,

    DP_OPT_DYNDNS /* attrs counter */
};

#define DYNDNS_REMOVE_A     0x1
#define DYNDNS_REMOVE_AAAA  0x2

errno_t be_nsupdate_check(void);

errno_t
be_nsupdate_init(TALLOC_CTX *mem_ctx, struct be_ctx *be_ctx,
                 struct dp_option *defopts,
                 struct be_nsupdate_ctx **_ctx);

errno_t be_nsupdate_init_timer(struct be_nsupdate_ctx *ctx,
                               struct tevent_context *ev,
                               nsupdate_timer_fn_t timer_callback,
                               void *timer_pvt);

void be_nsupdate_timer_schedule(struct tevent_context *ev,
                                struct be_nsupdate_ctx *ctx);

errno_t
sss_iface_addr_list_get(TALLOC_CTX *mem_ctx, const char *ifname,
                        struct sss_iface_addr **_addrlist);

errno_t
sss_iface_addr_list_as_str_list(TALLOC_CTX *mem_ctx,
                                struct sss_iface_addr *ifaddr_list,
                                char ***_straddrs);

errno_t
be_nsupdate_create_fwd_msg(TALLOC_CTX *mem_ctx, const char *realm,
                           const char *servername,
                           const char *hostname, const unsigned int ttl,
                           uint8_t remove_af, struct sss_iface_addr *addresses,
                           bool update_per_family,
                           char **_update_msg);

errno_t
be_nsupdate_create_ptr_msg(TALLOC_CTX *mem_ctx, const char *realm,
                           const char *servername,
                           const char *hostname, const unsigned int ttl,
                           uint8_t remove_af, struct sss_iface_addr *addresses,
                           bool update_per_family,
                           char **_update_msg);

/* Returns:
 *    * ERR_OK              - on success
 *    * ERR_DYNDNS_FAILED   - if nsupdate fails for any reason
 *    * ERR_DYNDNS_TIMEOUT  - if the update times out. child_status
 *                            is ETIMEDOUT in this case
 */
struct tevent_req *be_nsupdate_send(TALLOC_CTX *mem_ctx,
                                    struct tevent_context *ev,
                                    enum be_nsupdate_auth auth_type,
                                    char *nsupdate_msg,
                                    bool force_tcp);
errno_t be_nsupdate_recv(struct tevent_req *req, int *child_status);

struct tevent_req * nsupdate_get_addrs_send(TALLOC_CTX *mem_ctx,
                                            struct tevent_context *ev,
                                            struct be_resolv_ctx *be_res,
                                            const char *hostname);
errno_t
nsupdate_get_addrs_recv(struct tevent_req *req,
                        TALLOC_CTX *mem_ctx,
                        struct sss_iface_addr **_addrlist,
                        size_t *_count);

void
sss_iface_addr_concatenate(struct sss_iface_addr **list,
                           struct sss_iface_addr *list2);

errno_t
sss_get_dualstack_addresses(TALLOC_CTX *mem_ctx,
                            struct sockaddr *ss,
                            struct sss_iface_addr **_iface_addrs);

struct sss_iface_addr *
sss_iface_addr_get_next(struct sss_iface_addr *address);

struct sockaddr_storage*
sss_iface_addr_get_address(struct sss_iface_addr *address);

#endif /* DP_DYNDNS_H_ */
