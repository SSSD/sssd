/*
    SSSD

    ipa_dyndns.c

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2010 Red Hat

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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <ctype.h>
#include "util/util.h"
#include "confdb/confdb.h"
#include "providers/ipa/ipa_common.h"
#include "providers/ipa/ipa_dyndns.h"
#include "util/child_common.h"
#include "providers/data_provider.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_async_private.h"
#include "resolv/async_resolv.h"

#define IPA_DYNDNS_TIMEOUT 15

#define IPA_DYNDNS_REMOVE_A     0x1
#define IPA_DYNDNS_REMOVE_AAAA  0x2

struct ipa_ipaddress {
    struct ipa_ipaddress *next;
    struct ipa_ipaddress *prev;

    struct sockaddr_storage *addr;
    bool matched;
};

struct ipa_dyndns_ctx {
    struct ipa_options *ipa_ctx;
    struct sdap_id_op* sdap_op;
    char *hostname;
    struct ipa_ipaddress *addresses;
    bool use_server_with_nsupdate;
    uint8_t remove_af;
    enum restrict_family family_order;
};


static struct tevent_req * ipa_dyndns_update_send(struct ipa_options *ctx);

static void ipa_dyndns_update_done(struct tevent_req *req);

static errno_t
ipa_ipaddress_list_as_string_list(TALLOC_CTX *mem_ctx,
                                  struct ipa_ipaddress *ipa_addr_list,
                                  char ***_straddrs)
{
    struct ipa_ipaddress *ipa_addr;
    size_t count;
    int ai;
    char **straddrs;
    const char *ip;
    char ip_addr[INET6_ADDRSTRLEN];
    errno_t ret;

    count = 0;
    DLIST_FOR_EACH(ipa_addr, ipa_addr_list) {
        count++;
    }

    straddrs = talloc_array(mem_ctx, char *, count+1);
    if (straddrs == NULL) {
        return ENOMEM;
    }

    ai = 0;
    DLIST_FOR_EACH(ipa_addr, ipa_addr_list) {
        switch(ipa_addr->addr->ss_family) {
        case AF_INET:
            errno = 0;
            ip = inet_ntop(ipa_addr->addr->ss_family,
                           &(((struct sockaddr_in *)ipa_addr->addr)->sin_addr),
                           ip_addr, INET6_ADDRSTRLEN);
            if (ip == NULL) {
                ret = errno;
                goto fail;
            }
            break;

        case AF_INET6:
            errno = 0;
            ip = inet_ntop(ipa_addr->addr->ss_family,
                           &(((struct sockaddr_in6 *)ipa_addr->addr)->sin6_addr),
                           ip_addr, INET6_ADDRSTRLEN);
            if (ip == NULL) {
                ret = errno;
                goto fail;
            }
            break;

        default:
            DEBUG(0, ("Unknown address family\n"));
            continue;
        }

        straddrs[ai] = talloc_strdup(straddrs, ip);
        if (straddrs[ai] == NULL) {
            ret = ENOMEM;
            goto fail;
        }
        ai++;
    }

    straddrs[count] = NULL;
    *_straddrs = straddrs;
    return EOK;

fail:
    talloc_free(straddrs);
    return ret;
}


errno_t ipa_dyndns_init(struct be_ctx *be_ctx,
                        struct ipa_options *ctx)
{
    errno_t ret;
    int resolv_timeout;

    ret = confdb_get_int(be_ctx->cdb, be_ctx->conf_path,
                         CONFDB_DOMAIN_RESOLV_TIMEOUT,
                         RESOLV_DEFAULT_TIMEOUT, &resolv_timeout);
    if (ret != EOK) {
        DEBUG(1, ("Could get the timeout parameter from confdb\n"));
        return ret;
    }

    ret = resolv_init(be_ctx, be_ctx->ev, resolv_timeout, &ctx->resolv);
    if (ret != EOK) {
        DEBUG(1, ("Could not set up resolver context\n"));
        return ret;
    }

    ret = be_add_online_cb(be_ctx, be_ctx,
                           ipa_dyndns_update,
                           ctx, NULL);
    if (ret != EOK) {
        DEBUG(1, ("Could not set up online callback\n"));
        return ret;
    }

    return EOK;
}

void ipa_dyndns_update(void *pvt)
{
    struct ipa_options *ctx = talloc_get_type(pvt, struct ipa_options);
    struct tevent_req *req = ipa_dyndns_update_send(ctx);
    if (req == NULL) {
        DEBUG(1, ("Could not update DNS\n"));
        return;
    }
    tevent_req_set_callback(req, ipa_dyndns_update_done, NULL);
}

static bool ok_for_dns(struct sockaddr *sa)
{
    char straddr[INET6_ADDRSTRLEN];

    if (sa->sa_family == AF_INET6) {
        struct in6_addr *addr = &((struct sockaddr_in6 *) sa)->sin6_addr;

        if (inet_ntop(AF_INET6, addr, straddr, INET6_ADDRSTRLEN) == NULL) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("inet_ntop failed, won't log IP addresses\n"));
            snprintf(straddr, INET6_ADDRSTRLEN, "unknown");
        }

        if (IN6_IS_ADDR_LINKLOCAL(addr)) {
            DEBUG(SSSDBG_FUNC_DATA, ("Link local IPv6 address %s\n", straddr));
            return false;
        } else if (IN6_IS_ADDR_LOOPBACK(addr)) {
            DEBUG(SSSDBG_FUNC_DATA, ("Loopback IPv6 address %s\n", straddr));
            return false;
        } else if (IN6_IS_ADDR_MULTICAST(addr)) {
            DEBUG(SSSDBG_FUNC_DATA, ("Multicast IPv6 address %s\n", straddr));
            return false;
        }
    } else if (sa->sa_family == AF_INET) {
        struct in_addr *addr = &((struct sockaddr_in *) sa)->sin_addr;

        if (inet_ntop(AF_INET, addr, straddr, INET6_ADDRSTRLEN) == NULL) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("inet_ntop failed, won't log IP addresses\n"));
            snprintf(straddr, INET6_ADDRSTRLEN, "unknown");
        }

        if (IN_MULTICAST(addr->s_addr)) {
            DEBUG(SSSDBG_FUNC_DATA, ("Multicast IPv4 address %s\n", straddr));
            return false;
        } else if (inet_netof(*addr) == IN_LOOPBACKNET) {
            DEBUG(SSSDBG_FUNC_DATA, ("Loopback IPv4 address %s\n", straddr));
            return false;
        } else if ((addr->s_addr & 0xffff0000) == 0xa9fe0000) {
            /* 169.254.0.0/16 */
            DEBUG(SSSDBG_FUNC_DATA, ("Link-local IPv4 address %s\n", straddr));
            return false;
        } else if (addr->s_addr == htonl(INADDR_BROADCAST)) {
            DEBUG(SSSDBG_FUNC_DATA, ("Broadcast IPv4 address %s\n", straddr));
            return false;
        }
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Unknown address family\n"));
        return false;
    }

    return true;
}

static void ipa_dyndns_sdap_connect_done(struct tevent_req *subreq);
static int ipa_dyndns_add_ldap_iface(struct ipa_dyndns_ctx *state,
                                     struct sdap_handle *sh);
static int ipa_dyndns_gss_tsig_update_step(struct tevent_req *req);

static struct tevent_req *
ipa_dyndns_gss_tsig_update_send(struct ipa_dyndns_ctx *ctx);

static void ipa_dyndns_gss_tsig_update_done(struct tevent_req *subreq);

static struct tevent_req *
ipa_dyndns_update_send(struct ipa_options *ctx)
{
    int ret;
    char *iface;
    struct ipa_dyndns_ctx *state;
    struct ifaddrs *ifaces;
    struct ifaddrs *ifa;
    struct ipa_ipaddress *address;
    struct tevent_req *req, *subreq;
    size_t addrsize;

    DEBUG (9, ("Performing update\n"));

    req = tevent_req_create(ctx, &state, struct ipa_dyndns_ctx);
    if (req == NULL) {
        return NULL;
    }
    state->ipa_ctx = ctx;
    state->use_server_with_nsupdate = false;

    iface = dp_opt_get_string(ctx->basic, IPA_DYNDNS_IFACE);

    if (iface) {
        /* Get the IP addresses associated with the
         * specified interface
         */
        errno = 0;
        ret = getifaddrs(&ifaces);
        if (ret == -1) {
            ret = errno;
            DEBUG(0, ("Could not read interfaces [%d][%s]\n",
                      ret, strerror(ret)));
            goto failed;
        }

        for(ifa = ifaces; ifa != NULL; ifa=ifa->ifa_next) {
            /* Some interfaces don't have an ifa_addr */
            if (!ifa->ifa_addr) continue;

            /* Add IP addresses to the list */
            if((ifa->ifa_addr->sa_family == AF_INET ||
                ifa->ifa_addr->sa_family == AF_INET6) &&
               strcasecmp(ifa->ifa_name, iface) == 0 &&
               ok_for_dns(ifa->ifa_addr)) {

                /* Add this address to the IP address list */
                address = talloc_zero(state, struct ipa_ipaddress);
                if (!address) {
                    goto failed;
                }

                addrsize = ifa->ifa_addr->sa_family == AF_INET ? \
                                    sizeof(struct sockaddr_in) : \
                                    sizeof(struct sockaddr_in6);

                address->addr = talloc_memdup(address, ifa->ifa_addr,
                                              addrsize);
                if(address->addr == NULL) {
                    goto failed;
                }
                DLIST_ADD(state->addresses, address);
            }
        }

        freeifaddrs(ifaces);

        ret = ipa_dyndns_gss_tsig_update_step(req);
        if (ret != EOK) {
            goto failed;
        }
    }

    else {
        /* Detect DYNDNS interface from LDAP connection */
        state->sdap_op = sdap_id_op_create(state, state->ipa_ctx->id_ctx->sdap_id_ctx->conn_cache);
        if (!state->sdap_op) {
            DEBUG(1, ("sdap_id_op_create failed\n"));
            ret = ENOMEM;
            goto failed;
        }

        subreq = sdap_id_op_connect_send(state->sdap_op, state, &ret);
        if (!subreq) {
            DEBUG(1, ("sdap_id_op_connect_send failed: [%d](%s)\n",
                ret, strerror(ret)));

            goto failed;
        }

        tevent_req_set_callback(subreq, ipa_dyndns_sdap_connect_done, req);
    }

    return req;

failed:
    talloc_free(req);
    return NULL;
}

static void ipa_dyndns_sdap_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
    struct ipa_dyndns_ctx *state = tevent_req_data(req, struct ipa_dyndns_ctx);
    int ret, dp_error;

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (ret != EOK) {
        if (dp_error == DP_ERR_OFFLINE) {
            DEBUG(9,("No LDAP server is available, dynamic DNS update is skipped in OFFLINE mode.\n"));
        } else {
            DEBUG(9,("Failed to connect to LDAP server: [%d](%s)\n",
                ret, strerror(ret)));
        }

        goto failed;
    }

    ret = ipa_dyndns_add_ldap_iface(state, sdap_id_op_handle(state->sdap_op));
    talloc_zfree(state->sdap_op);
    if (ret != EOK) {
        goto failed;
    }

    ret = ipa_dyndns_gss_tsig_update_step(req);
    if (ret != EOK) {
        goto failed;
    }

    return;

failed:
    tevent_req_error(req, ret);
}

static int ipa_dyndns_add_ldap_iface(struct ipa_dyndns_ctx *state,
                                     struct sdap_handle *sh)
{
    int ret;
    int fd;
    struct ipa_ipaddress *address;
    struct sockaddr_storage ss;
    socklen_t ss_len = sizeof(ss);

    if (!sh) {
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
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to get socket name\n"));
        return ret;
    }

    switch(ss.ss_family) {
    case AF_INET:
    case AF_INET6:
        address = talloc(state, struct ipa_ipaddress);
        if (!address) {
            return ENOMEM;
        }
        address->addr = talloc_memdup(address, &ss,
                                      sizeof(struct sockaddr_storage));
        if(address->addr == NULL) {
            talloc_zfree(address);
            return ENOMEM;
        }
        DLIST_ADD(state->addresses, address);
        break;
    default:
        DEBUG(1, ("Connection to LDAP is neither IPv4 nor IPv6\n"));
        return EIO;
    }

    return EOK;
}

static struct tevent_req *
ipa_dyndns_update_get_addrs_send(TALLOC_CTX *mem_ctx,
                                 struct ipa_dyndns_ctx *ctx,
                                 enum restrict_family family_order);
static errno_t
ipa_dyndns_update_get_addrs_recv(struct tevent_req *req,
                                 TALLOC_CTX *mem_ctx,
                                 char ***_addrlist);

static errno_t
ipa_dyndns_gss_tsig_update_setup_check(struct ipa_dyndns_ctx *state);
static void
ipa_dyndns_gss_tsig_update_check(struct tevent_req *subreq);

static int ipa_dyndns_gss_tsig_update_step(struct tevent_req *req)
{
    struct ipa_dyndns_ctx *state = tevent_req_data(req, struct ipa_dyndns_ctx);
    char *ipa_hostname;
    struct tevent_req *subreq;
    errno_t ret;

    /* Get the IPA hostname */
    ipa_hostname = dp_opt_get_string(state->ipa_ctx->basic,
                                     IPA_HOSTNAME);
    if (!ipa_hostname) {
        /* This should never happen, but we'll protect
         * against it anyway.
         */
        return EINVAL;
    }

    state->hostname = talloc_strdup(state, ipa_hostname);
    if (state->hostname == NULL) {
        return ENOMEM;
    }

    DEBUG(7, ("Checking if the update is needed\n"));

    ret = ipa_dyndns_gss_tsig_update_setup_check(state);
    if (ret != EOK) {
        return ret;
    }

    subreq = ipa_dyndns_update_get_addrs_send(state, state,
                                              state->family_order);
    if (subreq == NULL) {
        return ENOMEM;
    }
    tevent_req_set_callback(subreq,
                            ipa_dyndns_gss_tsig_update_check,
                            req);
    return EOK;
}

static errno_t
ipa_dyndns_gss_tsig_update_setup_check(struct ipa_dyndns_ctx *state)
{
    struct sdap_id_ctx *id_ctx = state->ipa_ctx->id_ctx->sdap_id_ctx;
    errno_t ret;

    if (dp_opt_get_string(state->ipa_ctx->basic, IPA_DYNDNS_IFACE)) {
        ret = resolv_get_family_order(id_ctx->be->cdb, id_ctx->be->conf_path,
                                      &state->family_order);
        if (ret != EOK) {
            return ret;
        }

        /* Unless one family is restricted, just replace all
        * address families during the update
        */
        switch (state->family_order) {
        case IPV4_ONLY:
            state->remove_af |= IPA_DYNDNS_REMOVE_A;
            break;
        case IPV6_ONLY:
            state->remove_af |= IPA_DYNDNS_REMOVE_AAAA;
            break;
        case IPV4_FIRST:
        case IPV6_FIRST:
            state->remove_af |= (IPA_DYNDNS_REMOVE_A |
                                IPA_DYNDNS_REMOVE_AAAA);
            break;
        }
    } else {
        /* If the interface isn't specified, we ONLY want to have the address
         * that's connected to the LDAP server stored, so we need to check
         * (and later remove) both address families.
         */
        state->family_order = IPV4_FIRST;
        state->remove_af = (IPA_DYNDNS_REMOVE_A |
                            IPA_DYNDNS_REMOVE_AAAA);
    }

    return EOK;
}

static void
ipa_dyndns_gss_tsig_update_check(struct tevent_req *subreq)
{
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct ipa_dyndns_ctx *state = tevent_req_data(req,
                                                   struct ipa_dyndns_ctx);

    errno_t ret;
    char **str_dnslist = NULL, **str_local_list = NULL;
    char **dns_only = NULL, **local_only = NULL;
    bool do_update = false;
    int i;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        ret = ENOMEM;
        goto fail;
    }

    ret = ipa_dyndns_update_get_addrs_recv(subreq, tmp_ctx, &str_dnslist);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(3, ("Getting the current list of addresses failed [%d]: %s\n",
                  ret, strerror(ret)));
        goto fail;
    }

    ret = ipa_ipaddress_list_as_string_list(tmp_ctx,
                                            state->addresses, &str_local_list);
    if (ret != EOK) {
        DEBUG(3, ("Converting DNS IP addresses to strings failed: [%d]: %s\n",
                  ret, strerror(ret)));
        goto fail;
    }

    /* Compare the lists */
    ret = diff_string_lists(tmp_ctx, str_dnslist, str_local_list,
                            &dns_only, &local_only, NULL);
    if (ret != EOK) {
        DEBUG(3, ("diff_string_lists failed: [%d]: %s\n", ret, strerror(ret)));
        goto fail;
    }

    if (dns_only) {
        for (i=0; dns_only[i]; i++) {
            DEBUG(7, ("Address in DNS only: %s\n", dns_only[i]));
            do_update = true;
        }
    }

    if (local_only) {
        for (i=0; local_only[i]; i++) {
            DEBUG(7, ("Address on localhost only: %s\n", local_only[i]));
            do_update = true;
        }
    }

    if (do_update) {
        DEBUG(6, ("Detected IP addresses change, will perform an update\n"));
        subreq = ipa_dyndns_gss_tsig_update_send(state);
        if(subreq == NULL) {
            ret = ENOMEM;
            goto fail;
        }
        tevent_req_set_callback(subreq,
                                ipa_dyndns_gss_tsig_update_done,
                                req);
        talloc_free(tmp_ctx);
        return;
    }

    DEBUG(6, ("No DNS update needed, addresses did not change\n"));
    tevent_req_done(req);
    talloc_free(tmp_ctx);
    return;

fail:
    talloc_free(tmp_ctx);
    tevent_req_error(req, ret);
}

struct ipa_dyndns_update_get_addrs_state {
    struct ipa_dyndns_ctx *dctx;

    enum host_database *db;
    enum restrict_family family_order;

    char **addrlist;
    size_t count;
};

static void ipa_dyndns_update_get_addrs_done(struct tevent_req *subreq);
static errno_t ipa_dyndns_update_get_addrs_step(struct tevent_req *req);

static struct tevent_req *
ipa_dyndns_update_get_addrs_send(TALLOC_CTX *mem_ctx,
                                 struct ipa_dyndns_ctx *ctx,
                                 enum restrict_family family_order)
{
    errno_t ret;
    struct tevent_req *req;
    struct ipa_dyndns_update_get_addrs_state *state;
    struct sdap_id_ctx *id_ctx = ctx->ipa_ctx->id_ctx->sdap_id_ctx;

    req = tevent_req_create(mem_ctx, &state,
                            struct ipa_dyndns_update_get_addrs_state);
    if (req == NULL) {
        return NULL;
    }
    state->dctx = ctx;
    state->family_order = family_order;

    state->db = talloc_array(state, enum host_database, 2);
    if (state->db == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    state->db[0] = DB_DNS;
    state->db[1] = DB_SENTINEL;

    ret = ipa_dyndns_update_get_addrs_step(req);
    if (ret != EOK) {
        goto immediate;
    }

immediate:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, id_ctx->be->ev);
    }
    return req;
}

static errno_t
ipa_dyndns_update_get_addrs_step(struct tevent_req *req)
{
    struct tevent_req *subreq;
    struct ipa_dyndns_update_get_addrs_state *state = tevent_req_data(req,
                                        struct ipa_dyndns_update_get_addrs_state);
    struct ipa_id_ctx *ipa_id_ctx = state->dctx->ipa_ctx->id_ctx;

    subreq = resolv_gethostbyname_send(state,
                                       ipa_id_ctx->sdap_id_ctx->be->ev,
                                       state->dctx->ipa_ctx->resolv,
                                       state->dctx->hostname,
                                       state->family_order,
                                       state->db);
    if (!subreq) {
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, ipa_dyndns_update_get_addrs_done, req);
    return EOK;
}

static void
ipa_dyndns_update_get_addrs_done(struct tevent_req *subreq)
{
    int ret;
    size_t count;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct ipa_dyndns_update_get_addrs_state *state = tevent_req_data(req,
                                     struct ipa_dyndns_update_get_addrs_state);
    struct resolv_hostent *rhostent;
    int i;
    int resolv_status;

    ret = resolv_gethostbyname_recv(subreq, state, &resolv_status, NULL,
                                    &rhostent);
    talloc_zfree(subreq);

    /* If the retry did not match, simply quit */
    if (ret == ENOENT) {
        /* If the resolver is set to honor both address families
         * retry the second one
         */
        if (state->family_order == IPV4_FIRST ||
            state->family_order == IPV6_FIRST) {

            state->family_order = (state->family_order == IPV4_FIRST) ? \
                                   IPV6_ONLY : IPV4_ONLY;

            ret = ipa_dyndns_update_get_addrs_step(req);
            if (ret != EOK) {
                tevent_req_error(req, ret);
            }
            return;
        }

        /* Nothing to retry, simply quit */
        tevent_req_done(req);
        return;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Could not resolve address for this machine, error [%d]: %s, "
               "resolver returned: [%d]: %s\n", ret, strerror(ret),
               resolv_status, resolv_strerror(resolv_status)));
        tevent_req_error(req, ret);
        return;
    }

    /* EOK */

    if (rhostent->addr_list) {
        for (count=0; rhostent->addr_list[count]; count++);
    } else {
        /* The address list is NULL. This is probably a bug in
         * c-ares, but we need to handle it gracefully.
         */
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Lookup of [%s] returned no addresses. Skipping.\n",
               rhostent->name));
        count = 0;
    }

    state->addrlist = talloc_realloc(state, state->addrlist, char *,
                                        state->count + count + 1);
    if (!state->addrlist) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    for (i=0; i < count; i++) {
        state->addrlist[state->count + i] = \
                        resolv_get_string_address_index(state->addrlist,
                                                        rhostent, i);

        if (state->addrlist[state->count + i] == NULL) {
            tevent_req_error(req, ENOMEM);
            return;
        }
    }
    state->count += count;
    state->addrlist[state->count] = NULL;

    /* If the resolver is set to honor both address families
     * and the first one matched, retry the second one to
     * get the complete list.
     */
    if (((state->family_order == IPV4_FIRST &&
            rhostent->family == AF_INET) ||
        (state->family_order == IPV6_FIRST &&
            rhostent->family == AF_INET6))) {

        state->family_order = (state->family_order == IPV4_FIRST) ? \
                                IPV6_ONLY : IPV4_ONLY;

        ret = ipa_dyndns_update_get_addrs_step(req);
        if (ret != EOK) {
            tevent_req_error(req, ret);
        }
        return;
    }

    /* The second address matched either immediatelly or after a retry.
     * No need to retry again. */
    tevent_req_done(req);
    return;
}

static errno_t
ipa_dyndns_update_get_addrs_recv(struct tevent_req *req,
                                 TALLOC_CTX *mem_ctx,
                                 char ***_addrlist)
{
    struct ipa_dyndns_update_get_addrs_state *state = tevent_req_data(req,
                                    struct ipa_dyndns_update_get_addrs_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_addrlist = talloc_steal(mem_ctx, state->addrlist);
    return EOK;
}

struct ipa_nsupdate_ctx {
    char *update_msg;
    struct ipa_dyndns_ctx *dyndns_ctx;
    int pipefd_to_child;
    struct tevent_timer *timeout_handler;
    int child_status;
};


static int create_nsupdate_message(struct ipa_nsupdate_ctx *ctx,
                                   uint8_t remove_af,
                                   bool use_server_with_nsupdate);

static struct tevent_req *
fork_nsupdate_send(struct ipa_nsupdate_ctx *ctx);

static void fork_nsupdate_done(struct tevent_req *subreq);

static struct tevent_req *
ipa_dyndns_gss_tsig_update_send(struct ipa_dyndns_ctx *ctx)
{
    int ret;
    struct ipa_nsupdate_ctx *state;
    struct tevent_req *req;
    struct tevent_req *subreq;

    req = tevent_req_create(ctx, &state, struct ipa_nsupdate_ctx);
    if(req == NULL) {
        return NULL;
    }
    state->dyndns_ctx = ctx;
    state->child_status = 0;

    /* Format the message to pass to the nsupdate command */
    ret = create_nsupdate_message(state, ctx->remove_af,
                                  ctx->use_server_with_nsupdate);
    if (ret != EOK) {
        goto failed;
    }

    /* Fork a child process to perform the DNS update */
    subreq = fork_nsupdate_send(state);
    if(subreq == NULL) {
        goto failed;
    }
    tevent_req_set_callback(subreq, fork_nsupdate_done, req);

    return req;

failed:
    talloc_free(req);
    return NULL;
}

struct nsupdate_send_ctx {
    struct ipa_nsupdate_ctx *nsupdate_ctx;
    int child_status;
};

static int create_nsupdate_message(struct ipa_nsupdate_ctx *ctx,
                                   uint8_t remove_af,
                                   bool use_server_with_nsupdate)
{
    int ret, i;
    char *servername = NULL;
    char *realm;
    char *realm_directive;
    char *zone;
    char ip_addr[INET6_ADDRSTRLEN];
    const char *ip;
    struct ipa_ipaddress *new_record;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    realm = dp_opt_get_string(ctx->dyndns_ctx->ipa_ctx->basic, IPA_KRB5_REALM);
    if (!realm) {
        ret = EIO;
        goto done;
    }

#ifdef HAVE_NSUPDATE_REALM
    realm_directive = talloc_asprintf(tmp_ctx, "realm %s\n", realm);
#else
    realm_directive = talloc_asprintf(tmp_ctx, "");
#endif
    if (!realm_directive) {
        ret = ENOMEM;
        goto done;
    }

    zone = dp_opt_get_string(ctx->dyndns_ctx->ipa_ctx->basic,
                             IPA_DOMAIN);
    if (!zone) {
        ret = EIO;
        goto done;
    }

    /* The DNS zone for IPA is the lower-case
     * version of the IPA domain
     */
    for(i = 0; zone[i] != '\0'; i++) {
        zone[i] = tolower(zone[i]);
    }

    if (use_server_with_nsupdate) {
        if (strncmp(ctx->dyndns_ctx->ipa_ctx->service->sdap->uri,
                    "ldap://", 7) != 0) {
            DEBUG(1, ("Unexpected format of LDAP URI.\n"));
            ret = EIO;
            goto done;
        }
        servername = ctx->dyndns_ctx->ipa_ctx->service->sdap->uri + 7;
        if (!servername) {
            ret = EIO;
            goto done;
        }

        DEBUG(SSSDBG_FUNC_DATA,
              ("Creating update message for server [%s], realm [%s] "
               "and zone [%s].\n", servername, realm, zone));

        /* Add the server, realm and zone headers */
        ctx->update_msg = talloc_asprintf(ctx, "server %s\n%szone %s.\n",
                                               servername, realm_directive,
                                               zone);
    } else {
        DEBUG(SSSDBG_FUNC_DATA,
              ("Creating update message for realm [%s] and zone [%s].\n",
               realm, zone));

        /* Add the realm and zone headers */
        ctx->update_msg = talloc_asprintf(ctx, "%szone %s.\n",
                                               realm_directive, zone);
    }
    if (ctx->update_msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Remove existing entries as needed */
    if (remove_af & IPA_DYNDNS_REMOVE_A) {
        ctx->update_msg = talloc_asprintf_append(ctx->update_msg,
                                            "update delete %s. in A\nsend\n",
                                            ctx->dyndns_ctx->hostname);
        if (ctx->update_msg == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }
    if (remove_af & IPA_DYNDNS_REMOVE_AAAA) {
        ctx->update_msg = talloc_asprintf_append(ctx->update_msg,
                                         "update delete %s. in AAAA\nsend\n",
                                          ctx->dyndns_ctx->hostname);
        if (ctx->update_msg == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    DLIST_FOR_EACH(new_record, ctx->dyndns_ctx->addresses) {
        switch(new_record->addr->ss_family) {
        case AF_INET:
            ip = inet_ntop(new_record->addr->ss_family,
                           &(((struct sockaddr_in *)new_record->addr)->sin_addr),
                           ip_addr, INET6_ADDRSTRLEN);
            if (ip == NULL) {
                ret = EIO;
                goto done;
            }
            break;

        case AF_INET6:
            ip = inet_ntop(new_record->addr->ss_family,
                           &(((struct sockaddr_in6 *)new_record->addr)->sin6_addr),
                           ip_addr, INET6_ADDRSTRLEN);
            if (ip == NULL) {
                ret = EIO;
                goto done;
            }
            break;

        default:
            DEBUG(0, ("Unknown address family\n"));
            ret = EIO;
            goto done;
        }

        /* Format the record update */
        ctx->update_msg = talloc_asprintf_append(
                ctx->update_msg,
                "update add %s. 86400 in %s %s\n",
                ctx->dyndns_ctx->hostname,
                new_record->addr->ss_family == AF_INET ? "A" : "AAAA",
                ip_addr);
        if (ctx->update_msg == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    ctx->update_msg = talloc_asprintf_append(ctx->update_msg, "send\n");
    if (ctx->update_msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          (" -- Begin nsupdate message -- \n%s",
           ctx->update_msg));
    DEBUG(SSSDBG_TRACE_FUNC,
          (" -- End nsupdate message -- \n"));

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static void ipa_dyndns_stdin_done(struct tevent_req *subreq);

static void ipa_dyndns_child_handler(int child_status,
                                     struct tevent_signal *sige,
                                     void *pvt);

static void ipa_dyndns_timeout(struct tevent_context *ev,
                               struct tevent_timer *te,
                               struct timeval tv, void *pvt);

static struct tevent_req *
fork_nsupdate_send(struct ipa_nsupdate_ctx *ctx)
{
    int pipefd_to_child[2];
    pid_t pid;
    int ret;
    errno_t err;
    struct timeval tv;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct nsupdate_send_ctx *state;
    char *args[3];

    req = tevent_req_create(ctx, &state, struct nsupdate_send_ctx);
    if (req == NULL) {
        return NULL;
    }
    state->nsupdate_ctx = ctx;
    state->child_status = 0;

    ret = pipe(pipefd_to_child);
    if (ret == -1) {
        err = errno;
        DEBUG(1, ("pipe failed [%d][%s].\n", err, strerror(err)));
        return NULL;
    }

    pid = fork();

    if (pid == 0) { /* child */
        args[0] = talloc_strdup(ctx, NSUPDATE_PATH);
        args[1] = talloc_strdup(ctx, "-g");
        args[2] = NULL;
        if (args[0] == NULL || args[1] == NULL) {
            return NULL;
        }

        close(pipefd_to_child[1]);
        ret = dup2(pipefd_to_child[0], STDIN_FILENO);
        if (ret == -1) {
            err = errno;
            DEBUG(1, ("dup2 failed [%d][%s].\n", err, strerror(err)));
            return NULL;
        }

        errno = 0;
        execv(NSUPDATE_PATH, args);
        err = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, ("execv failed [%d][%s].\n", err, strerror(err)));
        return NULL;
    }

    else if (pid > 0) { /* parent */
        close(pipefd_to_child[0]);

        ctx->pipefd_to_child = pipefd_to_child[1];

        /* Write the update message to the nsupdate child */
        subreq = write_pipe_send(req,
                                 ctx->dyndns_ctx->ipa_ctx->id_ctx->sdap_id_ctx->be->ev,
                                 (uint8_t *)ctx->update_msg,
                                 strlen(ctx->update_msg)+1,
                                 ctx->pipefd_to_child);
        if (subreq == NULL) {
            return NULL;
        }
        tevent_req_set_callback(subreq, ipa_dyndns_stdin_done, req);

        /* Set up SIGCHLD handler */
        ret = child_handler_setup(ctx->dyndns_ctx->ipa_ctx->id_ctx->sdap_id_ctx->be->ev,
                                  pid, ipa_dyndns_child_handler, req);
        if (ret != EOK) {
            return NULL;
        }

        /* Set up timeout handler */
        tv = tevent_timeval_current_ofs(IPA_DYNDNS_TIMEOUT, 0);
        ctx->timeout_handler = tevent_add_timer(
                ctx->dyndns_ctx->ipa_ctx->id_ctx->sdap_id_ctx->be->ev,
                req, tv, ipa_dyndns_timeout, req);
        if(ctx->timeout_handler == NULL) {
            return NULL;
        }
    }

    else { /* error */
        err = errno;
        DEBUG(1, ("fork failed [%d][%s].\n", err, strerror(err)));
        return NULL;
    }

    return req;
}

static void ipa_dyndns_timeout(struct tevent_context *ev,
                               struct tevent_timer *te,
                               struct timeval tv, void *pvt)
{
    struct tevent_req *req =
            talloc_get_type(pvt, struct tevent_req);

    DEBUG(1, ("Timeout reached for dynamic DNS update\n"));

    tevent_req_error(req, ETIMEDOUT);
}

static void ipa_dyndns_stdin_done(struct tevent_req *subreq)
{
    /* Verify that the buffer was sent, then return
     * and wait for the sigchld handler to finish.
     */
    DEBUG(9, ("Sending nsupdate data complete\n"));

    int ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct nsupdate_send_ctx *state =
            tevent_req_data(req, struct nsupdate_send_ctx);

    ret = write_pipe_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(1, ("Sending nsupdate data failed\n"));
        tevent_req_error(req, ret);
        return;
    }

    close(state->nsupdate_ctx->pipefd_to_child);
    state->nsupdate_ctx->pipefd_to_child = -1;
}

static void ipa_dyndns_child_handler(int child_status,
                                     struct tevent_signal *sige,
                                     void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct nsupdate_send_ctx *state =
            tevent_req_data(req, struct nsupdate_send_ctx);

    state->child_status = child_status;

    if (WIFEXITED(child_status) && WEXITSTATUS(child_status) != 0) {
        DEBUG(1, ("Dynamic DNS child failed with status [%d]\n",
                  child_status));
        tevent_req_error(req, EIO);
        return;
    }

    if WIFSIGNALED(child_status) {
        DEBUG(1, ("Dynamic DNS child was terminated by signal [%d]\n",
                  WTERMSIG(child_status)));
        tevent_req_error(req, EIO);
        return;
    }

    tevent_req_done(req);
}

static int ipa_dyndns_child_recv(struct tevent_req *req, int *child_status)
{
    struct nsupdate_send_ctx *state =
            tevent_req_data(req, struct nsupdate_send_ctx);

    *child_status = state->child_status;

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

static int ipa_dyndns_generic_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

static void fork_nsupdate_done(struct tevent_req *subreq)
{
    int ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct ipa_nsupdate_ctx *state = tevent_req_data(req,
                                                     struct ipa_nsupdate_ctx);

    ret = ipa_dyndns_child_recv(subreq, &state->child_status);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static int fork_nsupdate_recv(struct tevent_req *req, int *child_status)
{
    struct ipa_nsupdate_ctx *state =
            tevent_req_data(req, struct ipa_nsupdate_ctx);

    *child_status = state->child_status;

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

static void ipa_dyndns_gss_tsig_update_done(struct tevent_req *subreq)
{
    /* Check the return code from the sigchld handler
     * and return it to the parent request.
     */
    int ret;
    int child_status;

    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct ipa_dyndns_ctx *state = tevent_req_data(req, struct ipa_dyndns_ctx);

    ret = fork_nsupdate_recv(subreq, &child_status);
    talloc_zfree(subreq);
    if (ret != EOK) {
        if (state->use_server_with_nsupdate == false &&
            WIFEXITED(child_status) && WEXITSTATUS(child_status) != 0) {
            DEBUG(9, ("nsupdate failed, retrying with server name.\n"));
            state->use_server_with_nsupdate = true;
            ret = ipa_dyndns_gss_tsig_update_step(req);
            if (ret != EOK) {
                tevent_req_error(req, ret);
            }
            return;
        } else {
            tevent_req_error(req, ret);
            return;
        }
    }

    tevent_req_done(req);
}

static void ipa_dyndns_update_done(struct tevent_req *req)
{
    int ret = ipa_dyndns_generic_recv(req);
    talloc_free(req);
    if (ret != EOK) {
        DEBUG(1, ("Updating DNS entry failed\n"));
        return;
    }

    DEBUG(1, ("DNS update finished\n"));
}
