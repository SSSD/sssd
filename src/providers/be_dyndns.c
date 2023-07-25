/*
    SSSD

    dp_dyndns.c

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <ctype.h>
#include "util/util.h"
#include "confdb/confdb.h"
#include "util/child_common.h"
#include "providers/data_provider.h"
#include "providers/backend.h"
#include "providers/be_dyndns.h"
#include "resolv/async_resolv.h"

#ifndef DYNDNS_TIMEOUT
#define DYNDNS_TIMEOUT 15
#endif /* DYNDNS_TIMEOUT */

/* MASK represents special value for matching all interfaces */
#define MASK "*"

struct sss_iface_addr {
    struct sss_iface_addr *next;
    struct sss_iface_addr *prev;

    struct sockaddr *addr;
};

struct sockaddr *
sss_iface_addr_get_address(struct sss_iface_addr *address)
{
    if (address == NULL) {
        return NULL;
    }

    return address->addr;
}

struct sss_iface_addr *sss_iface_addr_get_next(struct sss_iface_addr *address)
{
    if (address) {
        return address->next;
    }

    return NULL;
}

void sss_iface_addr_concatenate(struct sss_iface_addr **list,
                                struct sss_iface_addr *list2)
{
    DLIST_CONCATENATE((*list), list2, struct sss_iface_addr*);
}

static errno_t addr_to_str(struct sockaddr *addr,
                           char *dst, size_t size)
{
    const void *src;
    const char *res;
    errno_t ret;

    switch(addr->sa_family) {
    case AF_INET:
        src = &(((struct sockaddr_in *)addr)->sin_addr);
        break;
    case AF_INET6:
        src = &(((struct sockaddr_in6 *)addr)->sin6_addr);
        break;
    default:
        ret = ERR_ADDR_FAMILY_NOT_SUPPORTED;
        goto done;
    }

    res = inet_ntop(addr->sa_family, src, dst, size);
    if (res == NULL) {
        ret = errno;
        DEBUG(SSSDBG_OP_FAILURE, "inet_ntop failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = EOK;

done:
    return ret;
}

errno_t
sss_iface_addr_list_as_str_list(TALLOC_CTX *mem_ctx,
                                struct sss_iface_addr *ifaddr_list,
                                char ***_straddrs)
{
    struct sss_iface_addr *ifaddr;
    size_t count;
    int ai;
    char **straddrs;
    char ip_addr[INET6_ADDRSTRLEN];
    errno_t ret;

    count = 0;
    DLIST_FOR_EACH(ifaddr, ifaddr_list) {
        count++;
    }

    straddrs = talloc_array(mem_ctx, char *, count+1);
    if (straddrs == NULL) {
        return ENOMEM;
    }

    ai = 0;
    DLIST_FOR_EACH(ifaddr, ifaddr_list) {

        ret = addr_to_str(ifaddr->addr, ip_addr, INET6_ADDRSTRLEN);
        if (ret == ERR_ADDR_FAMILY_NOT_SUPPORTED) {
            continue;
        } else if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "addr_to_str failed: %d:[%s],\n",
                  ret, sss_strerror(ret));
            goto fail;
        }

        straddrs[ai] = talloc_strdup(straddrs, ip_addr);
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

static bool
ok_for_dns(struct sockaddr *sa)
{
    struct sockaddr_in sa4;
    struct sockaddr_in6 sa6;

    switch (sa->sa_family) {
    case AF_INET6:
        memcpy(&sa6, sa, sizeof(struct sockaddr_in6));
        return check_ipv6_addr(&sa6.sin6_addr, SSS_NO_SPECIAL);
    case AF_INET:
        memcpy(&sa4, sa, sizeof(struct sockaddr_in));
        return check_ipv4_addr(&sa4.sin_addr, SSS_NO_SPECIAL);
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Unknown address family\n");
        return false;
    }

    return true;
}

static bool supported_address_family(sa_family_t sa_family)
{
    return sa_family == AF_INET || sa_family == AF_INET6;
}

static bool matching_name(const char *ifname, const char *ifname2)
{
    return (strcmp(MASK, ifname) == 0) || (strcasecmp(ifname, ifname2) == 0);
}

/* Collect IP addresses associated with an interface */
errno_t
sss_iface_addr_list_get(TALLOC_CTX *mem_ctx, const char *ifname,
                        struct sss_iface_addr **_addrlist)
{
    struct ifaddrs *ifaces = NULL;
    struct ifaddrs *ifa;
    errno_t ret;
    size_t addrsize;
    struct sss_iface_addr *address;
    struct sss_iface_addr *addrlist = NULL;

    /* Get the IP addresses associated with the
     * specified interface
     */
    errno = 0;
    ret = getifaddrs(&ifaces);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not read interfaces [%d][%s]\n", ret, strerror(ret));
        goto done;
    }

    for (ifa = ifaces; ifa != NULL; ifa = ifa->ifa_next) {
        /* Some interfaces don't have an ifa_addr */
        if (!ifa->ifa_addr) continue;

        /* Add IP addresses to the list */
        if (supported_address_family(ifa->ifa_addr->sa_family)
                && matching_name(ifname, ifa->ifa_name)
                && ok_for_dns(ifa->ifa_addr)) {

            /* Add this address to the IP address list */
            address = talloc_zero(mem_ctx, struct sss_iface_addr);
            if (!address) {
                ret = ENOMEM;
                goto done;
            }

            addrsize = ifa->ifa_addr->sa_family == AF_INET ? \
                                sizeof(struct sockaddr_in) : \
                                sizeof(struct sockaddr_in6);

            address->addr = talloc_memdup(address, ifa->ifa_addr,
                                          addrsize);
            if (address->addr == NULL) {
                ret = ENOMEM;
                goto done;
            }

            /* steal old dlist to the new head */
            talloc_steal(address, addrlist);
            DLIST_ADD(addrlist, address);
        }
    }

    if (addrlist != NULL) {
        /* OK, some result was found */
        ret = EOK;
        *_addrlist = addrlist;
    } else {
        /* No result was found */
        DEBUG(SSSDBG_TRACE_FUNC,
              "No IP usable for DNS was found for interface: %s.\n", ifname);
        ret = ENOENT;
    }

done:
    freeifaddrs(ifaces);
    return ret;
}

static char *
nsupdate_msg_add_fwd(char *update_msg, struct sss_iface_addr *addresses,
                     const char *hostname, int ttl, uint8_t remove_af, bool update_per_family)
{
    struct sss_iface_addr *new_record;
    char ip_addr[INET6_ADDRSTRLEN];
    char *updateipv4 = talloc_strdup(update_msg, "");
    char *updateipv6 = talloc_strdup(update_msg, "");
    errno_t ret;

    /* Remove existing entries as needed */
    if (remove_af & DYNDNS_REMOVE_A) {
        updateipv4 = talloc_asprintf_append(updateipv4,
                                            "update delete %s. in A\n",
                                            hostname);
        if (updateipv4 == NULL) {
            return NULL;
        }
    }

    if (remove_af & DYNDNS_REMOVE_AAAA) {
        updateipv6 = talloc_asprintf_append(updateipv6,
                                            "update delete %s. in AAAA\n",
                                            hostname);
        if (updateipv6 == NULL) {
            return NULL;
        }
    }

    DLIST_FOR_EACH(new_record, addresses) {
        ret = addr_to_str(new_record->addr, ip_addr, INET6_ADDRSTRLEN);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "addr_to_str failed: %d:[%s],\n",
                  ret, sss_strerror(ret));
            return NULL;
        }

        switch (new_record->addr->sa_family) {
        case AF_INET:
            updateipv4 = talloc_asprintf_append(updateipv4,
                                                "update add %s. %d in %s %s\n",
                                                hostname, ttl, "A", ip_addr);
            if (updateipv4 == NULL) {
                return NULL;
            }

            break;
        case AF_INET6:
            updateipv6 = talloc_asprintf_append(updateipv6,
                                                "update add %s. %d in %s %s\n",
                                                hostname, ttl, "AAAA", ip_addr);
            if (updateipv6 == NULL) {
                return NULL;
            }

            break;
        }
    }

    if (update_per_family && updateipv4[0] && updateipv6[0]) {
        /* update per family and both families present */
        return talloc_asprintf_append(update_msg,
                                            "%s"
                                            "send\n"
                                            "%s"
                                            "send\n",
                                            updateipv4,
                                            updateipv6);
    }

    return talloc_asprintf_append(update_msg,
                                  "%s"
                                  "%s"
                                  "send\n",
                                  updateipv4,
                                  updateipv6);
}

static uint8_t *nsupdate_convert_address(struct sockaddr *add_address)
{
    uint8_t *addr;

    switch(add_address->sa_family) {
    case AF_INET:
        addr = (uint8_t *) &((struct sockaddr_in *) add_address)->sin_addr;
        break;
    case AF_INET6:
        addr = (uint8_t *) &((struct sockaddr_in6 *) add_address)->sin6_addr;
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Unknown address family\n");
        addr = NULL;
        break;
    }

    return addr;
}

static char *
nsupdate_msg_add_ptr(char *update_msg, struct sss_iface_addr *addresses,
                     const char *hostname, int ttl, uint8_t remove_af,
                     bool update_per_family)
{
    char *updateipv4 = talloc_strdup(update_msg, "");
    char *updateipv6 = talloc_strdup(update_msg, "");
    char *ptr;
    struct sss_iface_addr *address_it;
    uint8_t *addr;

    if (!updateipv4 || !updateipv6) {
        return NULL;
    }

    DLIST_FOR_EACH(address_it, addresses) {
        addr = nsupdate_convert_address(address_it->addr);
        if (addr == NULL) {
            return NULL;
        }

        ptr = resolv_get_string_ptr_address(update_msg, address_it->addr->sa_family,
                                            addr);
        if (ptr == NULL) {
            return NULL;
        }

        switch (address_it->addr->sa_family) {
        case AF_INET:
            if (remove_af & DYNDNS_REMOVE_A) {
                updateipv4 = talloc_asprintf_append(updateipv4,
                                                    "update delete %s in PTR\n",
                                                    ptr);
                if (updateipv4 == NULL) {
                    return NULL;
                }
            }

            updateipv4 = talloc_asprintf_append(updateipv4,
                                                "update add %s %d in PTR %s.\n",
                                                ptr, ttl, hostname);
            break;
        case AF_INET6:
            if (remove_af & DYNDNS_REMOVE_AAAA) {
                updateipv6 = talloc_asprintf_append(updateipv6,
                                                    "update delete %s in PTR\n",
                                                    ptr);
                if (updateipv6 == NULL) {
                    return NULL;
                }
            }
            updateipv6 = talloc_asprintf_append(updateipv6,
                                                "update add %s %d in PTR %s.\n",
                                                ptr, ttl, hostname);
            break;
        }

        talloc_free(ptr);
        if (!updateipv4 || !updateipv6) {
            return NULL;
        }
    }

    if (update_per_family && updateipv4[0] && updateipv6[0]) {
        /* update per family and both families present */
        return talloc_asprintf_append(update_msg,
                                      "%s"
                                      "send\n"
                                      "%s"
                                      "send\n",
                                      updateipv4,
                                      updateipv6);
    }

    return talloc_asprintf_append(update_msg,
                                  "%s"
                                  "%s"
                                  "send\n",
                                  updateipv4,
                                  updateipv6);
}

static char *
nsupdate_msg_add_realm_cmd(TALLOC_CTX *mem_ctx, const char *realm)
{
    if (realm != NULL) {
        return talloc_asprintf(mem_ctx, "realm %s\n", realm);
    } else {
        return talloc_asprintf(mem_ctx, "\n");
    }
}

static char *
nsupdate_msg_create_common(TALLOC_CTX *mem_ctx, const char *realm,
                           const char *servername)
{
    char *realm_directive;
    char *update_msg;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) return NULL;

    realm_directive = nsupdate_msg_add_realm_cmd(tmp_ctx, realm);
    if (!realm_directive) {
        goto fail;
    }

    /* The realm_directive would now either contain an empty string or be
     * completely empty so we don't need to add another newline here
     */
    if (servername) {
        DEBUG(SSSDBG_FUNC_DATA,
              "Creating update message for server [%s] and realm [%s].\n",
               servername, realm);

        /* Add the server, realm and headers */
        update_msg = talloc_asprintf(tmp_ctx, "server %s\n%s",
                                     servername, realm_directive);
    } else if (realm != NULL) {
        DEBUG(SSSDBG_FUNC_DATA,
              "Creating update message for realm [%s].\n", realm);
        /* Add the realm headers */
        update_msg = talloc_asprintf(tmp_ctx, "%s", realm_directive);
    } else {
        DEBUG(SSSDBG_FUNC_DATA,
              "Creating update message for auto-discovered realm.\n");
        update_msg = talloc_asprintf(tmp_ctx, "%s", realm_directive);
    }
    talloc_free(realm_directive);
    if (update_msg == NULL) {
        goto fail;
    }

    update_msg = talloc_steal(mem_ctx, update_msg);
    talloc_free(tmp_ctx);
    return update_msg;

fail:
    talloc_free(tmp_ctx);
    return NULL;
}

errno_t
be_nsupdate_create_fwd_msg(TALLOC_CTX *mem_ctx, const char *realm,
                           const char *servername,
                           const char *hostname, const unsigned int ttl,
                           uint8_t remove_af, struct sss_iface_addr *addresses,
                           bool update_per_family,
                           char **_update_msg)
{
    int ret;
    char *update_msg;
    TALLOC_CTX *tmp_ctx;

    /* in some cases realm could have been NULL if we weren't using TSIG */
    if (hostname == NULL) {
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) return ENOMEM;

    update_msg = nsupdate_msg_create_common(tmp_ctx, realm, servername);
    if (update_msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    update_msg = nsupdate_msg_add_fwd(update_msg, addresses, hostname,
                                      ttl, remove_af, update_per_family);
    if (update_msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          " -- Begin nsupdate message -- \n"
          "%s"
          " -- End nsupdate message -- \n",
          update_msg);

    ret = ERR_OK;
    *_update_msg = talloc_steal(mem_ctx, update_msg);
done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
be_nsupdate_create_ptr_msg(TALLOC_CTX *mem_ctx, const char *realm,
                           const char *servername,
                           const char *hostname, const unsigned int ttl,
                           uint8_t remove_af, struct sss_iface_addr *addresses,
                           bool update_per_family,
                           char **_update_msg)
{
    errno_t ret;
    char *update_msg;
    TALLOC_CTX *tmp_ctx;

    /* in some cases realm could have been NULL if we weren't using TSIG */
    if (hostname == NULL) {
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) return ENOMEM;

    update_msg = nsupdate_msg_create_common(tmp_ctx, realm, servername);
    if (update_msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    update_msg = nsupdate_msg_add_ptr(update_msg, addresses, hostname,
                                      ttl, remove_af, update_per_family);
    if (update_msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          " -- Begin nsupdate message -- \n"
          "%s"
          " -- End nsupdate message -- \n",
          update_msg);

    ret = ERR_OK;
    *_update_msg = talloc_steal(mem_ctx, update_msg);

done:
    talloc_free(tmp_ctx);
    return ret;
}

struct nsupdate_get_addrs_state {
    struct tevent_context *ev;
    struct be_resolv_ctx *be_res;
    enum host_database *db;
    const char *hostname;

    /* Use sss_addr in this request */
    struct sss_iface_addr *addrlist;
    size_t count;
};

static void nsupdate_get_addrs_done(struct tevent_req *subreq);

struct tevent_req *
nsupdate_get_addrs_send(TALLOC_CTX *mem_ctx,
                        struct tevent_context *ev,
                        struct be_resolv_ctx *be_res,
                        const char *hostname)
{
    errno_t ret;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct nsupdate_get_addrs_state *state;

    req = tevent_req_create(mem_ctx, &state, struct nsupdate_get_addrs_state);
    if (req == NULL) {
        return NULL;
    }
    state->be_res = be_res;
    state->ev = ev;
    state->hostname = talloc_strdup(state, hostname);
    if (state->hostname == NULL) {
        ret = ENOMEM;
        goto done;
    }

    state->db = talloc_array(state, enum host_database, 2);
    if (state->db == NULL) {
        ret = ENOMEM;
        goto done;
    }
    state->db[0] = DB_DNS;
    state->db[1] = DB_SENTINEL;

    subreq = resolv_gethostbyname_send(state, ev, be_res->resolv, hostname,
                                       state->be_res->family_order,
                                       state->db);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }
    tevent_req_set_callback(subreq, nsupdate_get_addrs_done, req);

    ret = ERR_OK;
done:
    if (ret != ERR_OK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }
    return req;
}

static void
nsupdate_get_addrs_done(struct tevent_req *subreq)
{
    errno_t ret;
    size_t count;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct nsupdate_get_addrs_state *state = tevent_req_data(req,
                                     struct nsupdate_get_addrs_state);
    struct resolv_hostent *rhostent;
    struct sss_iface_addr *addr;
    int i;
    int resolv_status;
    enum restrict_family retry_family_order;

    ret = resolv_gethostbyname_recv(subreq, state, &resolv_status, NULL,
                                    &rhostent);
    talloc_zfree(subreq);

    /* If the retry did not match, simply quit */
    if (ret == ENOENT) {
        /* If the resolver is set to honor both address families
         * it automatically retries the other one internally, so ENOENT
         * means neither matched and we can simply quit.
         */
        ret = EOK;
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not resolve address for this machine, error [%d]: %s, "
               "resolver returned: [%d]: %s\n", ret, sss_strerror(ret),
               resolv_status, resolv_strerror(resolv_status));
        goto done;
    }

    /* EOK */

    if (rhostent->addr_list) {
        for (count=0; rhostent->addr_list[count]; count++);
    } else {
        /* The address list is NULL. This is probably a bug in
         * c-ares, but we need to handle it gracefully.
         */
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Lookup of [%s] returned no addresses. Skipping.\n",
               rhostent->name);
        count = 0;
    }

    for (i=0; i < count; i++) {
        addr = talloc(state, struct sss_iface_addr);
        if (addr == NULL) {
            ret = ENOMEM;
            goto done;
        }

        addr->addr = resolv_get_sockaddr_address_index(addr, rhostent, 0, i, NULL);
        if (addr->addr == NULL) {
            ret = ENOMEM;
            goto done;
        }

        if (state->addrlist) {
            talloc_steal(state->addrlist, addr);
        }

        /* steal old dlist to the new head */
        talloc_steal(addr, state->addrlist);
        DLIST_ADD(state->addrlist, addr);
    }
    state->count += count;

    /* If the resolver is set to honor both address families
     * and the first one matched, retry the second one to
     * get the complete list.
     */
    if (((state->be_res->family_order == IPV4_FIRST &&
          rhostent->family == AF_INET) ||
        (state->be_res->family_order == IPV6_FIRST &&
         rhostent->family == AF_INET6))) {

        retry_family_order = (state->be_res->family_order == IPV4_FIRST) ? \
                             IPV6_ONLY : \
                             IPV4_ONLY;

        subreq = resolv_gethostbyname_send(state, state->ev,
                                           state->be_res->resolv,
                                           state->hostname,
                                           retry_family_order,
                                           state->db);
        if (!subreq) {
            ret = ENOMEM;
            goto done;
        }
        tevent_req_set_callback(subreq, nsupdate_get_addrs_done, req);
        return;
    }

    /* The second address matched either immediately or after a retry.
     * No need to retry again. */
    ret = EOK;

done:
    if (ret == EOK) {
        /* All done */
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        DEBUG(SSSDBG_OP_FAILURE,
              "nsupdate_get_addrs_done failed: [%d]: [%s]\n",
               ret, sss_strerror(ret));
        tevent_req_error(req, ret);
    }
    /* EAGAIN - another lookup in progress */
}

errno_t
nsupdate_get_addrs_recv(struct tevent_req *req,
                        TALLOC_CTX *mem_ctx,
                        struct sss_iface_addr **_addrlist,
                        size_t *_count)
{
    struct nsupdate_get_addrs_state *state = tevent_req_data(req,
                                    struct nsupdate_get_addrs_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (_addrlist) {
        *_addrlist = talloc_steal(mem_ctx, state->addrlist);
    }

    if (_count) {
        *_count = state->count;
    }

    return EOK;
}

/* Write the nsupdate_msg into the already forked child, wait until
 * the child finishes
 *
 * This is not a typical tevent_req styled request as it ends either after
 * a timeout or when the child finishes operation.
 */
struct nsupdate_child_state {
    int pipefd_to_child;
    struct tevent_timer *timeout_handler;
    struct sss_child_ctx_old *child_ctx;

    int child_status;
};

static void
nsupdate_child_timeout(struct tevent_context *ev,
                       struct tevent_timer *te,
                       struct timeval tv, void *pvt);
static void
nsupdate_child_handler(int child_status,
                       struct tevent_signal *sige,
                       void *pvt);

static void nsupdate_child_stdin_done(struct tevent_req *subreq);

static struct tevent_req *
nsupdate_child_send(TALLOC_CTX *mem_ctx,
                    struct tevent_context *ev,
                    int pipefd_to_child,
                    pid_t child_pid,
                    char *child_stdin)
{
    errno_t ret;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct nsupdate_child_state *state;
    struct timeval tv;

    req = tevent_req_create(mem_ctx, &state, struct nsupdate_child_state);
    if (req == NULL) {
        close(pipefd_to_child);
        return NULL;
    }
    state->pipefd_to_child = pipefd_to_child;

    /* Set up SIGCHLD handler */
    ret = child_handler_setup(ev, child_pid, nsupdate_child_handler, req,
                              &state->child_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not set up child handlers [%d]: %s\n",
              ret, sss_strerror(ret));
        ret = ERR_DYNDNS_FAILED;
        goto done;
    }

    /* Set up timeout handler */
    tv = tevent_timeval_current_ofs(DYNDNS_TIMEOUT, 0);
    state->timeout_handler = tevent_add_timer(ev, req, tv,
                                              nsupdate_child_timeout, req);
    if(state->timeout_handler == NULL) {
        ret = ERR_DYNDNS_FAILED;
        goto done;
    }

    /* Write the update message to the nsupdate child */
    subreq = write_pipe_send(req, ev,
                             (uint8_t *) child_stdin,
                             strlen(child_stdin)+1,
                             state->pipefd_to_child);
    if (subreq == NULL) {
        ret = ERR_DYNDNS_FAILED;
        goto done;
    }
    tevent_req_set_callback(subreq, nsupdate_child_stdin_done, req);

    ret = EOK;
done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }
    return req;
}

static void
nsupdate_child_timeout(struct tevent_context *ev,
                       struct tevent_timer *te,
                       struct timeval tv, void *pvt)
{
    struct tevent_req *req =
            talloc_get_type(pvt, struct tevent_req);
    struct nsupdate_child_state *state =
            tevent_req_data(req, struct nsupdate_child_state);

    DEBUG(SSSDBG_CRIT_FAILURE, "Timeout reached for dynamic DNS update\n");
    child_handler_destroy(state->child_ctx);
    state->child_ctx = NULL;
    state->child_status = ETIMEDOUT;
    tevent_req_error(req, ERR_DYNDNS_TIMEOUT);
}

static void
nsupdate_child_stdin_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct nsupdate_child_state *state =
            tevent_req_data(req, struct nsupdate_child_state);

    /* Verify that the buffer was sent, then return
     * and wait for the sigchld handler to finish.
     */
    DEBUG(SSSDBG_TRACE_LIBS, "Sending nsupdate data complete\n");

    ret = write_pipe_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Sending nsupdate data failed [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ERR_DYNDNS_FAILED);
        return;
    }

    PIPE_FD_CLOSE(state->pipefd_to_child);

    /* Now either wait for the timeout to fire or the child
     * to finish
     */
}

static void
nsupdate_child_handler(int child_status,
                       struct tevent_signal *sige,
                       void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct nsupdate_child_state *state =
            tevent_req_data(req, struct nsupdate_child_state);

    state->child_status = child_status;

    if (WIFEXITED(child_status) && WEXITSTATUS(child_status) != 0) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Dynamic DNS child failed with status [%d]\n", child_status);
        tevent_req_error(req, ERR_DYNDNS_FAILED);
        return;
    }

    if (WIFSIGNALED(child_status)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Dynamic DNS child was terminated by signal [%d]\n",
               WTERMSIG(child_status));
        tevent_req_error(req, ERR_DYNDNS_FAILED);
        return;
    }

    tevent_req_done(req);
}

static errno_t
nsupdate_child_recv(struct tevent_req *req, int *child_status)
{
    struct nsupdate_child_state *state =
            tevent_req_data(req, struct nsupdate_child_state);

    *child_status = state->child_status;

    PIPE_FD_CLOSE(state->pipefd_to_child);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return ERR_OK;
}

/* Fork a nsupdate child, write the nsupdate_msg into stdin and wait for the child
 * to finish one way or another
 */
struct be_nsupdate_state {
    int child_status;
};

static void be_nsupdate_done(struct tevent_req *subreq);
static char **be_nsupdate_args(TALLOC_CTX *mem_ctx,
                               enum be_nsupdate_auth auth_type,
                               bool force_tcp);

struct tevent_req *be_nsupdate_send(TALLOC_CTX *mem_ctx,
                                    struct tevent_context *ev,
                                    enum be_nsupdate_auth auth_type,
                                    char *nsupdate_msg,
                                    bool force_tcp)
{
    int pipefd_to_child[2] = PIPE_INIT;
    pid_t child_pid;
    errno_t ret;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct be_nsupdate_state *state;
    char **args;
    int debug_fd;

    req = tevent_req_create(mem_ctx, &state, struct be_nsupdate_state);
    if (req == NULL) {
        return NULL;
    }
    state->child_status = 0;

    ret = pipe(pipefd_to_child);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "pipe failed [%d][%s].\n", ret, strerror(ret));
        goto done;
    }

    child_pid = fork();

    if (child_pid == 0) { /* child */
        PIPE_FD_CLOSE(pipefd_to_child[1]);
        ret = dup2(pipefd_to_child[0], STDIN_FILENO);
        if (ret == -1) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "dup2 failed [%d][%s].\n", ret, strerror(ret));
            goto done;
        }

        if (debug_level >= SSSDBG_TRACE_LIBS) {
            debug_fd = get_fd_from_debug_file();
            ret = dup2(debug_fd, STDERR_FILENO);
            if (ret == -1) {
                ret = errno;
                DEBUG(SSSDBG_MINOR_FAILURE,
                    "dup2 failed [%d][%s].\n", ret, strerror(ret));
                /* stderr is not fatal */
            }
        }

        args = be_nsupdate_args(state, auth_type, force_tcp);
        if (args == NULL) {
            ret = ENOMEM;
            goto done;
        }

        errno = 0;
        execv(NSUPDATE_PATH, args);
        /* The child should never end up here */
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, "execv failed [%d][%s].\n", ret, strerror(ret));
        goto done;
    } else if (child_pid > 0) { /* parent */
        PIPE_FD_CLOSE(pipefd_to_child[0]);

        /* the nsupdate_child request now owns the pipefd and is responsible
         * for closing it
         */
        subreq = nsupdate_child_send(state, ev, pipefd_to_child[1],
                                     child_pid, nsupdate_msg);
        if (subreq == NULL) {
            ret = ERR_DYNDNS_FAILED;
            goto done;
        }
        tevent_req_set_callback(subreq, be_nsupdate_done, req);
    } else { /* error */
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "fork failed [%d][%s].\n", ret, strerror(ret));
        goto done;
    }

    ret = EOK;
done:
    if (ret != EOK) {
        PIPE_CLOSE(pipefd_to_child);
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }
    return req;
}

static char **
be_nsupdate_args(TALLOC_CTX *mem_ctx,
                 enum be_nsupdate_auth auth_type,
                 bool force_tcp)
{
    char **argv;
    int argc = 0;

    argv = talloc_zero_array(mem_ctx, char *, 6);
    if (argv == NULL) {
        return NULL;
    }

    argv[argc] = talloc_strdup(argv, NSUPDATE_PATH);
    if (argv[argc] == NULL) {
        goto fail;
    }
    argc++;

    switch (auth_type) {
    case BE_NSUPDATE_AUTH_NONE:
        DEBUG(SSSDBG_FUNC_DATA, "nsupdate auth type: none\n");
        break;
    case BE_NSUPDATE_AUTH_GSS_TSIG:
        DEBUG(SSSDBG_FUNC_DATA, "nsupdate auth type: GSS-TSIG\n");
        argv[argc] = talloc_strdup(argv, "-g");
        if (argv[argc] == NULL) {
            goto fail;
        }
        argc++;
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unknown nsupdate auth type %d\n", auth_type);
        goto fail;
    }

    if (force_tcp) {
        DEBUG(SSSDBG_FUNC_DATA, "TCP is set to on\n");
        argv[argc] = talloc_strdup(argv, "-v");
        if (argv[argc] == NULL) {
            goto fail;
        }
        argc++;
    }

    if (debug_level >= SSSDBG_TRACE_LIBS) {
        argv[argc] = talloc_strdup(argv, "-d");
        if (argv[argc] == NULL) {
            goto fail;
        }
        argc++;
    }

    if (debug_level >= SSSDBG_TRACE_INTERNAL) {
        argv[argc] = talloc_strdup(argv, "-D");
        if (argv[argc] == NULL) {
            goto fail;
        }
        argc++;
    }

    return argv;

fail:
    talloc_free(argv);
    return NULL;
}

static void
be_nsupdate_done(struct tevent_req *subreq)
{
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct be_nsupdate_state *state =
            tevent_req_data(req, struct be_nsupdate_state);
    errno_t ret;

    ret = nsupdate_child_recv(subreq, &state->child_status);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "nsupdate child execution failed [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_FUNC_DATA,
           "nsupdate child status: %d\n", state->child_status);
    tevent_req_done(req);
}

errno_t
be_nsupdate_recv(struct tevent_req *req, int *child_status)
{
    struct be_nsupdate_state *state =
            tevent_req_data(req, struct be_nsupdate_state);

    *child_status = state->child_status;

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

errno_t
be_nsupdate_check(void)
{
    errno_t ret;
    struct stat stat_buf;

    /* Ensure that nsupdate exists */
    errno = 0;
    ret = stat(NSUPDATE_PATH, &stat_buf);
    if (ret == -1) {
        ret = errno;
        if (ret == ENOENT) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "%s does not exist. Dynamic DNS updates disabled\n",
                  NSUPDATE_PATH);
        } else {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Could not set up dynamic DNS updates: [%d][%s]\n",
                  ret, strerror(ret));
        }
    }

    return ret;
}

static struct dp_option default_dyndns_opts[] = {
    { "dyndns_update", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "dyndns_update_per_family", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    { "dyndns_refresh_interval", DP_OPT_NUMBER, NULL_NUMBER, NULL_NUMBER },
    { "dyndns_iface", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "dyndns_ttl", DP_OPT_NUMBER, { .number = 1200 }, NULL_NUMBER },
    { "dyndns_update_ptr", DP_OPT_BOOL, BOOL_TRUE, BOOL_FALSE },
    { "dyndns_force_tcp", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "dyndns_auth", DP_OPT_STRING, { "gss-tsig" }, NULL_STRING },
    { "dyndns_auth_ptr", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "dyndns_server", DP_OPT_STRING, NULL_STRING, NULL_STRING },

    DP_OPTION_TERMINATOR
};

errno_t
be_nsupdate_init(TALLOC_CTX *mem_ctx, struct be_ctx *be_ctx,
                 struct dp_option *defopts,
                 struct be_nsupdate_ctx **_ctx)
{
    errno_t ret;
    struct dp_option *src_opts;
    struct be_nsupdate_ctx *ctx;
    char *strauth;

    ctx = talloc_zero(mem_ctx, struct be_nsupdate_ctx);
    if (ctx == NULL) return ENOMEM;

    src_opts = defopts ? defopts : default_dyndns_opts;

    ret = dp_get_options(ctx, be_ctx->cdb, be_ctx->conf_path,
                         src_opts, DP_OPT_DYNDNS, &ctx->opts);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot retrieve dynamic DNS options\n");
        return ret;
    }

    strauth = dp_opt_get_string(ctx->opts, DP_OPT_DYNDNS_AUTH);
    if (strcasecmp(strauth, "gss-tsig") == 0) {
        ctx->auth_type = BE_NSUPDATE_AUTH_GSS_TSIG;
    } else if (strcasecmp(strauth, "none") == 0) {
        ctx->auth_type = BE_NSUPDATE_AUTH_NONE;
    } else {
        DEBUG(SSSDBG_OP_FAILURE, "Unknown dyndns auth type %s\n", strauth);
        return EINVAL;
    }

    strauth = dp_opt_get_string(ctx->opts, DP_OPT_DYNDNS_AUTH_PTR);
    if (strauth == NULL) {
        ctx->auth_ptr_type = ctx->auth_type;
    } else if (strcasecmp(strauth, "gss-tsig") == 0) {
        ctx->auth_ptr_type = BE_NSUPDATE_AUTH_GSS_TSIG;
    } else if (strcasecmp(strauth, "none") == 0) {
        ctx->auth_ptr_type = BE_NSUPDATE_AUTH_NONE;
    } else {
        DEBUG(SSSDBG_OP_FAILURE, "Unknown dyndns ptr auth type %s\n", strauth);
        return EINVAL;
    }

    *_ctx = ctx;
    return ERR_OK;
}

static bool match_ip(const struct sockaddr *sa,
                     const struct sockaddr *sb)
{
    size_t addrsize;
    bool res;
    const void *addr_a;
    const void *addr_b;

    if (sa->sa_family == AF_INET) {
        addrsize = sizeof(struct in_addr);
        addr_a = (const void *) &((const struct sockaddr_in *) sa)->sin_addr;
        addr_b = (const void *) &((const struct sockaddr_in *) sb)->sin_addr;
    } else if (sa->sa_family == AF_INET6) {
        addrsize = sizeof(struct in6_addr);
        addr_a = (const void *) &((const struct sockaddr_in6 *) sa)->sin6_addr;
        addr_b = (const void *) &((const struct sockaddr_in6 *) sb)->sin6_addr;
    } else {
        res = false;
        goto done;
    }

    if (sa->sa_family != sb->sa_family) {
        res = false;
        goto done;
    }

    res = memcmp(addr_a, addr_b, addrsize) == 0;

done:
    return res;
}

static errno_t find_iface_by_addr(TALLOC_CTX *mem_ctx,
                                  const struct sockaddr *ss,
                                  const char **_iface_name)
{
    struct ifaddrs *ifaces = NULL;
    struct ifaddrs *ifa;
    errno_t ret;

    ret = getifaddrs(&ifaces);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not read interfaces [%d][%s]\n", ret, sss_strerror(ret));
        goto done;
    }

    for (ifa = ifaces; ifa != NULL; ifa = ifa->ifa_next) {

        /* Some interfaces don't have an ifa_addr */
        if (!ifa->ifa_addr) continue;

        if (match_ip(ss, ifa->ifa_addr)) {
            const char *iface_name;
            iface_name = talloc_strdup(mem_ctx, ifa->ifa_name);
            if (iface_name == NULL) {
                ret = ENOMEM;
            } else {
                *_iface_name = iface_name;
                ret = EOK;
            }
            goto done;
        }
    }
    ret = ENOENT;

done:
    freeifaddrs(ifaces);
    return ret;
}

errno_t sss_get_dualstack_addresses(TALLOC_CTX *mem_ctx,
                                    struct sockaddr *ss,
                                    struct sss_iface_addr **_iface_addrs)
{
    struct sss_iface_addr *iface_addrs;
    const char *iface_name = NULL;
    TALLOC_CTX *tmp_ctx;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = find_iface_by_addr(tmp_ctx, ss, &iface_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "find_iface_by_addr failed: %d:[%s]\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = sss_iface_addr_list_get(tmp_ctx, iface_name, &iface_addrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "sss_iface_addr_list_get failed: %d:[%s]\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = EOK;
    *_iface_addrs = talloc_steal(mem_ctx, iface_addrs);

done:
    talloc_free(tmp_ctx);
    return ret;
}
