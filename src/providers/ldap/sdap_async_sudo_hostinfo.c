/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

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

#include <errno.h>
#include <tevent.h>
#include <talloc.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>

#include "util/util.h"
#include "providers/ldap/sdap.h"
#include "providers/ldap/sdap_id_op.h"
#include "providers/ldap/sdap_sudo.h"
#include "resolv/async_resolv.h"

static int sdap_sudo_get_ip_addresses(TALLOC_CTX *mem_ctx, char ***_ip_addr);

struct sdap_sudo_get_hostinfo_state {
    char **hostnames;
    char **ip_addr;
};

struct sdap_sudo_get_hostnames_state {
    struct tevent_context *ev;
    struct resolv_ctx *resolv_ctx;
    enum host_database *host_db;
    enum restrict_family family_order;
    char **hostnames;
};

static void sdap_sudo_get_hostinfo_done(struct tevent_req *req);

static struct tevent_req *sdap_sudo_get_hostnames_send(TALLOC_CTX *mem_ctx,
                                                       struct be_ctx *be_ctx);

static void sdap_sudo_get_hostnames_done(struct tevent_req *subreq);

static int sdap_sudo_get_hostnames_recv(TALLOC_CTX *mem_ctx,
                                        struct tevent_req *req,
                                        char ***hostnames);


struct tevent_req * sdap_sudo_get_hostinfo_send(TALLOC_CTX *mem_ctx,
                                                struct sdap_options *opts,
                                                struct be_ctx *be_ctx)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct sdap_sudo_get_hostinfo_state *state = NULL;
    char *conf_hostnames = NULL;
    char *conf_ip_addr = NULL;
    int ret = EOK;

    /* create request */
    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_sudo_get_hostinfo_state);
    if (req == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->hostnames = NULL;
    state->ip_addr = NULL;

    /* load info from configuration */
    conf_hostnames = dp_opt_get_string(opts->basic, SDAP_SUDO_HOSTNAMES);
    conf_ip_addr = dp_opt_get_string(opts->basic, SDAP_SUDO_IP);

    if (conf_hostnames != NULL) {
        ret = split_on_separator(state, conf_hostnames, ' ', true, true,
                                 &state->hostnames, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Unable to parse hostnames [%d]: %s\n", ret, strerror(ret));
            goto done;
        } else {
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "Hostnames set to: %s\n", conf_hostnames);
        }
    }

    if (conf_ip_addr != NULL) {
        ret = split_on_separator(state, conf_ip_addr, ' ', true, true,
                                 &state->ip_addr, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Unable to parse IP addresses [%d]: %s\n",
                   ret, strerror(ret));
            goto done;
        } else {
            DEBUG(SSSDBG_CONF_SETTINGS, "IP addresses set to: %s\n",
                  conf_ip_addr);
        }
    }

    /* if IP addresses are not specified, configure it automatically */
    if (state->ip_addr == NULL) {
        ret = sdap_sudo_get_ip_addresses(state, &state->ip_addr);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Unable to detect IP addresses [%d]: %s\n",
                   ret, strerror(ret));
        }
    }

    /* if hostnames are not specified, configure it automatically */
    if (state->hostnames == NULL) {
        subreq = sdap_sudo_get_hostnames_send(state, be_ctx);
        if (subreq == NULL) {
            ret = ENOMEM;
            goto done;
        }

        tevent_req_set_callback(subreq, sdap_sudo_get_hostinfo_done, req);
        ret = EAGAIN;
    }

done:
    if (ret != EAGAIN) {
        if (ret == EOK) {
            tevent_req_done(req);
        } else {
            tevent_req_error(req, ret);
        }
        tevent_req_post(req, be_ctx->ev);
    }

    return req;
}

static void sdap_sudo_get_hostinfo_done(struct tevent_req *subreq)
{
    struct tevent_req *req = NULL;
    struct sdap_sudo_get_hostinfo_state *state = NULL;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_sudo_get_hostinfo_state);

    ret = sdap_sudo_get_hostnames_recv(state, subreq, &state->hostnames);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to retrieve hostnames [%d]: %s\n",
                                    ret, strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

int sdap_sudo_get_hostinfo_recv(TALLOC_CTX *mem_ctx,
                                struct tevent_req *req,
                                char ***hostnames, char ***ip_addr)
{
    struct sdap_sudo_get_hostinfo_state *state = NULL;
    state = tevent_req_data(req, struct sdap_sudo_get_hostinfo_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *hostnames = talloc_steal(mem_ctx, state->hostnames);
    *ip_addr = talloc_steal(mem_ctx, state->ip_addr);

    return EOK;
}

static int sdap_sudo_get_ip_addresses(TALLOC_CTX *mem_ctx,
                                      char ***_ip_addr_list)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char **ip_addr_list = NULL;
    struct ifaddrs *ifaces = NULL;
    struct ifaddrs *iface = NULL;
    struct sockaddr_in ip4_addr;
    struct sockaddr_in ip4_network;
    struct sockaddr_in6 ip6_addr;
    struct sockaddr_in6 ip6_network;
    char ip_addr[INET6_ADDRSTRLEN + 1];
    char network_addr[INET6_ADDRSTRLEN + 1];
    in_addr_t ip4_netmask = 0;
    uint32_t ip6_netmask = 0;
    unsigned int netmask = 0;
    void *sinx_addr = NULL;
    void *sinx_network = NULL;
    int addr_count = 0;
    int ret;
    int i;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    errno = 0;
    ret = getifaddrs(&ifaces);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not read interfaces [%d][%s]\n",
                                    ret, strerror(ret));
        goto done;
    }

    for (iface = ifaces; iface != NULL; iface = iface->ifa_next) {
        /* Some interfaces don't have an ifa_addr */
        if (!iface->ifa_addr) continue;

        netmask = 0;
        switch (iface->ifa_addr->sa_family) {
        case AF_INET:
            memcpy(&ip4_addr, iface->ifa_addr, sizeof(struct sockaddr_in));
            memcpy(&ip4_network, iface->ifa_netmask, sizeof(struct sockaddr_in));

            if (!check_ipv4_addr(&ip4_addr.sin_addr,
                                  SSS_NO_LOOPBACK|SSS_NO_MULTICAST
                                  |SSS_NO_BROADCAST)) {
                continue;
            }

            /* get network mask length */
            ip4_netmask = ntohl(ip4_network.sin_addr.s_addr);
            while (ip4_netmask) {
                netmask++;
                ip4_netmask <<= 1;
            }

            /* get network address */
            ip4_network.sin_addr.s_addr = ip4_addr.sin_addr.s_addr
                                           & ip4_network.sin_addr.s_addr;

            sinx_addr = &ip4_addr.sin_addr;
            sinx_network = &ip4_network.sin_addr;
            break;
        case AF_INET6:
            memcpy(&ip6_addr, iface->ifa_addr, sizeof(struct sockaddr_in6));
            memcpy(&ip6_network, iface->ifa_netmask, sizeof(struct sockaddr_in6));

            if (!check_ipv6_addr(&ip6_addr.sin6_addr,
                                  SSS_NO_LOOPBACK|SSS_NO_MULTICAST)) {
                continue;
            }

            /* get network mask length */
            for (i = 0; i < 4; i++) {
                ip6_netmask = ntohl(((uint32_t*)(&ip6_network.sin6_addr))[i]);
                while (ip6_netmask) {
                    netmask++;
                    ip6_netmask <<= 1;
                }
            }

            /* get network address */
            for (i = 0; i < 4; i++) {
                ((uint32_t*)(&ip6_network.sin6_addr))[i] =
                          ((uint32_t*)(&ip6_addr.sin6_addr))[i]
                        & ((uint32_t*)(&ip6_network.sin6_addr))[i];
            }

            sinx_addr = &ip6_addr.sin6_addr;
            sinx_network = &ip6_network.sin6_addr;
            break;
        default:
            /* skip other families */
            continue;
        }

        /* ip address */
        errno = 0;
        if (inet_ntop(iface->ifa_addr->sa_family, sinx_addr,
                      ip_addr, INET6_ADDRSTRLEN) == NULL) {
            ret = errno;
            DEBUG(SSSDBG_MINOR_FAILURE, "inet_ntop() failed [%d]: %s\n",
                                         ret, strerror(ret));
            goto done;
        }

        /* network */
        errno = 0;
        if (inet_ntop(iface->ifa_addr->sa_family, sinx_network,
                      network_addr, INET6_ADDRSTRLEN) == NULL) {
            ret = errno;
            DEBUG(SSSDBG_MINOR_FAILURE, "inet_ntop() failed [%d]: %s\n",
                                         ret, strerror(ret));
            goto done;
        }

        addr_count += 2;
        ip_addr_list = talloc_realloc(tmp_ctx, ip_addr_list, char*,
                                      addr_count + 1);
        if (ip_addr_list == NULL) {
            ret = ENOMEM;
            goto done;
        }

        ip_addr_list[addr_count - 2] = talloc_strdup(ip_addr_list, ip_addr);
        if (ip_addr_list[addr_count - 2] == NULL) {
            ret = ENOMEM;
            goto done;
        }

        ip_addr_list[addr_count - 1] = talloc_asprintf(ip_addr_list, "%s/%d",
                                                       network_addr, netmask);
        if (ip_addr_list[addr_count - 1] == NULL) {
            ret = ENOMEM;
            goto done;
        }

        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Found IP address: %s in network %s/%d\n",
               ip_addr, network_addr, netmask);
    }

    if (ip_addr_list) {
        ip_addr_list[addr_count] = NULL;
    }
    *_ip_addr_list = talloc_steal(mem_ctx, ip_addr_list);

done:
    freeifaddrs(ifaces);
    talloc_free(tmp_ctx);

    return ret;
}

/*
 * SUDO allows only one hostname that is returned from gethostname()
 * (and set to "localhost" if the returned value is empty)
 * and then - if allowed - resolves its fqdn using gethostbyname() or
 * getaddrinfo() if available.
 */
static struct tevent_req *sdap_sudo_get_hostnames_send(TALLOC_CTX *mem_ctx,
                                                       struct be_ctx *be_ctx)
{
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct sdap_sudo_get_hostnames_state *state = NULL;
    char *dot = NULL;
    char hostname[HOST_NAME_MAX + 1];
    int ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_sudo_get_hostnames_state);
    if (req == NULL) {
        return NULL;
    }

    state->ev = be_ctx->ev;
    state->hostnames = NULL;

    /* hostname, fqdn and NULL */
    state->hostnames = talloc_zero_array(state, char*, 3);
    if (state->hostnames == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero_array() failed\n");
        ret = ENOMEM;
        goto done;
    }

    /* get hostname */

    errno = 0;
    ret = gethostname(hostname, sizeof(hostname));
    if (ret != EOK) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to retrieve machine hostname "
                                    "[%d]: %s\n", ret, strerror(ret));
        goto done;
    }
    hostname[HOST_NAME_MAX] = '\0';

    state->hostnames[0] = talloc_strdup(state->hostnames, hostname);
    if (state->hostnames[0] == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup() failed\n");
        ret = ENOMEM;
        goto done;
    }

    dot = strchr(hostname, '.');
    if (dot != NULL) {
        /* already a fqdn, determine hostname and finish */
        DEBUG(SSSDBG_TRACE_INTERNAL, "Found fqdn: %s\n", hostname);

        *dot = '\0';
        DEBUG(SSSDBG_TRACE_INTERNAL, "Found hostname: %s\n", hostname);

        state->hostnames[1] = talloc_strdup(state->hostnames, hostname);
        if (state->hostnames[1] == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup() failed\n");
            ret = ENOMEM;
            goto done;
        }

        ret = EOK;
        goto done;
    } else {
        DEBUG(SSSDBG_TRACE_INTERNAL, "Found hostname: %s\n", hostname);
    }

    state->resolv_ctx = be_ctx->be_res->resolv;
    state->host_db = default_host_dbs;

    /* get fqdn */
    subreq = resolv_gethostbyname_send(state, state->ev, state->resolv_ctx,
                                       hostname, be_ctx->be_res->family_order,
                                       state->host_db);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, sdap_sudo_get_hostnames_done, req);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        if (ret == EOK) {
            tevent_req_done(req);
        } else {
            tevent_req_error(req, ret);
        }
        tevent_req_post(req, be_ctx->ev);
    }

    return req;
}

static void sdap_sudo_get_hostnames_done(struct tevent_req *subreq)
{
    struct tevent_req *req = NULL;
    struct sdap_sudo_get_hostnames_state *state = NULL;
    struct resolv_hostent *rhostent = NULL;
    int resolv_status;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_sudo_get_hostnames_state);

    ret = resolv_gethostbyname_recv(subreq, state, &resolv_status, NULL,
                                    &rhostent);
    talloc_zfree(subreq);
    if (ret == ENOENT) {
        /* Empty result, just quit */
        DEBUG(SSSDBG_TRACE_INTERNAL, "No hostent found\n");
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not resolve fqdn for this machine, error [%d]: %s, "
               "resolver returned: [%d]: %s\n", ret, strerror(ret),
               resolv_status, resolv_strerror(resolv_status));
        tevent_req_error(req, ret);
        return;
    }

    /* EOK */

    DEBUG(SSSDBG_TRACE_INTERNAL, "Found fqdn: %s\n", rhostent->name);

    if (state->hostnames == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "state->hostnames is NULL\n");
        ret = EINVAL;
        goto done;
    }

    state->hostnames[1] = talloc_strdup(state->hostnames, rhostent->name);
    if (state->hostnames[1] == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup() failed\n");
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
}

static int sdap_sudo_get_hostnames_recv(TALLOC_CTX *mem_ctx,
                                        struct tevent_req *req,
                                        char ***hostnames)
{
    struct sdap_sudo_get_hostnames_state *state = NULL;

    state = tevent_req_data(req, struct sdap_sudo_get_hostnames_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *hostnames = talloc_steal(mem_ctx, state->hostnames);

    return EOK;
}
