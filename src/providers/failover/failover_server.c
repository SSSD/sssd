/*
    Copyright (C) 2025 Red Hat

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

#include <arpa/inet.h>
#include <talloc.h>
#include <time.h>

#include "config.h"
#include "providers/failover/failover_server.h"
#include "util/util.h"

static struct sss_failover_server_address *
sss_failover_server_address_new(TALLOC_CTX *mem_ctx,
                                const uint16_t port,
                                const int family,
                                const time_t expire,
                                const uint8_t *addr_binary)
{
    struct sss_failover_server_address *out;
    char buf[INET6_ADDRSTRLEN] = {0};
    const char *ntop_result;
    struct sockaddr_in *in4;
    struct sockaddr_in6 *in6;
    errno_t ret;

    if (addr_binary == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Empty IP address!\n");
        return NULL;
    }

    out = talloc_zero(mem_ctx, struct sss_failover_server_address);
    if (out == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        ret = ENOMEM;
        goto done;
    }

    out->family = family;
    out->expire = expire;

    switch (family) {
    case AF_INET:
        out->binary_len = sizeof(struct in_addr);
        out->sockaddr_len = sizeof(struct sockaddr_in);

        in4 = talloc_zero(out, struct sockaddr_in);
        if (in4 == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
            ret = ENOMEM;
            goto done;
        }

        in4->sin_family = AF_INET;
        in4->sin_port = (in_port_t)htons(port);
        memcpy(&in4->sin_addr, addr_binary, out->binary_len);
        out->sockaddr = (struct sockaddr *)in4;
        break;
    case AF_INET6:
        out->binary_len = sizeof(struct in6_addr);
        out->sockaddr_len = sizeof(struct sockaddr_in6);

        in6 = talloc_zero(out, struct sockaddr_in6);
        if (in6 == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
            ret = ENOMEM;
            goto done;
        }

        in6->sin6_family = AF_INET6;
        in6->sin6_port = (in_port_t)htons(port);
        memcpy(&in6->sin6_addr, addr_binary, out->binary_len);
        out->sockaddr = (struct sockaddr *)in6;
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Unknown IP family: %d\n", out->family);
        ret = EINVAL;
        goto done;
    }

    out->binary = talloc_memdup(out, addr_binary, out->binary_len);
    if (out->binary == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        ret = ENOMEM;
        goto done;
    }

    ntop_result = inet_ntop(family, addr_binary, buf, INET6_ADDRSTRLEN);
    if (ntop_result == NULL) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unable to convert IP address to string [%d]: %s\n", ret,
              sss_strerror(ret));
        goto done;
    }

    out->human = talloc_strdup(out, ntop_result);
    if (out->human == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(out);
        return NULL;
    }

    return out;
}

struct sss_failover_server *
sss_failover_server_new(TALLOC_CTX *mem_ctx,
                        const char *hostname,
                        const char *uri,
                        const uint16_t port,
                        const int priority,
                        const int weight)
{
    struct sss_failover_server *srv;

    if (hostname == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Hostname is not set!\n");
        return NULL;
    }

    srv = talloc_zero(mem_ctx, struct sss_failover_server);
    if (srv == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        return NULL;
    }

    srv->name = talloc_strdup(srv, hostname);
    if (srv->name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        talloc_free(srv);
        return NULL;
    }

    srv->uri = talloc_strdup(srv, uri);
    if (srv->uri == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        talloc_free(srv);
        return NULL;
    }

    srv->port = port;
    srv->priority = priority;
    srv->weight = weight;

    return srv;
}

errno_t
sss_failover_server_set_address(struct sss_failover_server *srv,
                                int family,
                                int ttl,
                                const uint8_t *addr)
{
    struct sss_failover_server_address *new_addr;
    time_t expire;

    if (family != AF_INET && family != AF_INET6) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid family given: %d\n", family);
        return EINVAL;
    }

    if (addr == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Empty addr given\n");
        return EINVAL;
    }

    expire = time(NULL) + ttl;
    new_addr = sss_failover_server_address_new(srv, srv->port, family, expire,
                                               addr);
    if (new_addr == NULL) {
        return ENOMEM;
    }

    if (srv->addr != NULL) {
        talloc_free(srv->addr);
    }

    srv->addr = new_addr;

    DEBUG(SSSDBG_TRACE_FUNC, "Server %s resolved to %s, ttl %d\n",
          srv->name, srv->addr->human, ttl);

    return EOK;
}

struct sss_failover_server *
sss_failover_server_clone(TALLOC_CTX *mem_ctx,
                          const struct sss_failover_server *srv)
{
    struct sss_failover_server *out;
    errno_t ret;

    if (srv == NULL || srv->name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Empty failover server information!\n");
        return NULL;
    }

    if (srv->addr != NULL
        && (srv->addr->binary == NULL || srv->addr->human == NULL)) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Address is not complete!\n");
        return NULL;
    }

    out = talloc_zero(mem_ctx, struct sss_failover_server);
    if (out == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        return NULL;
    }

    out->priority = srv->priority;
    out->weight = srv->weight;
    out->port = srv->port;
    out->state = srv->state;

    out->name = talloc_strdup(out, srv->name);
    if (out->name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        ret = ENOMEM;
        goto done;
    }

    if (srv->uri != NULL) {
        out->uri = talloc_strdup(out, srv->uri);
        if (out->uri == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
            ret = ENOMEM;
            goto done;
        }
    }

    if (srv->addr == NULL) {
        ret = EOK;
        goto done;
    }

    out->addr = sss_failover_server_address_new(out, srv->port,
                                                srv->addr->family,
                                                srv->addr->expire,
                                                srv->addr->binary);
    if (out->addr == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create new server address!\n");
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(out);
        return NULL;
    }

    return out;
}

bool
sss_failover_server_maybe_working(struct sss_failover_server *srv)
{
    switch (srv->state) {
        case SSS_FAILOVER_SERVER_STATE_OFFLINE:
        case SSS_FAILOVER_SERVER_STATE_RESOLVER_ERROR:
            return false;
        case SSS_FAILOVER_SERVER_STATE_UNKNOWN:
        case SSS_FAILOVER_SERVER_STATE_REACHABLE:
        case SSS_FAILOVER_SERVER_STATE_WORKING:
            return true;
        default:
            DEBUG(SSSDBG_CRIT_FAILURE, "Bug: unknown state [%d]!\n", srv->state);
            return false;
    }
}

void
sss_failover_server_mark_unknown(struct sss_failover_server *srv)
{
    DEBUG(SSSDBG_TRACE_FUNC,
          "Marking server [%s] as state unknown\n", srv->name);
    srv->state = SSS_FAILOVER_SERVER_STATE_UNKNOWN;
}

void
sss_failover_server_mark_reachable(struct sss_failover_server *srv)
{
    DEBUG(SSSDBG_TRACE_FUNC,
          "Marking server [%s] as reachable\n", srv->name);
    srv->state = SSS_FAILOVER_SERVER_STATE_REACHABLE;
}

void
sss_failover_server_mark_working(struct sss_failover_server *srv)
{
    DEBUG(SSSDBG_TRACE_FUNC,
          "Marking server [%s] as functional\n", srv->name);
    srv->state = SSS_FAILOVER_SERVER_STATE_WORKING;
}

void
sss_failover_server_mark_offline(struct sss_failover_server *srv)
{
    DEBUG(SSSDBG_TRACE_FUNC, "Marking server [%s] as offline\n", srv->name);
    srv->state = SSS_FAILOVER_SERVER_STATE_OFFLINE;
}

void
sss_failover_server_mark_resolver_error(struct sss_failover_server *srv)
{
    DEBUG(SSSDBG_TRACE_FUNC,
          "Marking server [%s] as unable to resolve hostname\n", srv->name);
    srv->state = SSS_FAILOVER_SERVER_STATE_RESOLVER_ERROR;
}

bool
sss_failover_server_equal(const struct sss_failover_server *a,
                          const struct sss_failover_server *b)
{
    if (a->name == NULL || b->name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: server with no name?\n");
        return false;
    }

    if (strcmp(a->name, b->name) != 0) {
        return false;
    }

    if (a->port != b->port) {
        return false;
    }

    return true;
}
