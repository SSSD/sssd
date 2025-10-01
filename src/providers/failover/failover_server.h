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

#ifndef _FAILOVER_SERVER_H_
#define _FAILOVER_SERVER_H_

#include <talloc.h>

#include "config.h"
#include "util/util.h"

enum sss_failover_server_state {
    /**
     * @brief State of the server is unknown.
     */
    SSS_FAILOVER_SERVER_STATE_UNKNOWN,

    /**
     * @brief The server is responding but there is no active connection.
     *
     * E.g. ping succeeded, but full connection was not done.
     */
    SSS_FAILOVER_SERVER_STATE_REACHABLE,

    /**
     * @brief The server is fully functional.
     */
    SSS_FAILOVER_SERVER_STATE_WORKING,

    /**
     * @brief The server is currently offline.
     */
    SSS_FAILOVER_SERVER_STATE_OFFLINE,

    /**
     * @brief The server host name can not be resolved.
     */
    SSS_FAILOVER_SERVER_STATE_RESOLVER_ERROR,
};

struct sss_failover_server_address {
    /* AF_INET or AF_INET6 */
    int family;

    /* Human readable IP address. */
    char *human;

    /* IP address in binary format. */
    uint8_t *binary;

    /* Length of @binary */
    size_t binary_len;

    /* Generic sockaddr record. */
    struct sockaddr *sockaddr;

    /* @sockaddr length */
    socklen_t sockaddr_len;

    /* Time when the address will be expired and needs to be resolved again. */
    time_t expire;
};

struct sss_failover_server {
    /* DNS hostname */
    char *name;

    /* Server URI */
    char *uri;

    /* Service port. */
    uint16_t port;

    /* DNS priority */
    int priority;

    /* DNS weight */
    int weight;

    /* Host IP address. */
    struct sss_failover_server_address *addr;

    /* Current state. */
    enum sss_failover_server_state state;

    /* Connection handle if state is CONNECTED. */
    void *connection;
};

/**
 * @brief Create new failover server record.
 *
 * @return struct sss_failover_server *
 */
struct sss_failover_server *
sss_failover_server_new(TALLOC_CTX *mem_ctx,
                        const char *hostname,
                        const char *uri,
                        const uint16_t port,
                        const int priority,
                        const int weight);

/**
 * @brief Set resolved IP address of the server hostname.
 *
 * @param srv
 * @param family
 * @param ttl
 * @param addr
 * @return errno_t
 */
errno_t
sss_failover_server_set_address(struct sss_failover_server *srv,
                                int family,
                                int ttl,
                                const uint8_t *addr);

/**
 * @brief Clone failover server record.
 *
 * @param mem_ctx
 * @param srv
 * @return struct sss_failover_server *
 */
struct sss_failover_server *
sss_failover_server_clone(TALLOC_CTX *mem_ctx,
                          const struct sss_failover_server *srv);


/**
 * @brief Return true if server state suggest that the server may work.
 */
bool
sss_failover_server_maybe_working(struct sss_failover_server *srv);

/**
 * @brief Mark server as state unknown
 */
void
sss_failover_server_mark_unknown(struct sss_failover_server *srv);

/**
 * @brief Mark server as reachable.
 */
void
sss_failover_server_mark_reachable(struct sss_failover_server *srv);

/**
 * @brief Mark server as fully functional and working.
 */
void
sss_failover_server_mark_working(struct sss_failover_server *srv);

/**
 * @brief Mark server as offline.
 */
void
sss_failover_server_mark_offline(struct sss_failover_server *srv);

/**
 * @brief Mark server as unable to resolve hostname.
 */
void
sss_failover_server_mark_resolver_error(struct sss_failover_server *srv);

/**
 * @brief Compare two servers and return true if they are equal.
 *
 * Note: this only compares name and port.
 */
bool
sss_failover_server_equal(const struct sss_failover_server *a,
                          const struct sss_failover_server *b);

#endif /* _FAILOVER_SERVER_H_ */
