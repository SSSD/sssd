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

/* dynamic dns helpers */
struct sss_iface_addr;

#define DYNDNS_REMOVE_A     0x1
#define DYNDNS_REMOVE_AAAA  0x2

errno_t
sss_iface_addr_list_get(TALLOC_CTX *mem_ctx, const char *ifname,
                        struct sss_iface_addr **_addrlist);

struct sss_iface_addr *
sss_iface_addr_add(TALLOC_CTX *mem_ctx, struct sss_iface_addr **list,
                   struct sockaddr_storage *ss);

errno_t
sss_iface_addr_list_as_str_list(TALLOC_CTX *mem_ctx,
                                struct sss_iface_addr *ifaddr_list,
                                char ***_straddrs);

errno_t
be_nsupdate_create_msg(TALLOC_CTX *mem_ctx, const char *realm,
                       const char *zone, const char *servername,
                       const char *hostname, const unsigned int ttl,
                       uint8_t remove_af, struct sss_iface_addr *addresses,
                       char **_update_msg);

/* Returns:
 *    * ERR_OK              - on success
 *    * ERR_DYNDNS_FAILED   - if nsupdate fails for any reason
 *    * ERR_DYNDNS_TIMEOUT  - if the update times out. child_status
 *                            is ETIMEDOUT in this case
 */
struct tevent_req *be_nsupdate_send(TALLOC_CTX *mem_ctx,
                                    struct tevent_context *ev,
                                    char *nsupdate_msg);
errno_t be_nsupdate_recv(struct tevent_req *req, int *child_status);

struct tevent_req * nsupdate_get_addrs_send(TALLOC_CTX *mem_ctx,
                                            struct tevent_context *ev,
                                            struct be_resolv_ctx *be_res,
                                            const char *hostname);
errno_t nsupdate_get_addrs_recv(struct tevent_req *req,
                                TALLOC_CTX *mem_ctx,
                                char ***_addrlist);
