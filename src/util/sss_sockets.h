/*
   SSSD

   Socket utils

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2016

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

#ifndef __SSS_SOCKETS_H__
#define __SSS_SOCKETS_H__

errno_t set_fd_common_opts(int fd, int timeout);

struct tevent_req *sssd_async_connect_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           int fd,
                                           const struct sockaddr *addr,
                                           socklen_t addr_len);
int sssd_async_connect_recv(struct tevent_req *req);


struct tevent_req *sssd_async_socket_init_send(TALLOC_CTX *mem_ctx,
                                               struct tevent_context *ev,
                                               bool use_udp,
                                               struct sockaddr *addr,
                                               socklen_t addr_len, int timeout);
int sssd_async_socket_init_recv(struct tevent_req *req, int *sd);

#endif /* __SSS_SOCKETS_H__ */
