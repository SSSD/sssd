/*
   SSSD

   Service monitor

   Copyright (C) Simo Sorce			2008

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

#ifndef _MONITOR_H_
#define _MONITOR_H_

/* for detecting if NSCD is running */
#ifndef NSCD_SOCKET_PATH
#define NSCD_SOCKET_PATH "/var/run/nscd/socket"
#endif

struct mt_ctx;

/* from monitor_netlink.c */
struct netlink_ctx;

typedef void (*network_change_cb)(void *);

int setup_netlink(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
                  network_change_cb change_cb, void *cb_data,
                  struct netlink_ctx **_nlctx);

#endif /* _MONITOR_H */
