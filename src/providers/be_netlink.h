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

#ifndef _DP_NETLINK_H_
#define _DP_NETLINK_H_

#include <talloc.h>
#include <tevent.h>

/* from be_netlink.c */
struct be_netlink_ctx;

typedef void (*network_change_cb)(void *);

int netlink_watch(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
                  network_change_cb change_cb, void *cb_data,
                  struct be_netlink_ctx **_nlctx);

#endif /* _DP_MONITOR_H */
