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

#define RESOLV_CONF_PATH "/etc/resolv.conf"
#define CONFIG_FILE_POLL_INTERVAL 5 /* seconds */

/* for detecting if NSCD is running */
#ifndef NSCD_SOCKET_PATH
#define NSCD_SOCKET_PATH "/var/run/nscd/socket"
#endif

struct config_file_ctx;

typedef int (*monitor_reconf_fn) (struct config_file_ctx *file_ctx,
                                  const char *filename);

struct mt_ctx;

int monitor_process_init(struct mt_ctx *ctx,
                         const char *config_file);

/* from monitor_netlink.c */
struct netlink_ctx;

enum network_change {
    NL_ROUTE_UP,
    NL_ROUTE_DOWN
};

typedef void (*network_change_cb)(enum network_change, void *);

int setup_netlink(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
                  network_change_cb change_cb, void *cb_data,
                  struct netlink_ctx **_nlctx);

#endif /* _MONITOR_H */
