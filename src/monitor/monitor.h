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

typedef int (*monitor_reconf_fn) (struct config_file_ctx *file_ctx,
                                  const char *filename);

struct mt_ctx;

int monitor_process_init(struct mt_ctx *ctx,
                         const char *config_file);

#endif /* _MONITOR_H */
