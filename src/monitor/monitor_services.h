/*
   SSSD

   Helper functions to be used by 'monitor' process to handle services.

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

#ifndef __SSSD_MONITOR_SERVICES_H__
#define __SSSD_MONITOR_SERVICES_H__

#include <talloc.h>
#include <tevent.h>


struct sss_sigchild_ctx;
struct sss_child_ctx;

typedef void (*sss_child_fn_t)(int pid, int wait_status, void *pvt);


/* Create a new child context to manage callbacks */
errno_t sss_sigchld_init(TALLOC_CTX *mem_ctx,
                         struct tevent_context *ev,
                         struct sss_sigchild_ctx **child_ctx);

errno_t sss_child_register(TALLOC_CTX *mem_ctx,
                           struct sss_sigchild_ctx *sigchld_ctx,
                           pid_t pid,
                           sss_child_fn_t cb,
                           void *pvt,
                           struct sss_child_ctx **child_ctx);

#endif /* __SSSD_MONITOR_SERVICES_H__ */
