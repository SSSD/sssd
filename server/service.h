/*
   Unix SMB/CIFS implementation.

   SERVER SERVICE code

   Copyright (C) Andrew Tridgell 2003-2005
   Copyright (C) Stefan (metze) Metzmacher	2004

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

#ifndef __SERVICE_H__
#define __SERVICE_H__

#include "service_task.h"

/* The following definitions come from service.c  */

int register_server_service(const char *name,
                            void (*task_init)(struct task_server *));
int server_service_startup(struct event_context *event_ctx,
                           const char **server_services);
int server_service_init(const char *name,
			struct event_context *ev,
			pid_t *rpid);

/* The following definitions come from service_task.c  */

int task_server_startup(struct event_context *event_ctx,
                        const char *service_name,
                        void (*task_init)(struct task_server *),
                        pid_t *rpid);
void task_server_set_title(struct task_server *task, const char *title);
void task_server_terminate(struct task_server *task, const char *reason);

#endif /* __SERVICE_H__ */

