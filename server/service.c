/*
   Based on:
   SERVER SERVICE code from samba4

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

#include <strings.h>
#include "util/util.h"
#include "../talloc/talloc.h"
#include "../events/events.h"
#include "service.h"

/*
  a linked list of registered servers
*/
static struct registered_server {
	struct registered_server *next, *prev;
	const char *service_name;
	void (*task_init)(struct task_server *);
} *registered_servers;

/*
  register a server service.
*/
int register_server_service(const char *name,
				 void (*task_init)(struct task_server *))
{
	struct registered_server *srv;
	srv = talloc(talloc_autofree_context(), struct registered_server);
	if (NULL == srv) return ENOMEM;
	srv->service_name = name;
	srv->task_init = task_init;
	DLIST_ADD_END(registered_servers, srv, struct registered_server *);
	return EOK;
}


/*
  initialise a server service
*/
static int server_service_init(const char *name, struct event_context *ev)
{
	struct registered_server *srv;
	for (srv=registered_servers; srv; srv=srv->next) {
		if (strcasecmp(name, srv->service_name) == 0) {
			return task_server_startup(ev,
						   srv->service_name,
						   srv->task_init);
		}
	}
	return EINVAL;
}


/*
  startup all of our server services
*/
int server_service_startup(struct event_context *event_ctx,
				const char **server_services)
{
	int i;

	if (!server_services) {
		DEBUG(0,("server_service_startup: no endpoint servers configured\n"));
		return EINVAL;
	}

	for (i = 0; server_services[i]; i++) {
		int status;

		status = server_service_init(server_services[i], event_ctx);
		if (status != EOK) {
			DEBUG(0,("Failed to start service '%s'\n",
				server_services[i]));
			return status;
		}
	}

	return EOK;
}
