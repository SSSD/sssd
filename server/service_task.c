/* 
   Unix SMB/CIFS implementation.

   helper functions for task based servers (nbtd, winbind etc)

   Copyright (C) Andrew Tridgell 2005

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

#include "../talloc/talloc.h"
#include "../events/events.h"
#include "util/util.h"
#include "process.h"
#include "service.h"
#include "service_task.h"

/*
  terminate a task service
*/
void task_server_terminate(struct task_server *task, const char *reason)
{
	struct event_context *event_ctx = task->event_ctx;
	process_terminate(event_ctx, reason);

	/* don't free this above, it might contain the 'reason' being printed */
	talloc_free(task);
}

/* used for the callback from the process model code */
struct task_state {
	void (*task_init)(struct task_server *);
};


/*
  called by the process model code when the new task starts up. This then calls
  the server specific startup code
*/
static void task_server_callback(struct event_context *event_ctx, void *private)
{
	struct task_state *state = talloc_get_type(private, struct task_state);
	struct task_server *task;

	task = talloc(event_ctx, struct task_server);
	if (task == NULL) return;

	task->event_ctx = event_ctx;

 /* TODO: Init task messaging here */

	state->task_init(task);
}

/*
  startup a task based server
*/
int task_server_startup(struct event_context *event_ctx,
			const char *service_name,
			void (*task_init)(struct task_server *))
{
	struct task_state *state;

	state = talloc(event_ctx, struct task_state);
	if (NULL == state) return RES_NOMEM;

	state->task_init = task_init;

	return process_new_task(event_ctx, service_name, task_server_callback, state);
}

/*
  setup a task title
*/
void task_server_set_title(struct task_server *task, const char *title)
{
	process_set_title(task->event_ctx, title);
}
