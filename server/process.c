/*
   Based on process_standard.c from samba4

   Copyright (C) Andrew Tridgell 1992-2005
   Copyright (C) James J Myers 2003 <myersjj@samba.org>
   Copyright (C) Stefan (metze) Metzmacher 2004

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

#include <unistd.h>
#include "../events/events.h"
#include "../tdb/include/tdb.h"
#include "../talloc/talloc.h"
#include "util/util.h"

#ifdef HAVE_SETPROCTITLE
#ifdef HAVE_SETPROCTITLE_H
#include <setproctitle.h>
#endif
#else
#define setproctitle none_setproctitle
static int none_setproctitle(const char *fmt, ...) PRINTF_ATTRIBUTE(1, 2);
static int none_setproctitle(const char *fmt, ...)
{
	return 0;
}
#endif

/*
  called to create a new server task
*/
int process_new_task(struct event_context *ev,
		     const char *service_name,
		     void (*new_task)(struct event_context *, void *),
		     void *private)
{
	pid_t pid;
	struct event_context *ev2;

	pid = fork();

	if (pid != 0) {
		int res;

		/* parent */
		res = EOK;

		if (pid == -1) {
			/* error */
			res = ECHILD;
		}

		/* ... go back to the event loop */
		return res;
	}

	pid = getpid();

	/* This is now the child code. We need a completely new event_context to work with */
	ev2 = event_context_init(NULL);

	/* the service has given us a private pointer that
	   encapsulates the context it needs for this new connection -
	   everything else will be freed */
	talloc_steal(ev2, private);

	/* this will free all the listening sockets and all state that
	   is not associated with this new connection */
	talloc_free(ev);

	/* tdb needs special fork handling */
	if (tdb_reopen_all(1) == -1) {
		DEBUG(0,("process_new_task: tdb_reopen_all failed.\n"));
	}

	setproctitle("task %s server_id[%d]", service_name, pid);

	/* setup this new task. */
	new_task(ev2, private);

	/* we can't return to the top level here, as that event context is gone,
	   so we now process events in the new event context until there are no
	   more to process */
	event_loop_wait(ev2);

	talloc_free(ev2);
	exit(0);
}


/* called when a task goes down */
void process_terminate(struct event_context *ev, const char *reason)
{
	DEBUG(2,("process_terminate: reason[%s]\n",reason));

	talloc_free(ev);

	/* terminate this process */
	exit(0);
}

/* called to set a title of a task or connection */
void process_set_title(struct event_context *ev, const char *title)
{
	if (title) {
		setproctitle("%s", title);
	} else {
		setproctitle(NULL);
	}
}
