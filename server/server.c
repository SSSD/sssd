/* 
   Unix SMB/CIFS implementation.

   Main SMB server routines

   Copyright (C) Andrew Tridgell		1992-2005
   Copyright (C) Martin Pool			2002
   Copyright (C) Jelmer Vernooij		2002
   Copyright (C) James J Myers 			2003 <myersjj@samba.org>
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

#include <stdbool.h>
#include <unistd.h>
#include <popt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "util/util.h"
#include "../events/events.h"
#include "../ldb/include/ldb.h"
#include "service.h"
#include "confdb/confdb.h"
#include "providers/providers.h"
#include "monitor.h"

extern int nss_process_init(TALLOC_CTX *mem_ctx,
                            struct event_context *ev,
                            struct confdb_ctx *cdb);

static void sig_hup(int sig)
{
	/* cycle log/debug files */
	return;
}

static void sig_term(int sig)
{
#if HAVE_GETPGRP
	static int done_sigterm;
	if (done_sigterm == 0 && getpgrp() == getpid()) {
		DEBUG(0,("SIGTERM: killing children\n"));
		done_sigterm = 1;
		kill(-getpgrp(), SIGTERM);
	}
#endif
	exit(0);
}

/*
  setup signal masks
*/
static void setup_signals(void)
{
	/* we are never interested in SIGPIPE */
	BlockSignals(true, SIGPIPE);

#if defined(SIGFPE)
	/* we are never interested in SIGFPE */
	BlockSignals(true, SIGFPE);
#endif

	/* We are no longer interested in USR1 */
	BlockSignals(true, SIGUSR1);

#if defined(SIGUSR2)
	/* We are no longer interested in USR2 */
	BlockSignals(true, SIGUSR2);
#endif

	/* POSIX demands that signals are inherited. If the invoking process has
	 * these signals masked, we will have problems, as we won't recieve them. */
	BlockSignals(false, SIGHUP);
	BlockSignals(false, SIGTERM);

	CatchSignal(SIGHUP, sig_hup);
	CatchSignal(SIGTERM, sig_term);
}

/*
  handle io on stdin
*/
static void server_stdin_handler(struct event_context *event_ctx, struct fd_event *fde,
				 uint16_t flags, void *private)
{
	const char *binary_name = (const char *)private;
	uint8_t c;
	if (read(0, &c, 1) == 0) {
		DEBUG(0,("%s: EOF on stdin - terminating\n", binary_name));
#if HAVE_GETPGRP
		if (getpgrp() == getpid()) {
			kill(-getpgrp(), SIGTERM);
		}
#endif
		exit(0);
	}
}

/*
 main server.
*/
int main(int argc, const char *argv[])
{
    char *service = NULL;
	bool opt_daemon = false;
	bool opt_interactive = false;
	int opt;
	poptContext pc;
	struct event_context *event_ctx;
    struct confdb_ctx *confdb_ctx;
    TALLOC_CTX *mem_ctx;
	uint16_t stdin_event_flags;
	int ret = EOK;
    bool is_monitor = false;

    debug_prg_name = argv[0];

	enum {
		OPT_DAEMON = 1000,
		OPT_INTERACTIVE
	};
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{"daemon", 'D', POPT_ARG_NONE, NULL, OPT_DAEMON,
		 "Become a daemon (default)", NULL },
		{"interactive",	'i', POPT_ARG_NONE, NULL, OPT_INTERACTIVE,
		 "Run interactive (not a daemon)", NULL},
		{"service",	's', POPT_ARG_STRING, &service, 0,
		 "Executes a specific service instead of the monitor", NULL},
		{"debug-level",	'd', POPT_ARG_INT, &debug_level, 0,
		 "Executes a specific service instead of the monitor", NULL},
		{ NULL }
	};

	pc = poptGetContext(argv[0], argc, argv, long_options, 0);
	while((opt = poptGetNextOpt(pc)) != -1) {
		switch(opt) {
		case OPT_DAEMON:
			opt_daemon = true;
			break;
		case OPT_INTERACTIVE:
			opt_interactive = true;
			break;
		default:
			fprintf(stderr, "\nInvalid option %s: %s\n\n",
				  poptBadOption(pc, 0), poptStrerror(opt));
			poptPrintUsage(pc, stderr, 0);
			return 1;
		}
	}

    if (!service) {
        fprintf(stderr,"\nERROR: No service specified\n\n");
        return 5;
    }

    if (strcmp(service, "monitor") == 0) is_monitor = true;

    if (is_monitor) {
        if (opt_daemon && opt_interactive) {
            fprintf(stderr,"\nERROR: "
                    "Option -i|--interactive is not allowed together with -D|--daemon\n\n");
            poptPrintUsage(pc, stderr, 0);
            return 1;
        } else if (!opt_interactive) {
            /* default is --daemon */
            opt_daemon = true;
        }
    } else {
        if (opt_daemon || opt_interactive) {
            fprintf(stderr,"\nERROR: "
                    "Options -i or -D not allowed with -s (service)\n\n");
            poptPrintUsage(pc, stderr, 0);
            return 1;
        }

    }

	poptFreeContext(pc);

	setup_signals();

	/* we want default permissions on created files to be very strict,
	   so set our umask to 0177 */
	umask(0177);

	if (opt_daemon) {
		DEBUG(3,("Becoming a daemon.\n"));
		become_daemon(true);

		ret = pidfile(PID_PATH, "sssd");
        if (ret != EOK) {
            fprintf(stderr, "\nERROR: PID File reports daemon already running!\n");
            return 1;
        }
	}

	/* the event context is the top level structure.
     * Everything else should hang off that */
	event_ctx = event_context_init(talloc_autofree_context());
	if (event_ctx == NULL) {
		DEBUG(0,("The event context initialiaziton failed\n"));
		return 1;
	}

    mem_ctx = talloc_new(event_ctx);
    if (mem_ctx == NULL) {
        DEBUG(0,("Out of memory, aborting!\n"));
        return 1;
    }

    ret = confdb_init(mem_ctx, event_ctx, &confdb_ctx);
    if (ret != EOK) {
        DEBUG(0,("The confdb initialization failed\n"));
		return 1;
	}

	if (opt_interactive) {
		/* terminate when stdin goes away */
		stdin_event_flags = EVENT_FD_READ;
	} else {
		/* stay alive forever */
		stdin_event_flags = 0;
	}

	/* catch EOF on stdin */
#ifdef SIGTTIN
	signal(SIGTTIN, SIG_IGN);
#endif
	event_add_fd(event_ctx, event_ctx, 0, stdin_event_flags,
		     server_stdin_handler,
		     discard_const(argv[0]));

    /* What are we asked to run ? */
    if (is_monitor) {
        /* the monitor */
        ret = monitor_process_init(mem_ctx, event_ctx, confdb_ctx);

    } else {

        if (strcmp(service, "nss") == 0) {
            ret = nss_process_init(mem_ctx, event_ctx, confdb_ctx);

        } else if (strcmp(service, "dp") == 0) {
            ret = dp_process_init(mem_ctx, event_ctx, confdb_ctx);

        } else {
            fprintf(stderr,
                    "\nERROR: Unknown Service specified [%s]\n",
                    service);
            ret = EINVAL;
        }
    }

    if (ret != EOK) return 3;

	/* wait for events - this is where smbd sits for most of its
	   life */
	event_loop_wait(event_ctx);

	/* as everything hangs off this event context, freeing it
	   should initiate a clean shutdown of all services */
	talloc_free(event_ctx);

	return 0;
}
