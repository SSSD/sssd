/*
   SSSD

   Servers setup routines

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

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "util/util.h"
#include "ldb.h"
#include "confdb/confdb.h"

#ifdef HAVE_PRCTL
#include <sys/prctl.h>
#endif

/*******************************************************************
 Close the low 3 fd's and open dev/null in their place.
********************************************************************/
static void close_low_fds(void)
{
#ifndef VALGRIND
	int fd;
	int i;

	close(0);
	close(1);
	close(2);

	/* try and use up these file descriptors, so silly
		library routines writing to stdout etc won't cause havoc */
	for (i=0;i<3;i++) {
		fd = open("/dev/null",O_RDWR,0);
		if (fd < 0)
			fd = open("/dev/null",O_WRONLY,0);
		if (fd < 0) {
			DEBUG(0,("Can't open /dev/null\n"));
			return;
		}
		if (fd != i) {
			DEBUG(0,("Didn't get file descriptor %d\n",i));
			return;
		}
	}
#endif
}

/**
 Become a daemon, discarding the controlling terminal.
**/

void become_daemon(bool Fork)
{
        int ret;

	if (Fork) {
		if (fork()) {
			_exit(0);
		}
	}

    /* detach from the terminal */
	setsid();

        /* chdir to / to be sure we're not on a remote filesystem */
        errno = 0;
        if(chdir("/") == -1) {
            ret = errno;
            DEBUG(0, ("Cannot change directory (%d [%s])\n",
                    ret, strerror(ret)));
            return;
        }

	/* Close fd's 0,1,2. Needed if started by rsh */
	close_low_fds();
}

int pidfile(const char *path, const char *name)
{
    char pid_str[32];
    pid_t pid;
    char *file;
    int fd;
    int ret, err;

    file = talloc_asprintf(NULL, "%s/%s.pid", path, name);
    if (!file) {
        return ENOMEM;
    }

    fd = open(file, O_RDONLY, 0644);
    err = errno;
    if (fd != -1) {

        pid_str[sizeof(pid_str) -1] = '\0';
        ret = read(fd, pid_str, sizeof(pid_str) -1);
        if (ret > 0) {
            /* let's check the pid */

            pid = (pid_t)atoi(pid_str);
            if (pid != 0) {
                errno = 0;
                ret = kill(pid, 0);
                /* succeeded in signaling the process -> another sssd process */
                if (ret == 0) {
                    close(fd);
                    talloc_free(file);
                    return EEXIST;
                }
                if (ret != 0 && errno != ESRCH) {
                    err = errno;
                    close(fd);
                    talloc_free(file);
                    return err;
                }
            }
        }

        /* nothing in the file or no process */
        close(fd);
        unlink(file);

    } else {
        if (err != ENOENT) {
            talloc_free(file);
            return err;
        }
    }

    fd = open(file, O_CREAT | O_WRONLY | O_EXCL, 0644);
    err = errno;
    if (fd == -1) {
        talloc_free(file);
        return err;
    }
    talloc_free(file);

    memset(pid_str, 0, sizeof(pid_str));
    snprintf(pid_str, sizeof(pid_str) -1, "%u\n", (unsigned int) getpid());

    ret = write(fd, pid_str, strlen(pid_str));
    err = errno;
    if (ret != strlen(pid_str)) {
        close(fd);
        return err;
    }

    close(fd);

    return 0;
}

static void sig_hup(int sig)
{
	/* cycle log/debug files */
	return;
}

void sig_term(int sig)
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

#ifndef HAVE_PRCTL
static void sig_segv_abrt(int sig)
{
#if HAVE_GETPGRP
	static int done;
	if (done == 0 && getpgrp() == getpid()) {
		DEBUG(0,("%s: killing children\n", strsignal(sig)));
		done = 1;
		kill(-getpgrp(), SIGTERM);
	}
#endif  /* HAVE_GETPGRP */
    exit(1);
}
#endif /* HAVE_PRCTL */

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

#ifndef HAVE_PRCTL
        /* If prctl is not defined on the system, try to handle
         * some common termination signals gracefully */
	CatchSignal(SIGSEGV, sig_segv_abrt);
	CatchSignal(SIGABRT, sig_segv_abrt);
#endif

}

/*
  handle io on stdin
*/
static void server_stdin_handler(struct tevent_context *event_ctx,
                                 struct tevent_fd *fde,
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
 main server helpers.
*/

int die_if_parent_died(void)
{
#ifdef HAVE_PRCTL
    int ret;

    errno = 0;
    ret = prctl(PR_SET_PDEATHSIG, SIGTERM, 0, 0, 0);
    if (ret != 0) {
        ret = errno;
        DEBUG(2, ("prctl failed [%d]: %s", ret, strerror(ret)));
        return ret;
    }
#endif
    return EOK;
}

static void te_server_hup(struct tevent_context *ev,
                          struct tevent_signal *se,
                          int signum,
                          int count,
                          void *siginfo,
                          void *private_data)
{
    DEBUG(1, ("Received SIGHUP. Rotating logfiles.\n"));
    rotate_debug_files();
}

int server_setup(const char *name, int flags,
                 const char *conf_entry,
                 struct main_context **main_ctx)
{
    struct tevent_context *event_ctx;
    struct main_context *ctx;
    uint16_t stdin_event_flags;
    char *conf_db;
    int ret = EOK;
    bool dt;
    bool dl;
    struct tevent_signal *tes;

    debug_prg_name = strdup(name);
    if (!debug_prg_name) {
        return ENOMEM;
    }

    setenv("_SSS_LOOPS", "NO", 0);

    setup_signals();

    /* we want default permissions on created files to be very strict,
       so set our umask to 0177 */
    umask(0177);

    if (flags & FLAGS_DAEMON) {
        DEBUG(3,("Becoming a daemon.\n"));
        become_daemon(true);
    }

    if (flags & FLAGS_PID_FILE) {
        ret = pidfile(PID_PATH, name);
        if (ret != EOK) {
            DEBUG(0, ("Error creating pidfile! (%d [%s])\n",
                      ret, strerror(ret)));
            return ret;
        }
    }

    /* Set up locale */
    setlocale (LC_ALL, "");
    bindtextdomain (PACKAGE, LOCALEDIR);
    textdomain (PACKAGE);

    /* the event context is the top level structure.
     * Everything else should hang off that */
    event_ctx = tevent_context_init(talloc_autofree_context());
    if (event_ctx == NULL) {
        DEBUG(0,("The event context initialiaziton failed\n"));
        return 1;
    }

    ctx = talloc(event_ctx, struct main_context);
    if (ctx == NULL) {
        DEBUG(0,("Out of memory, aborting!\n"));
        return ENOMEM;
    }

    ctx->event_ctx = event_ctx;

    conf_db = talloc_asprintf(ctx, "%s/%s", DB_PATH, CONFDB_FILE);
    if (conf_db == NULL) {
        DEBUG(0,("Out of memory, aborting!\n"));
        return ENOMEM;
    }

    ret = confdb_init(ctx, &ctx->confdb_ctx, conf_db);
    if (ret != EOK) {
        DEBUG(0,("The confdb initialization failed\n"));
        return ret;
    }

    /* set debug level if any in conf_entry */
    ret = confdb_get_int(ctx->confdb_ctx, ctx, conf_entry,
                         CONFDB_SERVICE_DEBUG_LEVEL,
                         debug_level, &debug_level);
    if (ret != EOK) {
        DEBUG(0, ("Error reading from confdb (%d) [%s]\n",
                  ret, strerror(ret)));
        return ret;
    }

    /* same for debug timestamps */
    dt = (debug_timestamps != 0);
    ret = confdb_get_bool(ctx->confdb_ctx, ctx, conf_entry,
                          CONFDB_SERVICE_DEBUG_TIMESTAMPS,
                          dt, &dt);
    if (ret != EOK) {
        DEBUG(0, ("Error reading from confdb (%d) [%s]\n",
                  ret, strerror(ret)));
        return ret;
    }
    if (dt) debug_timestamps = 1;
    else debug_timestamps = 0;

    /* same for debug to file */
    dl = (debug_to_file != 0);
    ret = confdb_get_bool(ctx->confdb_ctx, ctx, conf_entry,
                          CONFDB_SERVICE_DEBUG_TO_FILES,
                          dl, &dl);
    if (ret != EOK) {
        DEBUG(0, ("Error reading from confdb (%d) [%s]\n",
                  ret, strerror(ret)));
        return ret;
    }
    if (dl) debug_to_file = 1;

    /* before opening the log file set up log rotation */
    tes = tevent_add_signal(ctx->event_ctx, ctx, SIGHUP, 0,
                            te_server_hup, NULL);
    if (tes == NULL) {
        return EIO;
    }

    /* open log file if told so */
    if (debug_to_file) {
        ret = open_debug_file();
        if (ret != EOK) {
            DEBUG(0, ("Error setting up logging (%d) [%s]\n",
                    ret, strerror(ret)));
            return ret;
        }
    }

    DEBUG(3, ("CONFDB: %s\n", conf_db));

    if (flags & FLAGS_INTERACTIVE) {
        /* terminate when stdin goes away */
        stdin_event_flags = TEVENT_FD_READ;
    } else {
        /* stay alive forever */
        stdin_event_flags = 0;
    }

    /* catch EOF on stdin */
#ifdef SIGTTIN
    signal(SIGTTIN, SIG_IGN);
#endif
    tevent_add_fd(event_ctx, event_ctx, 0, stdin_event_flags,
                 server_stdin_handler, discard_const(name));

    *main_ctx = ctx;
    return EOK;
}

void server_loop(struct main_context *main_ctx)
{
    /* wait for events - this is where the server sits for most of its
       life */
    tevent_loop_wait(main_ctx->event_ctx);

    /* as everything hangs off this event context, freeing it
       should initiate a clean shutdown of all services */
    talloc_free(main_ctx->event_ctx);
}
