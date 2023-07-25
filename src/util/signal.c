/*
   Unix SMB/CIFS implementation.
   signal handling functions

   Copyright (C) Andrew Tridgell 1998

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

#include "util/util.h"
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>

/**
 * @file
 * @brief Signal handling
 */

/**
 Block sigs.
**/

void BlockSignals(bool block, int signum)
{
#ifdef HAVE_SIGPROCMASK
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set,signum);
	sigprocmask(block?SIG_BLOCK:SIG_UNBLOCK,&set,NULL);
#elif defined(HAVE_SIGBLOCK)
	if (block) {
		sigblock(sigmask(signum));
	} else {
		sigsetmask(siggetmask() & ~sigmask(signum));
	}
#else
	/* yikes! This platform can't block signals? */
	static int done;
	if (!done) {
		DEBUG(SSSDBG_FATAL_FAILURE,"WARNING: No signal blocking available\n");
		done=1;
	}
#endif
}

/**
 Catch a signal. This should implement the following semantics:

 1) The handler remains installed after being called.
 2) The signal should be blocked during handler execution.
**/

void (*CatchSignal(int signum,void (*handler)(int )))(int)
{
#ifdef HAVE_SIGACTION
	struct sigaction act;
	struct sigaction oldact;

	memset(&act, 0, sizeof(act));

	act.sa_handler = handler;
#ifdef SA_RESTART
	/*
	 * We *want* SIGALRM to interrupt a system call.
	 */
	if(signum != SIGALRM)
		act.sa_flags = SA_RESTART;
#endif
	sigemptyset(&act.sa_mask);
	sigaddset(&act.sa_mask,signum);
	sigaction(signum,&act,&oldact);
	return oldact.sa_handler;
#else /* !HAVE_SIGACTION */
	/* FIXME: need to handle sigvec and systems with broken signal() */
	return signal(signum, handler);
#endif
}
