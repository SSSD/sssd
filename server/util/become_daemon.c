/* 
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Jeremy Allison 2001-2002
   Copyright (C) Simo Sorce 2001
   Copyright (C) Jim McDonough (jmcd@us.ibm.com)  2003.
   Copyright (C) James J Myers 2003
   
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
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "util/util.h"


/*******************************************************************
 Close the low 3 fd's and open dev/null in their place.
********************************************************************/
static void close_low_fds(bool stderr_too)
{
#ifndef VALGRIND
	int fd;
	int i;

	close(0);
	close(1); 

	if (stderr_too)
		close(2);

	/* try and use up these file descriptors, so silly
		library routines writing to stdout etc won't cause havoc */
	for (i=0;i<3;i++) {
		if (i == 2 && !stderr_too)
			continue;

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
	if (Fork) {
		if (fork()) {
			_exit(0);
		}
	}

  /* detach from the terminal */
#ifdef HAVE_SETSID
	setsid();
#elif defined(TIOCNOTTY)
	{
		int i = open("/dev/tty", O_RDWR, 0);
		if (i != -1) {
			ioctl(i, (int) TIOCNOTTY, (char *)0);      
			close(i);
		}
	}
#endif /* HAVE_SETSID */

	/* Close fd's 0,1,2. Needed if started by rsh */
	close_low_fds(false);  /* Don't close stderr, let the debug system
				  attach it to the logfile */
}

int pidfile(const char *path, const char *name)
{
    char pid_str[32];
    pid_t pid;
    char *file;
    int fd;
    int ret;

    asprintf(&file, "%s/%s.pid", path, name);

    fd = open(file, O_RDONLY, 0644);
    if (fd != -1) {

        pid_str[sizeof(pid_str) -1] = '\0';
        ret = read(fd, pid_str, sizeof(pid_str) -1);
        if (ret > 0) {
            /* let's check the pid */

            pid = (pid_t)atoi(pid_str);
            if (pid != 0) {
                errno = 0;
                ret = kill(pid, 0);
                if (ret != 0 && errno != ESRCH) {
                    close(fd);
                    free(file);
                    return EEXIST;
                }
            }
        }

        /* notihng in the file or no process */
        close(fd);
        unlink(file);

    } else {
        if (errno != ENOENT) {
            free(file);
            return EIO;
        }
    }

    fd = open(file, O_CREAT | O_WRONLY | O_EXCL, 0644);
    if (fd == -1) {
        free(file);
        return EIO;
    }
    free(file);

    memset(pid_str, 0, sizeof(pid_str));
    snprintf(pid_str, sizeof(pid_str) -1, "%u\n", (unsigned int) getpid());

    ret = write(fd, pid_str, strlen(pid_str));
    if (ret != strlen(pid_str)) {
        close(fd);
        return EIO;
    }

    close(fd);

    return 0;
}

