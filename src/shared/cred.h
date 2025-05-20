/*
    Copyright (C) 2025 Red Hat

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

#ifndef _SHARED_CRED_H_
#define _SHARED_CRED_H_

#include "config.h"

/* CAUTION:
 * This file is also used in sss_client (pam, nss). Therefore it have to be
 * minimalist and cannot include DEBUG macros or header file util.h.
 */

#ifdef HAVE_UCRED

#include <sys/socket.h>
#define SSS_PEERCRED_SOCKET_OPTION SO_PEERCRED
#define STRUCT_CRED struct ucred
#define CRED_UID(x) ((x)->uid)
#define CRED_GID(x) ((x)->gid)
#define CRED_PID(x) ((x)->pid)

#define SET_CRED_UID(x, v) { (x)->uid = v; }
#define SET_CRED_GID(x, v) { (x)->gid = v; }

#elif HAVE_XUCRED

/* On FreeBSD and MacOS the credentials structure obtained from a unix socket
 * is called xucred and is defined in sys/ucred.h
 * See description for the LOCAL_PEERCRED socket option in the unix(4) manual
 * page: https://man.freebsd.org/cgi/man.cgi?query=unix
 */
#include <sys/ucred.h>
#define STRUCT_CRED struct xucred
#define SSS_PEERCRED_SOCKET_OPTION LOCAL_PEERCRED
#define CRED_UID(x) ((x)->cr_uid)
#define CRED_GID(x) ((x)->cr_ngroups > 0 ? (x)->cr_groups[0] : -1)
#define CRED_PID(x) ((x)->cr_pid)

#define SET_CRED_UID(x, v) { (x)->cr_uid = v; }
#define SET_CRED_GID(x, v) { if ((x)->cr_ngroups > 0) (x)->cr_groups[0] = v; }

#endif

#endif /* _SHARED_CRED_H_ */
