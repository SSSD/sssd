/*
    Authors:
        Simo Sorce <simo@redhat.com>

    Copyright (C) 2016 Red Hat

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

#ifndef __SSSD_UTIL_CREDS_H__
#define __SSSD_UTIL_CREDS_H__

/* following code comes from gss-proxy's gp_selinux.h file */
#ifdef HAVE_SELINUX

#include <selinux/context.h>
typedef context_t SELINUX_CTX;
#include <selinux/selinux.h>
typedef char * SEC_CTX;

#define SELINUX_context_new context_new
#define SELINUX_context_free context_free
#define SELINUX_context_str context_str
#define SELINUX_context_type_get context_type_get
#define SELINUX_context_user_get context_user_get
#define SELINUX_context_role_get context_role_get
#define SELINUX_context_range_get context_range_get
#define SELINUX_getpeercon getpeercon
#define SELINUX_freecon freecon

#else /* not HAVE_SELINUX */

typedef void * SELINUX_CTX;
typedef void * SEC_CTX;

#define SELINUX_context_new(x) NULL
#define SELINUX_context_free(x) (x) = NULL
#define SELINUX_context_dummy_get(x) "<SELinux not compiled in>"
#define SELINUX_context_str SELINUX_context_dummy_get
#define SELINUX_context_type_get SELINUX_context_dummy_get
#define SELINUX_context_user_get SELINUX_context_dummy_get
#define SELINUX_context_role_get SELINUX_context_dummy_get
#define SELINUX_context_range_get SELINUX_context_dummy_get

#include <errno.h>
#define SELINUX_getpeercon(x, y) -1; do { \
    *(y) = NULL; \
    errno = ENOTSUP; \
} while(0)

#define SELINUX_freecon(x) (x) = NULL

#endif /* done HAVE_SELINUX */

#ifdef HAVE_UCRED
#define STRUCT_CRED struct ucred
#define CRED_UID(x) ((x)->uid)
#define CRED_GID(x) ((x)->gid)
#define CRED_PID(x) ((x)->pid)
#include <sys/socket.h>
#elif HAVE_XUCRED
/* On FreeBSD and MacOS the credentials structure obtained from a unix socket
 * is called xucred and is defined in sys/ucred.h
 * See description for the LOCAL_PEERCRED socket option in the unix(4) manual
 * page: https://man.freebsd.org/cgi/man.cgi?query=unix
 */
#define STRUCT_CRED struct xucred
#define CRED_UID(x) ((x)->cr_uid)
#define CRED_GID(x) ((x)->cr_ngroups > 0 ? (x)->cr_groups[0] : -1)
#define CRED_PID(x) ((x)->cr_pid)
#include <sys/ucred.h>
#endif

struct cli_creds {
    STRUCT_CRED ucred;
    SELINUX_CTX selinux_ctx;
};

#define cli_creds_get_uid(x) (CRED_UID(&x->ucred))
#define cli_creds_get_gid(x) (CRED_UID(&x->ucred))

#endif /* __SSSD_UTIL_CREDS_H__ */
