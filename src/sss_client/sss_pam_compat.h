/*
   SSSD

   Compat declarations for PAM.

   Authors:
        Lukas Slebodnik <lslebodn@redhat.com>

   Copyright (C) Red Hat, Inc 2014

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _SSS_PAM_COMPAT_H
#define _SSS_PAM_COMPAT_H

#include "config.h"

#ifdef HAVE_SECURITY_PAM_MODUTIL_H
# include <security/pam_modutil.h>
#endif /* HAVE_SECURITY_PAM_MODUTIL_H */

#ifdef HAVE_SECURITY_PAM_EXT_H
# include <security/pam_ext.h>
#endif /* HAVE_SECURITY_PAM_EXT_H */

#ifndef HAVE_PAM_VSYSLOG
#define pam_vsyslog(pamh, priority, fmt, vargs) \
    vsyslog((priority), (fmt), (vargs))
#endif /* HAVE_PAM_VSYSLOG */

#ifndef HAVE_PAM_SYSLOG
#define pam_syslog(pamh, priority, fmt, ...) \
    syslog((priority), (fmt) __VA_OPT__(,) __VA_ARGS__)
#endif /* HAVE_PAM_SYSLOG */

#ifndef PAM_BAD_ITEM
# define PAM_BAD_ITEM PAM_USER_UNKNOWN
#endif /* PAM_BAD_ITEM */

#if !defined(PAM_NONNULL) && defined(OPENPAM_NONNULL)
#define PAM_NONNULL OPENPAM_NONNULL
#endif

#ifndef HAVE_PAM_MODUTIL_GETLOGIN
#include <unistd.h>

static inline const char * PAM_NONNULL((1)) pam_modutil_getlogin(pam_handle_t *pamh)
{
    return getlogin();
}
#endif

#endif /* _SSS_PAM_COMPAT_H */
