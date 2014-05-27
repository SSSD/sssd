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

#ifndef PAM_BAD_ITEM
# define PAM_BAD_ITEM PAM_USER_UNKNOWN
#endif /* PAM_BAD_ITEM */

#endif /* _SSS_PAM_COMPAT_H */
