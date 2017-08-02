/*
   SSSD

   selinux.c

   Copyright (C) Jakub Hrozek <jhrozek@redhat.com>        2010

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

#include "config.h"

#include <stdio.h>

#ifdef HAVE_SELINUX
#include <selinux/selinux.h>
#endif

#include "tools/tools_util.h"

#ifdef HAVE_SELINUX
/*
 * selinux_file_context - Set the security context before any file or
 *                        directory creation.
 *
 *  selinux_file_context () should be called before any creation of file,
 *  symlink, directory, ...
 *
 *  Callers may have to Reset SELinux to create files with default
 *  contexts:
 *      reset_selinux_file_context();
 */
int selinux_file_context(const char *dst_name)
{
    security_context_t scontext = NULL;

    if (is_selinux_enabled() == 1) {
        /* Get the default security context for this file */
        if (matchpathcon(dst_name, 0, &scontext) < 0) {
            if (security_getenforce () != 0) {
                return 1;
            }
        }
        /* Set the security context for the next created file */
        if (setfscreatecon(scontext) < 0) {
            if (security_getenforce() != 0) {
                return 1;
            }
        }
        freecon(scontext);
    }

    return 0;
}

int reset_selinux_file_context(void)
{
    setfscreatecon(NULL);
    return EOK;
}

#else   /* HAVE_SELINUX */
int selinux_file_context(const char *dst_name)
{
    return EOK;
}

int reset_selinux_file_context(void)
{
    return EOK;
}
#endif  /* HAVE_SELINUX */
