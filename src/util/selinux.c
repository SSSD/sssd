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
#include <stdlib.h>
#include <errno.h>

#ifdef HAVE_SELINUX
#include <selinux/selinux.h>
#include <selinux/label.h>
#endif

#include "util/debug.h"

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
    struct selabel_handle *handle = NULL;
    char *scontext = NULL;
    char *pathname = NULL;
    int ret;

    if (is_selinux_enabled() != 1) {
        return EOK;
    }

    pathname = realpath(dst_name, NULL);
    if (pathname == NULL) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, "realpath of %s failed [%d]: %s\n",
              dst_name, ret, sss_strerror(ret));
        goto done;
    }

    /* Get the default security context for this file */
    handle = selabel_open(SELABEL_CTX_FILE, NULL, 0);
    if (handle == NULL) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create selabel context "
                "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    ret = selabel_lookup(handle, &scontext, pathname, 0);
    if (ret < 0 && errno == ENOENT) {
        scontext = NULL;
    } else if (ret != 0) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to lookup selinux context "
                "[%d]: %s", ret, sss_strerror(ret));
        goto done;
    }

    /* Set the security context for the next created file */
    if (setfscreatecon(scontext) < 0) {
        if (security_getenforce() != 0) {
            ret = EFAULT;
            goto done;
        }
    }

    ret = EOK;

done:
    free(pathname);
    freecon(scontext);

    if (handle != NULL) {
        selabel_close(handle);
    }

    return ret;
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
