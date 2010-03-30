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

#define _GNU_SOURCE
#include <stdio.h>

#ifdef HAVE_SELINUX
#include <selinux/selinux.h>
#endif

#ifdef HAVE_SEMANAGE
#include <semanage/semanage.h>
#endif

#include "util/util.h"

#ifndef DEFAULT_SERANGE
#define DEFAULT_SERANGE "s0"
#endif

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

#ifdef HAVE_SEMANAGE
/* turn libselinux messages into SSSD DEBUG() calls */
static void sss_semanage_error_callback(void *varg,
                                        semanage_handle_t *handle,
                                        const char *fmt, ...)
{
    int level = -1;
    int ret;
    char * message = NULL;
    va_list ap;

    switch (semanage_msg_get_level(handle)) {
        case SEMANAGE_MSG_ERR:
            level = 1;
            break;
        case SEMANAGE_MSG_WARN:
            level = 4;
            break;
        case SEMANAGE_MSG_INFO:
            level = 6;
            break;
    }

    va_start(ap, fmt);
    ret = vasprintf(&message, fmt, ap);
    if (ret < 0) {
        /* ENOMEM */
        return;
    }
    va_end(ap);

    if (level <= debug_level) {
        if (debug_timestamps) {
            time_t rightnow = time(NULL);
            char stamp[25];
            memcpy(stamp, ctime(&rightnow), 24);
            stamp[24] = '\0';
            debug_fn("(%s) [%s] [libsemanage] (%d): %s\n",
                     stamp, debug_prg_name, level, message);
        } else {
            debug_fn("[%s] [libsemanage] (%d): %s\n",
                     debug_prg_name, level, message);
        }
    }
    free(message);
}

static semanage_handle_t *sss_semanage_init(void)
{
    int ret;
    semanage_handle_t *handle = NULL;

    handle = semanage_handle_create();
    if (!handle) {
        DEBUG(1, ("Cannot create SELinux management handle\n"));
        return NULL;
    }

    semanage_msg_set_callback(handle,
                              sss_semanage_error_callback,
                              NULL);

    ret = semanage_is_managed(handle);
    if (ret != 1) {
        DEBUG(1, ("SELinux policy not managed\n"));
        goto fail;
    }

    ret = semanage_access_check(handle);
    if (ret < SEMANAGE_CAN_READ) {
        DEBUG(1, ("Cannot read SELinux policy store\n"));
        goto fail;
    }

    ret = semanage_connect(handle);
    if (ret != 0) {
        DEBUG(1, ("Cannot estabilish SELinux management connection\n"));
        goto fail;
    }

    ret = semanage_begin_transaction(handle);
    if (ret != 0) {
        DEBUG(1, ("Cannot begin SELinux transaction\n"));
        goto fail;
    }

    return handle;
fail:
    semanage_handle_destroy(handle);
    return NULL;
}

static int sss_semanage_user_add(semanage_handle_t *handle,
                                 semanage_seuser_key_t *key,
                                 const char *login_name,
                                 const char *seuser_name)
{
    int ret;
    semanage_seuser_t *seuser = NULL;

    ret = semanage_seuser_create(handle, &seuser);
    if (ret != 0) {
        DEBUG(1, ("Cannot create SELinux login mapping for %s\n", login_name));
        ret = EIO;
        goto done;
    }

    ret = semanage_seuser_set_name(handle, seuser, login_name);
    if (ret != 0) {
        DEBUG(1, ("Could not set name for %s\n", login_name));
        ret = EIO;
        goto done;
    }

    ret = semanage_seuser_set_mlsrange(handle, seuser, DEFAULT_SERANGE);
    if (ret != 0) {
        DEBUG(1, ("Could not set serange for %s\n", login_name));
        ret = EIO;
        goto done;
    }

    ret = semanage_seuser_set_sename(handle, seuser, seuser_name);
    if (ret != 0) {
        DEBUG(1, ("Could not set SELinux user for %s\n", login_name));
        ret = EIO;
        goto done;
    }

    ret = semanage_seuser_modify_local(handle, key, seuser);
    if (ret != 0) {
        DEBUG(1, ("Could not add login mapping for %s\n", login_name));
        ret = EIO;
        goto done;
    }

    ret = EOK;
done:
    semanage_seuser_free(seuser);
    return ret;
}

static int sss_semanage_user_mod(semanage_handle_t *handle,
                                 semanage_seuser_key_t *key,
                                 const char *login_name,
                                 const char *seuser_name)
{
    int ret;
    semanage_seuser_t *seuser = NULL;

    semanage_seuser_query(handle, key, &seuser);
    if (seuser == NULL) {
        DEBUG(1, ("Could not query seuser for %s\n", login_name));
        ret = EIO;
        goto done;
    }

    ret = semanage_seuser_set_mlsrange(handle, seuser, DEFAULT_SERANGE);
    if (ret != 0) {
        DEBUG(1, ("Could not set serange for %s\n", login_name));
        ret = EIO;
        goto done;
    }

    ret = semanage_seuser_set_sename(handle, seuser, seuser_name);
    if (ret != 0) {
        DEBUG(1, ("Could not set sename for %s\n", login_name));
        ret = EIO;
        goto done;
    }

    ret = semanage_seuser_modify_local(handle, key, seuser);
    if (ret != 0) {
        DEBUG(1, (("Could not modify login mapping for %s\n"), login_name));
        ret = EIO;
        goto done;
    }

    ret = EOK;
done:
    semanage_seuser_free(seuser);
    return ret;
}

int set_seuser(const char *login_name, const char *seuser_name)
{
    semanage_handle_t *handle = NULL;
    semanage_seuser_key_t *key = NULL;
    int ret;
    int seuser_exists = 0;

    if (seuser_name == NULL) {
        /* don't care, just let system pick the defaults */
        return EOK;
    }

    handle = sss_semanage_init();
    if (!handle) {
        DEBUG(1, ("Cannot init SELinux management\n"));
        ret = EIO;
        goto done;
    }

    ret = semanage_seuser_key_create(handle, login_name, &key);
    if (ret != 0) {
        DEBUG(1, ("Cannot create SELinux user key\n"));
        ret = EIO;
        goto done;
    }

    ret = semanage_seuser_exists(handle, key, &seuser_exists);
    if (ret < 0) {
        DEBUG(1, ("Cannot verify the SELinux user\n"));
        ret = EIO;
        goto done;
    }

    if (seuser_exists) {
        ret = sss_semanage_user_mod(handle, key, login_name, seuser_name);
        if (ret != 0) {
            DEBUG(1, ("Cannot modify SELinux user mapping\n"));
            ret = EIO;
            goto done;
        }
    } else {
        ret = sss_semanage_user_add(handle, key, login_name, seuser_name);
        if (ret != 0) {
            DEBUG(1, ("Cannot add SELinux user mapping\n"));
            ret = EIO;
            goto done;
        }
    }

    ret = semanage_commit(handle);
    if (ret != 0) {
        DEBUG(1, ("Cannot commit SELinux transaction\n"));
        ret = EIO;
        goto done;
    }

    ret = EOK;
done:
    semanage_seuser_key_free(key);
    semanage_handle_destroy(handle);
    return ret;
}

int del_seuser(const char *login_name)
{
    semanage_handle_t *handle = NULL;
    semanage_seuser_key_t *key = NULL;
    int ret;
    int exists = 0;

    handle = sss_semanage_init();
    if (!handle) {
        DEBUG(1, ("Cannot init SELinux management\n"));
        ret = EIO;
        goto done;
    }

    ret = semanage_seuser_key_create(handle, login_name, &key);
    if (ret != 0) {
        DEBUG(1, ("Cannot create SELinux user key\n"));
        ret = EIO;
        goto done;
    }

    ret = semanage_seuser_exists(handle, key, &exists);
    if (ret < 0) {
        DEBUG(1, ("Cannot verify the SELinux user\n"));
        ret = EIO;
        goto done;
    }

    if (!exists) {
        DEBUG(5, ("Login mapping for %s is not defined, OK if default mapping "
                  "was used\n", login_name));
        ret = EOK;  /* probably default mapping */
        goto done;
    }

    ret = semanage_seuser_exists_local(handle, key, &exists);
    if (ret < 0) {
        DEBUG(1, ("Cannot verify the SELinux user\n"));
        ret = EIO;
        goto done;
    }

    if (!exists) {
        DEBUG(1, ("Login mapping for %s is defined in policy, "
                  "cannot be deleted", login_name));
        ret = ENOENT;
        goto done;
    }

    ret = semanage_seuser_del_local(handle, key);
    if (ret != 0) {
        DEBUG(1, ("Could not delete login mapping for %s", login_name));
        ret = EIO;
        goto done;
    }

    ret = semanage_commit(handle);
    if (ret != 0) {
        DEBUG(1, ("Cannot commit SELinux transaction\n"));
        ret = EIO;
        goto done;
    }

    ret = EOK;
done:
    semanage_handle_destroy(handle);
    return ret;
}

#else /* HAVE_SEMANAGE */
int set_seuser(const char *login_name, const char *seuser_name)
{
    return EOK;
}

int del_seuser(const char *login_name)
{
    return EOK;
}
#endif  /* HAVE_SEMANAGE */
