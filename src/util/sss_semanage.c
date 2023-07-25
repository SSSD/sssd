/*
   SSSD

   sss_semanage.c

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
#if defined(HAVE_SEMANAGE) && defined(HAVE_SELINUX)
#include <semanage/semanage.h>
#include <selinux/selinux.h>
#endif

#include "util/util.h"

#ifndef DEFAULT_SERANGE
#define DEFAULT_SERANGE "s0"
#endif

#if defined(HAVE_SEMANAGE) && defined(HAVE_SELINUX)
/* turn libselinux messages into SSSD DEBUG() calls */
static void sss_semanage_error_callback(void *varg,
                                        semanage_handle_t *handle,
                                        const char *fmt, ...)
{
    int level = SSSDBG_INVALID;
    va_list ap;

    switch (semanage_msg_get_level(handle)) {
        case SEMANAGE_MSG_ERR:
            level = SSSDBG_CRIT_FAILURE;
            break;
        case SEMANAGE_MSG_WARN:
            level = SSSDBG_MINOR_FAILURE;
            break;
        case SEMANAGE_MSG_INFO:
            level = SSSDBG_TRACE_FUNC;
            break;
    }

    va_start(ap, fmt);
    sss_vdebug_fn(__FILE__, __LINE__, "libsemanage", level,
                  APPEND_LINE_FEED, fmt, ap);
    va_end(ap);
}

static void sss_semanage_close(semanage_handle_t *handle)
{
    if (handle == NULL) {
        return;     /* semanage uses asserts */
    }

    if (semanage_is_connected(handle)) {
        semanage_disconnect(handle);
    }
    semanage_handle_destroy(handle);
}

static int sss_is_selinux_managed(semanage_handle_t *handle)
{
    int ret;

    if (handle == NULL) {
        return EINVAL;
    }

    if (!is_selinux_enabled()) {
        return ERR_SELINUX_NOT_MANAGED;
    }

    ret = semanage_is_managed(handle);
    if (ret == 0) {
        DEBUG(SSSDBG_TRACE_FUNC, "SELinux policy not managed via libsemanage\n");
        return ERR_SELINUX_NOT_MANAGED;
    } else if (ret == -1) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Call to semanage_is_managed failed\n");
        return EIO;
    }

    return EOK;
}

static int sss_semanage_init(semanage_handle_t **_handle)
{
    int ret;
    semanage_handle_t *handle = NULL;

    handle = semanage_handle_create();
    if (!handle) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot create SELinux management handle\n");
        ret = EIO;
        goto done;
    }

    semanage_msg_set_callback(handle,
                              sss_semanage_error_callback,
                              NULL);

    ret = sss_is_selinux_managed(handle);
    if (ret != EOK) {
        goto done;
    }

    ret = semanage_access_check(handle);
    if (ret < SEMANAGE_CAN_READ) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot read SELinux policy store\n");
        ret = EACCES;
        goto done;
    }

    ret = semanage_connect(handle);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot estabilish SELinux management connection\n");
        ret = EIO;
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        sss_semanage_close(handle);
    } else {
        *_handle = handle;
    }

    return ret;
}

static int sss_semanage_user_add(semanage_handle_t *handle,
                                 semanage_seuser_key_t *key,
                                 const char *login_name,
                                 const char *seuser_name,
                                 const char *mls)
{
    int ret;
    semanage_seuser_t *seuser = NULL;

    ret = semanage_seuser_create(handle, &seuser);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot create SELinux login mapping for %s\n", login_name);
        ret = EIO;
        goto done;
    }

    ret = semanage_seuser_set_name(handle, seuser, login_name);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not set name for %s\n", login_name);
        ret = EIO;
        goto done;
    }

    ret = semanage_seuser_set_mlsrange(handle, seuser,
                                       mls ? mls : DEFAULT_SERANGE);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not set serange for %s\n", login_name);
        ret = EIO;
        goto done;
    }

    ret = semanage_seuser_set_sename(handle, seuser, seuser_name);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not set SELinux user for %s\n", login_name);
        ret = EIO;
        goto done;
    }

    ret = semanage_seuser_modify_local(handle, key, seuser);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not add login mapping for %s\n", login_name);
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
                                 const char *seuser_name,
                                 const char *mls)
{
    int ret;
    semanage_seuser_t *seuser = NULL;

    semanage_seuser_query(handle, key, &seuser);
    if (seuser == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not query seuser for %s\n", login_name);
        ret = EIO;
        goto done;
    }

    ret = semanage_seuser_set_mlsrange(handle, seuser,
                                       mls ? mls : DEFAULT_SERANGE);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not set serange for %s\n", login_name);
        ret = EIO;
        goto done;
    }

    ret = semanage_seuser_set_sename(handle, seuser, seuser_name);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not set sename for %s\n", login_name);
        ret = EIO;
        goto done;
    }

    ret = semanage_seuser_modify_local(handle, key, seuser);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not modify login mapping for %s\n", login_name);
        ret = EIO;
        goto done;
    }

    ret = EOK;
done:
    semanage_seuser_free(seuser);
    return ret;
}

int sss_seuser_exists(const char *linuxuser)
{
    int ret;
    int exists;
    semanage_seuser_key_t *sm_key = NULL;
    semanage_handle_t *sm_handle = NULL;

    ret = sss_semanage_init(&sm_handle);
    if (ret != EOK) {
        return ret;
    }

    ret = semanage_seuser_key_create(sm_handle, linuxuser, &sm_key);
    if (ret < 0) {
        sss_semanage_close(sm_handle);
        return EIO;
    }

    ret = semanage_seuser_exists(sm_handle, sm_key, &exists);
    semanage_seuser_key_free(sm_key);
    sss_semanage_close(sm_handle);
    if (ret < 0) {
        return EIO;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "seuser exists: %s\n", exists ? "yes" : "no");

    return exists ? EOK : ERR_SELINUX_USER_NOT_FOUND;
}

int sss_get_seuser(const char *linuxuser,
                   char **selinuxuser,
                   char **level)
{
    int ret;
    semanage_handle_t *handle;

    handle = semanage_handle_create();
    if (handle == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot create SELinux management handle\n");
        return EIO;
    }

    semanage_msg_set_callback(handle,
                              sss_semanage_error_callback,
                              NULL);

    /* We only needed the handle for this call. Close the handle right
     * after it */
    ret = sss_is_selinux_managed(handle);
    sss_semanage_close(handle);
    if (ret != EOK) {
        return ret;
    }

    return getseuserbyname(linuxuser, selinuxuser, level);
}

int sss_set_seuser(const char *login_name, const char *seuser_name,
                   const char *mls)
{
    semanage_handle_t *handle = NULL;
    semanage_seuser_key_t *key = NULL;
    int ret;
    int seuser_exists = 0;

    if (seuser_name == NULL) {
        /* don't care, just let system pick the defaults */
        return EOK;
    }

    ret = sss_semanage_init(&handle);
    if (ret == ERR_SELINUX_NOT_MANAGED) {
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot create SELinux handle\n");
        goto done;
    }

    ret = semanage_begin_transaction(handle);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot begin SELinux transaction\n");
        ret = EIO;
        goto done;
    }

    ret = semanage_seuser_key_create(handle, login_name, &key);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot create SELinux user key\n");
        ret = EIO;
        goto done;
    }

    ret = semanage_seuser_exists(handle, key, &seuser_exists);
    if (ret < 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot verify the SELinux user\n");
        ret = EIO;
        goto done;
    }

    if (seuser_exists) {
        ret = sss_semanage_user_mod(handle, key, login_name, seuser_name,
                                    mls);
        if (ret != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Cannot modify SELinux user mapping\n");
            ret = EIO;
            goto done;
        }
    } else {
        ret = sss_semanage_user_add(handle, key, login_name, seuser_name,
                                    mls);
        if (ret != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Cannot add SELinux user mapping\n");
            ret = EIO;
            goto done;
        }
    }

    ret = semanage_commit(handle);
    if (ret < 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot commit SELinux transaction\n");
        ret = EIO;
        goto done;
    }

    ret = EOK;
done:
    if (key != NULL) {
        semanage_seuser_key_free(key);
    }
    sss_semanage_close(handle);
    return ret;
}

int sss_del_seuser(const char *login_name)
{
    semanage_handle_t *handle = NULL;
    semanage_seuser_key_t *key = NULL;
    int ret;
    int exists = 0;

    ret = sss_semanage_init(&handle);
    if (ret == ERR_SELINUX_NOT_MANAGED) {
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot create SELinux handle\n");
        goto done;
    }

    ret = semanage_begin_transaction(handle);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot begin SELinux transaction\n");
        ret = EIO;
        goto done;
    }

    ret = semanage_seuser_key_create(handle, login_name, &key);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot create SELinux user key\n");
        ret = EIO;
        goto done;
    }

    ret = semanage_seuser_exists(handle, key, &exists);
    if (ret < 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot verify the SELinux user\n");
        ret = EIO;
        goto done;
    }

    if (!exists) {
        DEBUG(SSSDBG_FUNC_DATA,
              "Login mapping for %s is not defined, OK if default mapping "
                  "was used\n", login_name);
        ret = EOK;  /* probably default mapping */
        goto done;
    }

    ret = semanage_seuser_exists_local(handle, key, &exists);
    if (ret < 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot verify the SELinux user\n");
        ret = EIO;
        goto done;
    }

    if (!exists) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Login mapping for %s is defined in policy, cannot be deleted\n",
              login_name);
        ret = ENOENT;
        goto done;
    }

    ret = semanage_seuser_del_local(handle, key);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not delete login mapping for %s\n", login_name);
        ret = EIO;
        goto done;
    }

    ret = semanage_commit(handle);
    if (ret < 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot commit SELinux transaction\n");
        ret = EIO;
        goto done;
    }

    ret = EOK;
done:
    sss_semanage_close(handle);
    return ret;
}
#else /* HAVE_SEMANAGE && HAVE_SELINUX */
int sss_set_seuser(const char *login_name, const char *seuser_name,
                   const char *mls)
{
    return EOK;
}

int sss_del_seuser(const char *login_name)
{
    return EOK;
}

int sss_get_seuser(const char *linuxuser,
                   char **selinuxuser,
                   char **level)
{
    return EOK;
}
#endif  /* HAVE_SEMANAGE */
