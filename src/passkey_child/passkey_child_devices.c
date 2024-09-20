/*
    SSSD

    Helper child to commmunicate with passkey devices

    Authors:
        Iker Pedrosa <ipedrosa@redhat.com>

    Copyright (C) 2022 Red Hat

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

#include "util/debug.h"
#include "util/util.h"

#include "passkey_child.h"

errno_t
list_devices(int timeout, fido_dev_info_t *dev_list, size_t *dev_number)
{
    errno_t ret;

    for (int i = 0; i < timeout; i += FREQUENCY) {
        ret = fido_dev_info_manifest(dev_list, DEVLIST_SIZE, dev_number);
        if (ret != FIDO_OK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Unable to discover device(s) [%d]: %s.\n",
                  ret, fido_strerr(ret));
        }

        if ((*dev_number) != 0) {
            DEBUG(SSSDBG_TRACE_FUNC, "Device found.\n");
            break;
        }

        if (i < (timeout - 1)) {
            DEBUG(SSSDBG_TRACE_FUNC, "No device available, retrying.\n");
            sleep(FREQUENCY);
        }
    }

    return ret;
}

errno_t
select_device(enum action_opt action, fido_dev_info_t *dev_list,
              size_t dev_list_len, fido_assert_t *assert,
              fido_dev_t **_dev)
{
    fido_dev_t *dev = NULL;
    const char *path;
    const fido_dev_info_t *di = NULL;
    errno_t ret;

    if (dev_list_len == 0) {
        DEBUG(SSSDBG_OP_FAILURE, "No device found. Aborting.\n");
        ret = ENOENT;
        goto done;
    } else if (action == ACTION_REGISTER && dev_list_len == 1) {
        dev = fido_dev_new();
        if (dev == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "fido_dev_new failed.\n");
            ret = ENOMEM;
            goto done;
        }

        di = fido_dev_info_ptr(dev_list, 0);
        if (di == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "fido_dev_info_ptr failed.\n");
            ret = ENOMEM;
            goto done;
        }

        path = fido_dev_info_path(di);
        if (path == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "fido_dev_info_path failed.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = fido_dev_open(dev, path);
        if (ret != FIDO_OK) {
            DEBUG(SSSDBG_OP_FAILURE, "fido_dev_open failed [%d]: %s.\n",
                  ret, fido_strerr(ret));
            goto done;
        }

        *_dev = dev;
    } else if (action == ACTION_REGISTER && dev_list_len > 1) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Only one device is supported at a time. Aborting.\n");
        fprintf(stderr, "Only one device is supported at a time. Aborting.\n");
        ret = EPERM;
        goto done;
    } else {
        if (assert == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "assert cannot be NULL.\n");
            ret = EINVAL;
            goto done;
        }

        ret = select_from_multiple_devices(dev_list, dev_list_len, assert, _dev);
        if (ret != FIDO_OK) {
            goto done;
        }
    }

    ret = EOK;

done:
    if (ret != EOK) {
        if (dev != NULL) {
            fido_dev_close(dev);
        }
        fido_dev_free(&dev);
    }

    return ret;
}

errno_t
select_from_multiple_devices(fido_dev_info_t *dev_list,
                             size_t dev_list_len,
                             fido_assert_t *assert,
                             fido_dev_t **_dev)
{
    fido_dev_t *dev = NULL;
    const fido_dev_info_t *di = NULL;
    const char *path;
    bool is_fido2;
    errno_t ret;

    DEBUG(SSSDBG_TRACE_FUNC,
          "Working with %ld authenticator(s).\n", dev_list_len);

    for (size_t i = 0; i < dev_list_len; i++) {
        dev = fido_dev_new();
        if (dev == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "fido_dev_new failed.\n");
            ret = ENOMEM;
            goto done;
        }

        di = fido_dev_info_ptr(dev_list, i);
        if (di == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "fido_dev_info_ptr failed.\n");
            ret = ENOMEM;
            goto done;
        }

        path = fido_dev_info_path(di);
        if (path == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "fido_dev_info_path failed.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = fido_dev_open(dev, path);
        if (ret != FIDO_OK) {
            DEBUG(SSSDBG_OP_FAILURE, "fido_dev_open failed [%d]: %s.\n",
                ret, fido_strerr(ret));
        }

        is_fido2 = fido_dev_is_fido2(dev);
        ret = fido_dev_get_assert(dev, assert, NULL);
        if ((is_fido2 == false && ret == FIDO_ERR_USER_PRESENCE_REQUIRED)
            || (is_fido2 == true && ret == FIDO_OK)) {
            *_dev = dev;
            DEBUG(SSSDBG_FUNC_DATA, "Assertion found in passkey %ld.\n", i);
            ret = EOK;
            goto done;
        }

        DEBUG(SSSDBG_FUNC_DATA, "Assertion not found in passkey %ld.\n", i);

        fido_dev_close(dev);
        fido_dev_free(&dev);
    }

    ret = FIDO_ERR_NOTFOUND;
    DEBUG(SSSDBG_OP_FAILURE, "Assertion not found.\n");

done:
    return ret;
}

errno_t
get_device_options(fido_dev_t *dev, struct passkey_data *_data)
{
    bool has_pin;
    bool has_uv;
    bool supports_uv;
    errno_t ret;

    has_uv = fido_dev_has_uv(dev);
    has_pin = fido_dev_has_pin(dev);
    supports_uv = fido_dev_supports_uv(dev);

    if (_data->user_verification == FIDO_OPT_TRUE && has_pin != true
        && has_uv != true) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Policy enabled user-verification but there isn't any "
              "verification method set.\n");
        ret = EINVAL;
        goto done;
    }

    if (_data->user_verification == FIDO_OPT_OMIT
        && (has_uv == true || has_pin == true)) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Policy didn't indicate any preference for user-verification "
              "but the key settings are enforcing it. Thus, enforcing the "
              "user-verification.\n");
        _data->user_verification = FIDO_OPT_TRUE;
        ret = EOK;
        goto done;
    }

    if (_data->user_verification == FIDO_OPT_FALSE
        && supports_uv == false) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Policy disabled user-verification but the key doesn't support "
              "it. Thus, omitting the user-verification.\n");
        _data->user_verification = FIDO_OPT_OMIT;
        ret = EOK;
        goto done;
    }

    ret = EOK;

done:

    return ret;
}
