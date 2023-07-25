/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2017 Red Hat

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

#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <talloc.h>
#include <dbus/dbus.h>

#include "util/util.h"
#include "util/sss_utf8.h"
#include "sss_iface/sss_iface_types.h"
#include "sbus/interface/sbus_iterator_readers.h"
#include "sbus/interface/sbus_iterator_writers.h"

/**
 * D-Bus signature: issssssuayuayiu
 */
errno_t sbus_iterator_read_pam_data(TALLOC_CTX *mem_ctx,
                                    DBusMessageIter *iterator,
                                    struct pam_data **_pd)
{
    struct pam_data *pd;
    uint32_t authtok_type;
    uint8_t *authtok_data;
    uint32_t new_authtok_type;
    uint8_t *new_authtok_data;
    errno_t ret;

    pd = create_pam_data(mem_ctx);
    if (pd == NULL) {
        return ENOMEM;
    }

    ret = sbus_iterator_read_i(iterator, &pd->cmd);
    if (ret != EOK) {
        goto done;
    }

    ret = sbus_iterator_read_S(pd, iterator, &pd->user);
    if (ret != EOK) {
        goto done;
    }

    ret = sbus_iterator_read_S(pd, iterator, &pd->domain);
    if (ret != EOK) {
        goto done;
    }

    ret = sbus_iterator_read_S(pd, iterator, &pd->service);
    if (ret != EOK) {
        goto done;
    }

    ret = sbus_iterator_read_S(pd, iterator, &pd->tty);
    if (ret != EOK) {
        goto done;
    }

    ret = sbus_iterator_read_S(pd, iterator, &pd->ruser);
    if (ret != EOK) {
        goto done;
    }

    ret = sbus_iterator_read_S(pd, iterator, &pd->rhost);
    if (ret != EOK) {
        goto done;
    }

    ret = sbus_iterator_read_u(iterator, &authtok_type);
    if (ret != EOK) {
        goto done;
    }

    ret = sbus_iterator_read_ay(pd, iterator, &authtok_data);
    if (ret != EOK) {
        goto done;
    }

    ret = sbus_iterator_read_u(iterator, &new_authtok_type);
    if (ret != EOK) {
        goto done;
    }

    ret = sbus_iterator_read_ay(pd, iterator, &new_authtok_data);
    if (ret != EOK) {
        goto done;
    }

    ret = sbus_iterator_read_i(iterator, &pd->priv);
    if (ret != EOK) {
        goto done;
    }

    ret = sbus_iterator_read_u(iterator, &pd->cli_pid);
    if (ret != EOK) {
        goto done;
    }

    ret = sbus_iterator_read_u(iterator, &pd->child_pid);
    if (ret != EOK) {
        goto done;
    }

    ret = sbus_iterator_read_u(iterator, &pd->client_id_num);
    if (ret != EOK) {
        goto done;
    }

    pd->authtok = sss_authtok_new(pd);
    if (pd->authtok == NULL) {
        ret = ENOMEM;
        goto done;
    }

    pd->newauthtok = sss_authtok_new(pd);
    if (pd->newauthtok == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_authtok_set(pd->authtok, authtok_type, authtok_data,
                          talloc_array_length(authtok_data));
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to set auth token [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = sss_authtok_set(pd->newauthtok, new_authtok_type, new_authtok_data,
                          talloc_array_length(new_authtok_data));
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to set auth token [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    *_pd = pd;

    ret = EOK;

done:
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to read pam data [%d]: %s\n",
              ret, sss_strerror(ret));
        talloc_free(pd);
    }

    return ret;
}

/**
 * D-Bus signature: issssssuayuayiu
 */
errno_t sbus_iterator_write_pam_data(DBusMessageIter *iterator,
                                     struct pam_data *pd)
{
    uint32_t authtok_type;
    uint8_t *authtok_data;
    int authtok_length;
    uint32_t new_authtok_type;
    uint8_t *new_authtok_data;
    int new_authtok_length;
    errno_t ret;

    authtok_type = (uint32_t)sss_authtok_get_type(pd->authtok);
    authtok_data = sss_authtok_get_data(pd->authtok);
    authtok_length = sss_authtok_get_size(pd->authtok);
    new_authtok_type = (uint32_t)sss_authtok_get_type(pd->newauthtok);
    new_authtok_data = sss_authtok_get_data(pd->newauthtok);
    new_authtok_length = sss_authtok_get_size(pd->newauthtok);

    ret = sbus_iterator_write_i(iterator, pd->cmd);
    if (ret != EOK) {
        goto done;
    }

    ret = sbus_iterator_write_S(iterator, pd->user);
    if (ret != EOK) {
        goto done;
    }

    ret = sbus_iterator_write_S(iterator, pd->domain);
    if (ret != EOK) {
        goto done;
    }

    ret = sbus_iterator_write_S(iterator, pd->service);
    if (ret != EOK) {
        goto done;
    }

    ret = sbus_iterator_write_S(iterator, pd->tty);
    if (ret != EOK) {
        goto done;
    }

    ret = sbus_iterator_write_S(iterator, pd->ruser);
    if (ret != EOK) {
        goto done;
    }

    ret = sbus_iterator_write_S(iterator, pd->rhost);
    if (ret != EOK) {
        goto done;
    }

    ret = sbus_iterator_write_u(iterator, authtok_type);
    if (ret != EOK) {
        goto done;
    }

    ret = sbus_iterator_write_basic_array_len(iterator, DBUS_TYPE_BYTE, uint8_t,
                                              authtok_data, authtok_length);
    if (ret != EOK) {
        goto done;
    }

    ret = sbus_iterator_write_u(iterator, new_authtok_type);
    if (ret != EOK) {
        goto done;
    }

    ret = sbus_iterator_write_basic_array_len(iterator, DBUS_TYPE_BYTE, uint8_t,
                                              new_authtok_data, new_authtok_length);
    if (ret != EOK) {
        goto done;
    }

    ret = sbus_iterator_write_i(iterator, pd->priv);
    if (ret != EOK) {
        goto done;
    }

    ret = sbus_iterator_write_u(iterator, pd->cli_pid);
    if (ret != EOK) {
        goto done;
    }

    ret = sbus_iterator_write_u(iterator, pd->child_pid);
    if (ret != EOK) {
        goto done;
    }

    ret = sbus_iterator_write_u(iterator, pd->client_id_num);
    if (ret != EOK) {
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to write pam data [%d]: %s\n",
              ret, sss_strerror(ret));
    }

    return ret;
}

/**
 * D-Bus signature: uua(uay)
 */
errno_t sbus_iterator_read_pam_response(TALLOC_CTX *mem_ctx,
                                        DBusMessageIter *iterator,
                                        struct pam_data **_pd)
{
    struct pam_data *pd;
    DBusMessageIter array_iter;
    DBusMessageIter struct_iter;
    uint32_t pam_status;
    uint32_t account_locked;
    uint32_t resp_type;
    uint8_t *resp_data;
    errno_t ret;
    int type;

    pd = create_pam_data(mem_ctx);
    if (pd == NULL) {
        return ENOMEM;
    }

    ret = sbus_iterator_read_u(iterator, &pam_status);
    if (ret != EOK) {
        goto done;
    }
    pd->pam_status = pam_status;

    ret = sbus_iterator_read_u(iterator, &account_locked);
    if (ret != EOK) {
        goto done;
    }
    pd->account_locked = account_locked;

    type = dbus_message_iter_get_arg_type(iterator);
    if (type != DBUS_TYPE_ARRAY) {
        ret = EINVAL;
        goto done;
    }

    type = dbus_message_iter_get_element_type(iterator);
    if (type != DBUS_TYPE_STRUCT) {
        ret = EINVAL;
        goto done;
    }

    dbus_message_iter_recurse(iterator, &array_iter);
    while (dbus_message_iter_get_arg_type(&array_iter) != DBUS_TYPE_INVALID) {
        type = dbus_message_iter_get_arg_type(&array_iter);
        if (type != DBUS_TYPE_STRUCT) {
            ret = EINVAL;
            goto done;
        }

        dbus_message_iter_recurse(&array_iter, &struct_iter);

        ret = sbus_iterator_read_u(&struct_iter, &resp_type);
        if (ret != EOK) {
            goto done;
        }

        ret = sbus_iterator_read_ay(pd, &struct_iter, &resp_data);
        if (ret != EOK) {
            goto done;
        }

        ret = pam_add_response(pd, resp_type, talloc_array_length(resp_data),
                               resp_data);
        if (ret != EOK) {
            goto done;
        }

        talloc_free(resp_data);

        dbus_message_iter_next(&array_iter);
    }

    *_pd = pd;

    ret = EOK;

done:
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to read pam data [%d]: %s\n",
              ret, sss_strerror(ret));
        talloc_free(pd);
    }

    return ret;
}

/**
 * D-Bus signature: uua(uay)
 */
errno_t sbus_iterator_write_pam_response(DBusMessageIter *iterator,
                                         struct pam_data *pd)
{
    struct response_data *resp;
    DBusMessageIter array_iter;
    DBusMessageIter struct_iter;
    dbus_bool_t dbret;
    errno_t ret;

    ret = sbus_iterator_write_u(iterator, pd->pam_status);
    if (ret != EOK) {
        goto done;
    }

    ret = sbus_iterator_write_u(iterator, pd->account_locked);
    if (ret != EOK) {
        goto done;
    }

    dbret = dbus_message_iter_open_container(iterator, DBUS_TYPE_ARRAY,
                                             "(uay)", &array_iter);
    if (!dbret) {
        ret = EIO;
        goto done;
    }

    for (resp = pd->resp_list; resp != NULL; resp = resp->next) {
        dbret = dbus_message_iter_open_container(&array_iter, DBUS_TYPE_STRUCT,
                                                 NULL, &struct_iter);
        if (!dbret) {
            ret = EIO;
            goto done;
        }

        ret = sbus_iterator_write_u(&struct_iter, resp->type);
        if (ret != EOK) {
            goto done;
        }

        ret = sbus_iterator_write_basic_array_len(&struct_iter, DBUS_TYPE_BYTE,
                                              uint8_t, resp->data, resp->len);
        if (ret != EOK) {
            goto done;
        }

        dbret = dbus_message_iter_close_container(&array_iter, &struct_iter);
        if (!dbret) {
            dbus_message_iter_abandon_container(&array_iter, &struct_iter);
            dbus_message_iter_abandon_container(iterator, &array_iter);
            ret = EIO;
            goto done;
        }
    }

    dbret = dbus_message_iter_close_container(iterator, &array_iter);
    if (!dbret) {
        dbus_message_iter_abandon_container(iterator, &array_iter);
        ret = EIO;
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to write pam response [%d]: %s\n",
              ret, sss_strerror(ret));
    }

    return ret;
}
