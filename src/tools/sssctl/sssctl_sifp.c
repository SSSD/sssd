/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

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

#include <stdio.h>
#include <string.h>
#include <talloc.h>

#include "util/util.h"
#include "tools/sssctl/sssctl.h"

#define ERR_SSSD _("Check that SSSD is running and " \
                   "the InfoPipe responder is enabled. " \
                   "Make sure 'ifp' is listed in the " \
                   "'services' option in sssd.conf.\n")

struct sssctl_sifp_data {
    sss_sifp_ctx *sifp;
};

static int sssctl_sifp_data_destructor(struct sssctl_sifp_data *ctx)
{
    if (ctx->sifp != NULL) {
        sss_sifp_free(&ctx->sifp);
    }

    return 0;
}

static void *sssctl_sifp_talloc(size_t size, void *pvt)
{
    return talloc_size(pvt, size);
}

static void sssctl_sifp_talloc_free(void *ptr, void *pvt)
{
    talloc_free(ptr);
}

sss_sifp_error sssctl_sifp_init(struct sss_tool_ctx *tool_ctx,
                                sss_sifp_ctx **_sifp)
{
    struct sssctl_sifp_data *sifp_data;
    sss_sifp_error error;

    sifp_data = talloc_zero(tool_ctx, struct sssctl_sifp_data);
    if (sifp_data == NULL) {
        return SSS_SIFP_OUT_OF_MEMORY;
    }

    error = sss_sifp_init_ex(sifp_data, sssctl_sifp_talloc,
                             sssctl_sifp_talloc_free, &sifp_data->sifp);
    if (error != SSS_SIFP_OK) {
        *_sifp = sifp_data->sifp;
        return error;
    }

    talloc_set_destructor(sifp_data, sssctl_sifp_data_destructor);
    *_sifp = sifp_data->sifp;

    return SSS_SIFP_OK;
}

void _sssctl_sifp_error(sss_sifp_ctx *sifp,
                        sss_sifp_error error,
                        const char *message)
{
    const char *dbus_code;
    const char *dbus_msg;
    const char *sifp_msg;

    sifp_msg = sss_sifp_strerr(error);

    switch (error) {
    case SSS_SIFP_OK:
        break;
    case SSS_SIFP_IO_ERROR:
        dbus_code = sss_sifp_get_last_io_error_name(sifp);
        dbus_msg = sss_sifp_get_last_io_error_message(sifp);

        fprintf(stderr, "%s [%d]: %s\n", message, error, sifp_msg);
        fprintf(stderr, "%s: %s\n", dbus_code, dbus_msg);

        if (strcmp(dbus_code, DBUS_ERROR_SERVICE_UNKNOWN) == 0) {
            fprintf(stderr, ERR_SSSD);
            break;
        }

        if (strcmp(dbus_code, DBUS_ERROR_SPAWN_CHILD_EXITED) == 0) {
            fprintf(stderr, ERR_SSSD);
            break;
        }

        if (strcmp(dbus_code, DBUS_ERROR_NO_REPLY) == 0) {
            fprintf(stderr, ERR_SSSD);
            break;
        }

        break;
    default:
        fprintf(stderr, "%s [%d]: %s\n", message, error, sifp_msg);
        break;
    }
}

sss_sifp_error _sssctl_sifp_send(TALLOC_CTX *mem_ctx,
                                 sss_sifp_ctx *sifp,
                                 DBusMessage **_reply,
                                 const char *path,
                                 const char *iface,
                                 const char *method,
                                 int first_arg_type,
                                 ...)
{
    sss_sifp_error error;
    DBusMessage *msg;
    dbus_bool_t bret;
    errno_t ret;
    va_list va;

    msg = sss_sifp_create_message(path, iface, method);
    if (msg == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create D-Bus message\n");
        return SSS_SIFP_OUT_OF_MEMORY;
    }

    va_start(va, first_arg_type);
    bret = dbus_message_append_args_valist(msg, first_arg_type, va);
    va_end(va);
    if (!bret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to build message\n");
        error = SSS_SIFP_OUT_OF_MEMORY;
        goto done;
    }

    error = sss_sifp_send_message(sifp, msg, _reply);
    if (error != SSS_SIFP_OK) {
        goto done;
    }

    ret = sbus_talloc_bound_message(mem_ctx, *_reply);
    if (ret != EOK) {
        error = SSS_SIFP_OUT_OF_MEMORY;
        goto done;
    }

done:
    dbus_message_unref(msg);
    return error;
}
