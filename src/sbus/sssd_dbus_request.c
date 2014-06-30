/*
    Authors:
        Stef Walter <stefw@redhat.com>

    Copyright (C) 2014 Red Hat

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

#include "util/util.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_private.h"

#include <sys/time.h>
#include <dbus/dbus.h>

#define INTERNAL_ERROR "Internal Error"

static int sbus_request_destructor(struct sbus_request *dbus_req)
{
    dbus_message_unref(dbus_req->message);
    return 0;
}

struct sbus_request *
sbus_new_request(struct sbus_connection *conn,
                 struct sbus_interface *intf,
                 DBusMessage *message)
{
    struct sbus_request *dbus_req;

    dbus_req = talloc_zero(conn, struct sbus_request);
    if (!dbus_req) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory allocating DBus request\n");
        return NULL;
    }

    dbus_req->intf = intf;
    dbus_req->conn = conn;
    dbus_req->message = dbus_message_ref(message);
    talloc_set_destructor(dbus_req, sbus_request_destructor);

    return dbus_req;
}

void
sbus_request_invoke_or_finish(struct sbus_request *dbus_req,
                              sbus_msg_handler_fn handler_fn,
                              void *handler_data,
                              sbus_method_invoker_fn invoker_fn)
{
    DBusError error;
    int ret;

    if (invoker_fn != NULL) {
        ret = invoker_fn(dbus_req, handler_fn);
    } else if (handler_fn != NULL) {
        ret = handler_fn(dbus_req, handler_data);
    } else {
        ret = EINVAL;
    }

    switch(ret) {
    case EOK:
        return;
    case ENOMEM:
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory handling DBus message\n");
        sbus_request_finish(dbus_req, NULL);
        break;
    default:
        dbus_set_error_const(&error, DBUS_ERROR_FAILED, INTERNAL_ERROR);
        sbus_request_fail_and_finish(dbus_req, &error);
        break;
    }
}

int sbus_request_finish(struct sbus_request *dbus_req,
                        DBusMessage *reply)
{
    if (reply) {
        sbus_conn_send_reply(dbus_req->conn, reply);
    }
    return talloc_free(dbus_req);
}

int sbus_request_return_and_finish(struct sbus_request *dbus_req,
                                   int first_arg_type,
                                   ...)
{
    DBusMessage *reply;
    dbus_bool_t dbret;
    va_list va;
    int ret;

    reply = dbus_message_new_method_return(dbus_req->message);
    if (!reply) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory allocating DBus message\n");
        sbus_request_finish(dbus_req, NULL);
        return ENOMEM;
    }

    va_start(va, first_arg_type);
    dbret = dbus_message_append_args_valist(reply, first_arg_type, va);
    va_end(va);

    if (dbret) {
        ret = sbus_request_finish(dbus_req, reply);

    } else {
        DEBUG(SSSDBG_CRIT_FAILURE, "Couldn't build DBus message\n");
        sbus_request_finish(dbus_req, NULL);
        ret = EINVAL;
    }

    dbus_message_unref(reply);
    return ret;
}

int sbus_request_return_as_variant(struct sbus_request *dbus_req,
                                   int type,
                                   const void *value)
{
    DBusMessage *reply;
    dbus_bool_t dbret;
    DBusMessageIter iter;
    DBusMessageIter valiter;
    char strtype[2];
    int ret;

    snprintf(strtype, 2, "%c", type);

    reply = dbus_message_new_method_return(dbus_req->message);
    if (reply == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory allocating DBus message\n");
        sbus_request_finish(dbus_req, NULL);
        return ENOMEM;
    }

    dbus_message_iter_init_append(reply, &iter);
    dbret = dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
                                             strtype, &valiter);
    if (!dbret) {
        sbus_request_fail_and_finish(
                            dbus_req,
                            sbus_error_new(dbus_req,
                                        DBUS_ERROR_FAILED,
                                        "Could not open variant for [%s]\n",
                                        strtype));
        ret = EINVAL;
        goto done;
    }

    dbret = dbus_message_iter_append_basic(&valiter, type, value);
    if (!dbret) {
        sbus_request_fail_and_finish(
                            dbus_req,
                            sbus_error_new(dbus_req,
                                        DBUS_ERROR_FAILED,
                                        "Could not append [%s] to variant\n",
                                        strtype));
        ret = EINVAL;
        goto done;
    }

    dbret = dbus_message_iter_close_container(&iter, &valiter);
    if (dbret) {
        ret = sbus_request_finish(dbus_req, reply);
    } else {
        sbus_request_fail_and_finish(
                            dbus_req,
                            sbus_error_new(dbus_req,
                                        DBUS_ERROR_FAILED,
                                        "Could not close variant\n"));
        ret = EINVAL;
    }

done:
    dbus_message_unref(reply);
    return ret;
}


int sbus_request_return_array_as_variant(struct sbus_request *dbus_req,
                                         int type,
                                         uint8_t *values,
                                         const int len,
                                         const size_t item_size)
{
    TALLOC_CTX *tmp_ctx = NULL;
    DBusMessage *reply = NULL;
    dbus_bool_t dbret;
    DBusMessageIter iter;
    DBusMessageIter variant_iter;
    DBusMessageIter array_iter;
    char *variant_type = NULL;
    char *array_type = NULL;
    void *addr = NULL;
    int ret;
    int i;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    variant_type = talloc_asprintf(tmp_ctx, DBUS_TYPE_ARRAY_AS_STRING "%c",
                                   type);
    if (variant_type == NULL) {
        ret = ENOMEM;
        goto done;
    }

    array_type = talloc_asprintf(tmp_ctx, "%c", type);
    if (array_type == NULL) {
        ret = ENOMEM;
        goto done;
    }

    reply = dbus_message_new_method_return(dbus_req->message);
    if (reply == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory allocating DBus message\n");
        sbus_request_finish(dbus_req, NULL);
        ret = ENOMEM;
        goto done;
    }

    dbus_message_iter_init_append(reply, &iter);
    dbret = dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
                                             variant_type, &variant_iter);
    if (!dbret) {
        sbus_request_fail_and_finish(
                            dbus_req,
                            sbus_error_new(dbus_req,
                                        DBUS_ERROR_FAILED,
                                        "Could not open variant for [%s]\n",
                                        variant_type));
        ret = EINVAL;
        goto done;
    }

    /* Open container for values */
    dbret = dbus_message_iter_open_container(&variant_iter, DBUS_TYPE_ARRAY,
                                             array_type, &array_iter);
    if (!dbret) {
        sbus_request_fail_and_finish(
                            dbus_req,
                            sbus_error_new(dbus_req,
                                        DBUS_ERROR_FAILED,
                                        "Could not open array for [%s]\n",
                                        array_type));
        ret = EINVAL;
        goto done;
    }

    for (i = 0; i < len; i++) {
        addr = values + i * item_size;
        dbret = dbus_message_iter_append_basic(&array_iter, type, addr);
        if (!dbret) {
            sbus_request_fail_and_finish(
                                dbus_req,
                                sbus_error_new(dbus_req,
                                            DBUS_ERROR_FAILED,
                                            "Could not append [%s] to variant\n",
                                            array_type));
            ret = EINVAL;
            goto done;
        }
    }

    dbret = dbus_message_iter_close_container(&variant_iter, &array_iter);
    if (!dbret) {
        sbus_request_fail_and_finish(
                            dbus_req,
                            sbus_error_new(dbus_req,
                                        DBUS_ERROR_FAILED,
                                        "Could not close array\n"));
        ret = EINVAL;
    }

    dbret = dbus_message_iter_close_container(&iter, &variant_iter);
    if (dbret) {
        ret = sbus_request_finish(dbus_req, reply);
    } else {
        sbus_request_fail_and_finish(
                            dbus_req,
                            sbus_error_new(dbus_req,
                                        DBUS_ERROR_FAILED,
                                        "Could not close variant\n"));
        ret = EINVAL;
    }

done:
    if (reply != NULL) {
        dbus_message_unref(reply);
    }

    talloc_free(tmp_ctx);
    return ret;
}

int sbus_request_fail_and_finish(struct sbus_request *dbus_req,
                                 const DBusError *error)
{
    DBusMessage *reply;
    int ret;

    if (error == NULL) {
        sbus_request_finish(dbus_req, NULL);
        return ENOMEM;
    }

    reply = dbus_message_new_error(dbus_req->message, error->name, error->message);
    if (!reply) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory allocating DBus message\n");
        sbus_request_finish(dbus_req, NULL);
        return ENOMEM;
    }

    ret = sbus_request_finish(dbus_req, reply);
    dbus_message_unref(reply);
    return ret;
}

DBusError *sbus_error_new(TALLOC_CTX *mem_ctx,
                          const char *dbus_err_name,
                          const char *fmt,
                          ...)
{
    DBusError *dberr;
    const char *err_msg_dup = NULL;
    va_list ap;

    dberr = talloc(mem_ctx, DBusError);
    if (dberr == NULL) return NULL;

    if (fmt) {
        va_start(ap, fmt);
        err_msg_dup = talloc_vasprintf(dberr, fmt, ap);
        va_end(ap);
        if (err_msg_dup == NULL) {
            talloc_free(dberr);
            return NULL;
        }
    }

    dbus_error_init(dberr);
    dbus_set_error_const(dberr, dbus_err_name, err_msg_dup);
    return dberr;
}

struct array_arg {
    char **dbus_array;
};

static int array_arg_destructor(struct array_arg *arg)
{
    dbus_free_string_array(arg->dbus_array);
    return 0;
}

static bool
parent_dbus_string_arrays(struct sbus_request *request, int first_arg_type,
                          va_list va)
{
    struct array_arg *array_arg;
    int arg_type;
    void **arg_ptr;

    /*
     * Here we iterate through the entire thing again and look for
     * things we need to fix allocation for. Normally certain types
     * returned from dbus_message_get_args() and friends require
     * later freeing. We tie those to the talloc context here.
     *
     * The list of argument has already been validated by the previous
     * dbus_message_get_args() call, so we can be cheap.
     */

    arg_type = first_arg_type;
    while (arg_type != DBUS_TYPE_INVALID) {

        if (arg_type == DBUS_TYPE_ARRAY) {
            arg_type = va_arg(va, int);     /* the array element type */
            arg_ptr = va_arg(va, void **);  /* the array elements */
            va_arg(va, int *);              /* the array length */

            /* Arrays of these things need to be freed */
            if (arg_type == DBUS_TYPE_STRING ||
                arg_type == DBUS_TYPE_OBJECT_PATH ||
                arg_type == DBUS_TYPE_SIGNATURE) {

                array_arg = talloc_zero(request, struct array_arg);
                if (array_arg == NULL) {
                    /* no kidding ... */
                    DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory while trying not to leak memory\n");
                    return false;
                }

                array_arg->dbus_array = *arg_ptr;
                talloc_set_destructor(array_arg, array_arg_destructor);
            }

        /* A non array argument */
        } else {
            arg_ptr = va_arg(va, void**);
        }

        /* The next type */
        arg_type = va_arg(va, int);
    }

    return true;
}

bool
sbus_request_parse_or_finish(struct sbus_request *request,
                             int first_arg_type,
                             ...)
{
    DBusError error = DBUS_ERROR_INIT;
    bool ret = true;
    va_list va2;
    va_list va;

    va_start(va, first_arg_type);
    va_copy(va2, va);

    if (dbus_message_get_args_valist(request->message, &error,
                                     first_arg_type, va)) {
        ret = parent_dbus_string_arrays(request, first_arg_type, va2);

    } else {
        /* Trying to send the error back to the caller in this case is a joke */
        if (!dbus_error_is_set(&error) &&
                dbus_error_has_name(&error, DBUS_ERROR_NO_MEMORY)) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory parsing DBus message\n");
            sbus_request_finish(request, NULL);

        /* Log other errors and send them back, this include o.f.d.InvalidArgs */
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "Couldn't parse DBus message %s.%s: %s\n",
                  dbus_message_get_interface(request->message),
                  dbus_message_get_member(request->message),
                  error.message);
            sbus_request_fail_and_finish(request, &error);
        }

        dbus_error_free(&error);
        ret = false;
    }

    va_end(va2);
    va_end(va);

    return ret;
}

struct sbus_get_sender_id_state {
    struct sbus_connection *conn;
    DBusConnection *sysbus_conn;
    char *sender;
    int64_t uid;
};

static void sbus_get_sender_id_done(DBusPendingCall *pending, void *ptr);

struct tevent_req *sbus_get_sender_id_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           struct sbus_connection *conn,
                                           const char *sender)
{
    struct tevent_req *req;
    struct sbus_get_sender_id_state *state;
    DBusError dbus_error;
    DBusMessage *msg = NULL;
    dbus_bool_t dbret;
    errno_t ret;
    hash_key_t key;
    hash_value_t value;

    req = tevent_req_create(mem_ctx, &state, struct sbus_get_sender_id_state);
    if (req == NULL) {
        return NULL;
    }
    state->conn = conn;
    state->uid = -1;

    if (conn->connection_type != SBUS_CONN_TYPE_SYSBUS) {
        DEBUG(SSSDBG_TRACE_INTERNAL, "Not a sysbus message, quit\n");
        ret = EOK;
        goto immediate;
    }

    if (sender == NULL) {
        ret = ERR_SBUS_NO_SENDER;
        goto immediate;
    }

    state->sender = talloc_strdup(state, sender);
    if (state->sender == NULL) {
        ret = ENOMEM;
        goto immediate;
    }

    key.type = HASH_KEY_STRING;
    key.str = discard_const(sender);
    ret = hash_lookup(conn->clients, &key, &value);
    if (ret == HASH_SUCCESS) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "%s already present in the clients table\n", sender);
        state->uid = (int64_t) value.ul;
        ret = EOK;
        goto immediate;
    } else if (ret != HASH_ERROR_KEY_NOT_FOUND) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to look up %s in the clients table\n", sender);
        ret = ERR_SBUS_GET_SENDER_ERROR;
        goto immediate;
    }

    /* We don't know this sender yet, let's ask the system bus */

    /* Connect to the well-known system bus */
    dbus_error_init(&dbus_error);
    state->sysbus_conn = dbus_bus_get(DBUS_BUS_SYSTEM, &dbus_error);
    if (state->sysbus_conn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to connect to D-BUS system bus.\n");
        ret = ERR_SBUS_GET_SENDER_ERROR;
        goto immediate;
    }
    dbus_connection_set_exit_on_disconnect(state->sysbus_conn, FALSE);

    /* If we ever need to get the SELinux context or the PID here, we need
     * to call GetConnectionCredentials instead
     */
    msg = dbus_message_new_method_call("org.freedesktop.DBus",  /* bus name */
                                       "/org/freedesktop/DBus", /* path */
                                       "org.freedesktop.DBus",  /* interface */
                                       "GetConnectionUnixUser");
    if (msg == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory?!\n");
        ret = ENOMEM;
        goto immediate;
    }

    dbret = dbus_message_append_args(msg,
                                     DBUS_TYPE_STRING, &sender,
                                     DBUS_TYPE_INVALID);
    if (!dbret) {
        goto immediate;
    }

    ret = sss_dbus_conn_send(state->sysbus_conn, msg, 3000,
                             sbus_get_sender_id_done,
                             req, NULL);
    dbus_message_unref(msg);
    msg = NULL;
    if (ret != EOK) {
        goto immediate;
    }

    return req;

immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        if (msg != NULL) {
            dbus_message_unref(msg);
        }
        if (state->sysbus_conn != NULL) {
            dbus_connection_unref(state->sysbus_conn);
        }
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

static void sbus_get_sender_id_done(DBusPendingCall *pending, void *ptr)
{
    struct tevent_req *req;
    struct sbus_get_sender_id_state *state;
    DBusMessage *reply;
    DBusError dbus_error;
    hash_key_t key;
    hash_value_t value;
    dbus_bool_t dbret;
    int ret;
    uid_t uid;

    dbus_error_init(&dbus_error);

    req = talloc_get_type(ptr, struct tevent_req);
    state = tevent_req_data(req, struct sbus_get_sender_id_state);

    reply = dbus_pending_call_steal_reply(pending);
    if (!reply) {
        /* reply should never be null. This function shouldn't be called
         * until reply is valid or timeout has occurred. If reply is NULL
         * here, something is seriously wrong and we should bail out.
         */
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Severe error. A reply callback was called but no reply "
               "was received and no timeout occurred\n");

        ret = EIO;
        goto done;
    }

    dbret = dbus_message_get_args(reply,
                                  &dbus_error,
                                  DBUS_TYPE_UINT32, &uid,
                                  DBUS_TYPE_INVALID);
    if (!dbret) {
        ret = EIO;
        goto done;
    }

    state->uid = uid;

    key.type = HASH_KEY_STRING;
    key.str = talloc_steal(state->conn->clients, state->sender);
    value.type = HASH_VALUE_UINT;
    value.ul = state->uid;
    ret = hash_enter(state->conn->clients, &key, &value);
    if (ret != HASH_SUCCESS) {
        ret = EIO;
        goto done;
    }

    ret = EOK;
done:
    dbus_pending_call_unref(pending);
    dbus_message_unref(reply);
    dbus_connection_unref(state->sysbus_conn);
    if (ret != EOK) {
        tevent_req_error(req, ret);
    } else {
        tevent_req_done(req);
    }
}

int sbus_get_sender_id_recv(struct tevent_req *req, int64_t *_uid)
{
    struct sbus_get_sender_id_state *state = \
                        tevent_req_data(req, struct sbus_get_sender_id_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (_uid) {
        *_uid = state->uid;
    }

    return EOK;
}
