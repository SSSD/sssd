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

#ifndef _SBUS_REQUEST_H_
#define _SBUS_REQUEST_H_

#include <stdint.h>
#include <talloc.h>
#include <tevent.h>

#include "util/util_errors.h"
#include "sbus/sbus_opath.h"

struct sbus_connection;

/**
 * There are several cases when the sender id cannot be resolved but the
 * messages it self are valid. We use special uid values to distinguish
 * between those cases.
 */

/**
 * Sender is a message bus: org.freedesktop.dbus
 */
#define SBUS_SENDER_DBUS  -1

/**
 * This is a hello message that is used to estahblished a communication
 * channel. It is not possible to resolve the sender id at this point.
 */
#define SBUS_SENDER_HELLO -2

/**
 * The message is a signal and the sender has already quit before we
 * managed to process it. Therefore it is not possible to resolve the
 * send id.
 */
#define SBUS_SENDER_SIGNAL -3

/**
 * Identity of remote client who initiated this request.
 */
struct sbus_sender {
    /**
     * D-Bus name.
     */
    const char *name;

    /**
     * Unix user id.
     */
    int64_t uid;
};

enum sbus_request_type {
    SBUS_REQUEST_METHOD,
    SBUS_REQUEST_SIGNAL,
    SBUS_REQUEST_PROPERTY_GET,
    SBUS_REQUEST_PROPERTY_SET
};

/**
 * An sbus request data passed to the method, signal or property handler.
 */
struct sbus_request {
    struct sbus_connection *conn;

    enum sbus_request_type type;

    /**
     * Identity of remote client who initiated this request.
     */
    const struct sbus_sender *sender;

    /**
     * Request destination name.
     */
    const char *destination;

    /**
     * An sbus interface name.
     */
    const char *interface;

    /**
     * An sbus member name, depending on type
     * it is method, signal or property name.
     */
    union {
        const char *method;
        const char *signal_name;
        const char *property;
        const char *member;
    };

    /**
     * Object path of an sbus object.
     */
    const char *path;
};

/**
 * Await a finish of an outgoing sbus request.
 *
 * Sometimes you want to proceed with an operation only if a specific request
 * is not in progress. This function will create a new tevent request that
 * will either finish successfully (EOK) if outgoing request described with
 * @key is not in progress or it will await its finish and return its result.
 *
 * @param mem_ctx           Memory context.
 * @param conn              An sbus connection.
 * @param type              Type of the sbus request.
 * @param object_path       Object path on which the request is executed.
 * @param interface         Interface of the request.
 * @param member            Either method or property name, depends on @type.
 * @param additional_key    Additional key that identifies the request.
 *
 * @return Tevent request or NULL on error.
 */
struct tevent_req *
sbus_request_await_send(TALLOC_CTX *mem_ctx,
                        struct sbus_connection *conn,
                        enum sbus_request_type type,
                        const char *object_path,
                        const char *interface,
                        const char *member,
                        const char *additional_key);

/**
 * Receive result of @sbus_request_await_send.
 *
 * @return EOK on success, other errno code on failure.
 */
errno_t sbus_request_await_recv(struct tevent_req *req);

/**
 * This is a tevent req callback for messages where the caller is not
 * interested in the reply. Usage:
 *
 * tevent_req_set_callback(subreq, sbus_unwanted_reply, NULL);
 */
void sbus_unwanted_reply(struct tevent_req *subreq);

/**
 * It is not possible to send NULL over D-Bus as a string, but if the code
 * allows it, we can treat an empty string as NULL.
 */
#define SBUS_REQ_STRING_IS_EMPTY(str) ((str) == NULL || (str)[0] == '\0')
#define SBUS_REQ_STRING_DEFAULT(str, def) (SBUS_REQ_STRING_IS_EMPTY(str) ? (def) : (str))
#define SBUS_REQ_STRING(str) (SBUS_REQ_STRING_IS_EMPTY(str) ? NULL : (str))

#endif /* _SBUS_REQUEST_H_ */
