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

#include <tevent.h>

#include "providers/data_provider/dp_private.h"
#include "providers/backend.h"
#include "util/sss_utf8.h"
#include "util/util.h"

static const char *safe_be_req_err_msg(const char *msg_in,
                                       int error)
{
    bool ok;
    const char *def_msg;

    def_msg = sss_strerror(error);

    if (msg_in == NULL) {
        /* No custom error, just use default */
        return def_msg;
    }

    ok = sss_utf8_check((const uint8_t *) msg_in,
                        strlen(msg_in));
    if (!ok) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Back end message [%s] contains invalid non-UTF8 character, " \
              "using default\n", msg_in);
        return def_msg;
    }

    return msg_in;
}

void dp_req_reply_std(const char *request_name,
                      struct dp_reply_std *reply,
                      uint32_t *_error)
{
    const char *msg;

    msg = sss_strerror(*_error);

    DP_REQ_DEBUG(SSSDBG_TRACE_LIBS, request_name, "Returning [%d]: %s",
                 *_error, msg);

    *_error = reply->error;
    msg = reply->message;
}

void dp_req_reply_std_with_msg(const char *request_name,
                               struct dp_reply_std *reply,
                               uint32_t *_error,
                               const char **_message)
{
    const char *safe_err_msg;

    safe_err_msg = safe_be_req_err_msg(reply->message, reply->error);

    DP_REQ_DEBUG(SSSDBG_TRACE_LIBS, request_name, "Returning [%d]: %s",
                 reply->error, reply->message);

    *_error = reply->error;
    *_message = safe_err_msg;
}

void dp_reply_std_set(struct dp_reply_std *reply,
                      int error,
                      const char *msg)
{
    const char *def_msg;

    def_msg = sss_strerror(error);

    reply->error = error;
    reply->message = msg == NULL ? def_msg : msg;
}
