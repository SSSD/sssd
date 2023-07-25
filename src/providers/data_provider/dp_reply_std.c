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

static const char *dp_err_to_string(int dp_err_type)
{
    switch (dp_err_type) {
    case DP_ERR_OK:
        return "Success";
    case DP_ERR_OFFLINE:
        return "Provider is Offline";
    case DP_ERR_TIMEOUT:
        return "Request timed out";
    case DP_ERR_FATAL:
        return "Internal Error";
    default:
        break;
    }

    return "Unknown Error";
}

static const char *safe_be_req_err_msg(const char *msg_in,
                                       int dp_err_type)
{
    bool ok;

    if (msg_in == NULL) {
        /* No custom error, just use default */
        return dp_err_to_string(dp_err_type);
    }

    ok = sss_utf8_check((const uint8_t *) msg_in,
                        strlen(msg_in));
    if (!ok) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Back end message [%s] contains invalid non-UTF8 character, " \
              "using default\n", msg_in);
        return dp_err_to_string(dp_err_type);
    }

    return msg_in;
}

void dp_req_reply_std(const char *request_name,
                      struct dp_reply_std *reply,
                      uint16_t *_dp_error,
                      uint32_t *_error,
                      const char **_message)
{
    const char *safe_err_msg;

    safe_err_msg = safe_be_req_err_msg(reply->message, reply->dp_error);

    DP_REQ_DEBUG(SSSDBG_TRACE_LIBS, request_name, "Returning [%s]: %d,%d,%s",
                 dp_err_to_string(reply->dp_error), reply->dp_error,
                 reply->error, reply->message);

    *_dp_error = reply->dp_error;
    *_error = reply->error;
    *_message = safe_err_msg;
}

void dp_reply_std_set(struct dp_reply_std *reply,
                      int dp_error,
                      int error,
                      const char *msg)
{
    const char *def_msg;

    if (dp_error == DP_ERR_DECIDE) {
        switch (error) {
        case EOK:
            dp_error = DP_ERR_OK;
            break;
        case ERR_OFFLINE:
            dp_error = DP_ERR_OFFLINE;
            break;
        case ETIMEDOUT:
            dp_error = DP_ERR_TIMEOUT;
            break;
        default:
            dp_error = DP_ERR_FATAL;
            break;
        }
    }

    switch (dp_error) {
    case DP_ERR_OK:
        def_msg = "Success";
        break;
    case DP_ERR_OFFLINE:
        def_msg = "Offline";
        break;
    default:
        def_msg = sss_strerror(error);
        break;
    }

    if (dp_error == DP_ERR_OK && error != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "DP Error is OK on failed request?\n");
    }

    reply->dp_error = dp_error;
    reply->error = error;
    reply->message = msg == NULL ? def_msg : msg;
}

errno_t dp_error_to_ret(errno_t ret, int dp_error)
{
    if (ret != EOK) {
        return ret;
    }

    switch (dp_error) {
    case DP_ERR_OK:
        return EOK;
    case DP_ERR_OFFLINE:
        return ERR_OFFLINE;
    case DP_ERR_TIMEOUT:
        return ETIMEDOUT;
    case DP_ERR_FATAL:
        return EFAULT;
    }

    return ERR_INTERNAL;
}
