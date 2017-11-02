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

#include <talloc.h>
#include <tevent.h>
#include <dbus/dbus.h>

#include "sbus/sssd_dbus_errors.h"
#include "providers/data_provider/dp_private.h"
#include "providers/backend.h"
#include "util/dlinklist.h"
#include "util/sss_utf8.h"
#include "util/util.h"

void dp_req_reply_default(const char *req_name,
                          struct sbus_request *sbus_req,
                          void **data)
{
    DP_REQ_DEBUG(SSSDBG_TRACE_FUNC, req_name, "Replying with empty message");

    sbus_request_return_and_finish(sbus_req, DBUS_TYPE_INVALID);
}

static DBusError *dp_req_reply_gen_error(TALLOC_CTX *mem_ctx,
                                         const char *req_name,
                                         errno_t ret)
{
    DBusError *error;

    switch (ret) {
    case EOK:
        DP_REQ_DEBUG(SSSDBG_CRIT_FAILURE, req_name,
                     "Bug: Success case must be handled by custom handler.");
        error = sbus_error_new(mem_ctx, SBUS_ERROR_INTERNAL,
                     "Operation succeeded but result was not handled");
        break;
    case ERR_OFFLINE:
        DP_REQ_DEBUG(SSSDBG_MINOR_FAILURE, req_name,
                     "Finished. Backend is currently offline.");

        error = sbus_error_new(mem_ctx, SBUS_ERROR_DP_OFFLINE,
                     "Backend is currently offline");
        break;
    case ERR_MISSING_DP_TARGET:
        DP_REQ_DEBUG(SSSDBG_MINOR_FAILURE, req_name,
                     "Finished. Target is not supported "
                     "with this configuration.");

        error = sbus_error_new(mem_ctx, SBUS_ERROR_DP_NOTSUP,
                     "Target is not supported.");
        break;
    default:
        DP_REQ_DEBUG(SSSDBG_CRIT_FAILURE, req_name,
                     "Finished. Error [%d]: %s", ret, sss_strerror(ret));

        error = sbus_error_new(mem_ctx, SBUS_ERROR_DP_FATAL,
                     "An error occurred [%d]: %s", ret, sss_strerror(ret));
        break;
    }

    return error;
}

void dp_req_reply_error(struct sbus_request *sbus_req,
                        const char *req_name,
                        errno_t ret)
{
    DBusError *error;

    error = dp_req_reply_gen_error(sbus_req, req_name, ret);
    if (error == NULL) {
        DP_REQ_DEBUG(SSSDBG_CRIT_FAILURE, req_name,
                     "Out of memory, killing request...");
        talloc_free(sbus_req);
        return;
    }

    sbus_request_fail_and_finish(sbus_req, error);
}

static void dp_req_reply_list_error(struct dp_sbus_req_item *list,
                                    const char *req_name,
                                    errno_t ret)
{
    struct dp_sbus_req_item *next_item;
    struct dp_sbus_req_item *item;
    DBusError *error;

    error = dp_req_reply_gen_error(NULL, req_name, ret);
    if (error == NULL) {
        DP_REQ_DEBUG(SSSDBG_CRIT_FAILURE, req_name,
                     "Out of memory, killing request...");

        for (item = list; item != NULL; item = next_item) {
            next_item = item->next;
            talloc_free(item->sbus_req);
        }

        return;
    }

    for (item = list; item != NULL; item = next_item) {
        next_item = item->next;
        sbus_request_fail_and_finish(item->sbus_req, error);
    }

    talloc_free(error);
    return;
}

static void dp_req_reply_list_success(struct dp_sbus_req_item *list,
                                      dp_req_reply_fn reply_fn,
                                      const char *request_name,
                                      void *output_data)
{
    struct dp_sbus_req_item *next_item;
    struct dp_sbus_req_item *item;

    DP_REQ_DEBUG(SSSDBG_TRACE_FUNC, request_name, "Finished. Success.");

    for (item = list; item != NULL; item = next_item) {
        next_item = item->next;
        reply_fn(request_name, item->sbus_req, output_data);
    }
}

struct dp_req_with_reply_state {
    struct data_provider *provider;

    void *postprocess_data;
    dp_req_post_fn postprocess_fn;

    const char *output_dtype;
    dp_req_reply_fn reply_fn;
    const char *key;
    const char *name;
};

static errno_t dp_req_with_reply_step(struct data_provider *provider,
                                      struct dp_client *dp_cli,
                                      const char *domain,
                                      const char *request_name,
                                      const char *custom_key,
                                      struct sbus_request *sbus_req,
                                      enum dp_targets target,
                                      enum dp_methods method,
                                      uint32_t dp_flags,
                                      void *request_data,
                                      dp_req_post_fn postprocess_fn,
                                      void *postprocess_data,
                                      dp_req_reply_fn reply_fn,
                                      const char *output_dtype);

static void dp_req_with_reply_done(struct tevent_req *req);

void _dp_req_with_reply(struct dp_client *dp_cli,
                        const char *domain,
                        const char *request_name,
                        const char *custom_key,
                        struct sbus_request *sbus_req,
                        enum dp_targets target,
                        enum dp_methods method,
                        uint32_t dp_flags,
                        void *request_data,
                        dp_req_post_fn postprocess_fn,
                        void *postprocess_data,
                        dp_req_reply_fn reply_fn,
                        const char *output_dtype)
{
    TALLOC_CTX *tmp_ctx;
    struct data_provider *provider;
    const char *key;
    bool has_key;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    provider = dp_client_provider(dp_cli);

    if (custom_key == NULL) {
        /* It may not be always possible or desirable to have a meaningful key
         * to chain sbus request. In such cases, we generate a unique key from
         * sbus_req address that allows us to use the same code but the
         * chaining is logically disabled. */
        custom_key = talloc_asprintf(tmp_ctx, "%p", sbus_req);
        if (custom_key == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    key = dp_req_table_key(tmp_ctx, target, method, dp_flags, custom_key);
    if (key == NULL) {
        ret = ENOMEM;
        goto done;
    }

    has_key = dp_req_table_has_key(provider->requests.reply_table, key);
    if (has_key) {
        ret = dp_req_table_add(provider->requests.reply_table,
                               key, NULL, sbus_req);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to attach sbus request to "
                  "existing data provider request [%d]: %s\n",
                  ret, sss_strerror(ret));
            goto done;
        }

        DEBUG(SSSDBG_TRACE_FUNC, "Attaching to DP request: %s\n", key);

        ret = EOK;
        goto done;
    }

    ret = dp_req_with_reply_step(provider, dp_cli, domain, request_name, key,
                                 sbus_req, target, method, dp_flags,
                                 request_data, postprocess_fn, postprocess_data,
                                 reply_fn, output_dtype);

done:
    if (ret == ENOMEM) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to allocate memory for "
              "new DP request, killing D-Bus request...\n");
        talloc_zfree(sbus_req);
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to initialize "
              "DP request [%d: %s], killing D-Bus request...\n",
              ret, sss_strerror(ret));
        talloc_zfree(sbus_req);
    }

    talloc_free(tmp_ctx);
}

static errno_t dp_req_with_reply_step(struct data_provider *provider,
                                      struct dp_client *dp_cli,
                                      const char *domain,
                                      const char *request_name,
                                      const char *custom_key,
                                      struct sbus_request *sbus_req,
                                      enum dp_targets target,
                                      enum dp_methods method,
                                      uint32_t dp_flags,
                                      void *request_data,
                                      dp_req_post_fn postprocess_fn,
                                      void *postprocess_data,
                                      dp_req_reply_fn reply_fn,
                                      const char *output_dtype)
{
    TALLOC_CTX *tmp_ctx;
    struct dp_req_with_reply_state *state;
    struct tevent_req *req;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    state = talloc_zero(tmp_ctx, struct dp_req_with_reply_state);
    if (state == NULL) {
        ret = ENOMEM;
        goto done;
    }

    state->provider = provider;
    state->reply_fn = reply_fn;
    state->key = talloc_strdup(state, custom_key);
    if (state->key == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (postprocess_fn != NULL) {
        state->postprocess_data = postprocess_data;
        state->postprocess_fn = postprocess_fn;
    }

    state->output_dtype = talloc_strdup(state, output_dtype);
    if (state->output_dtype == NULL) {
        ret = ENOMEM;
        goto done;
    }

    req = dp_req_send(tmp_ctx, provider, dp_cli, domain, request_name, target,
                      method, dp_flags, request_data, &state->name);
    if (req == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = dp_req_table_add(provider->requests.reply_table,
                           custom_key, req, sbus_req);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to add request to table "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    tevent_req_set_callback(req, dp_req_with_reply_done, state);

    talloc_steal(provider, req);
    talloc_steal(req, state);
    talloc_steal(state, state->name);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static void dp_req_with_reply_done(struct tevent_req *req)
{
    struct dp_req_with_reply_state *state;
    struct dp_table_value *value;
    void *output_data;
    errno_t ret;

    state = tevent_req_callback_data(req, struct dp_req_with_reply_state);

    value = dp_req_table_lookup(state->provider->requests.reply_table,
                                state->key);
    if (value == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to lookup table!\n");
        return;
    }

    ret = _dp_req_recv(state, req, state->output_dtype, &output_data);
    if (ret != EOK) {
        dp_req_reply_list_error(value->list, state->name, ret);
        goto done;
    }

    /* Run postprocess function if any. */
    if (state->postprocess_fn != NULL) {
        state->postprocess_fn(state->name,
                              state->provider,
                              state->postprocess_data,
                              output_data);
    }

    /* Reply with data. */
    dp_req_reply_list_success(value->list, state->reply_fn,
                              state->name, output_data);

done:
    /* Freeing value will remove it from the table as well. */
    talloc_free(value);
    talloc_free(req);
}
