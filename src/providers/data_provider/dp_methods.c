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

#include "config.h"
#include "providers/data_provider/dp.h"
#include "providers/data_provider/dp_private.h"
#include "providers/backend.h"
#include "util/util.h"

void _dp_set_method(struct dp_method *methods,
                    enum dp_methods method,
                    dp_req_send_fn send_fn,
                    dp_req_recv_fn recv_fn,
                    void *method_data,
                    const char *method_dtype,
                    const char *request_dtype,
                    const char *output_dtype,
                    uint32_t output_size)
{
    if (method >= DP_METHOD_SENTINEL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: invalid method %d\n", method);
        return;
    }

    /* Each method can be set only once, if we attempt to set it twice it
     * is a bug in module initialization. */
    if (methods[method].send_fn != NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: method %d is already set!\n", method);
        return;
    }

    if (send_fn == NULL || recv_fn == NULL || method_dtype == NULL
            || request_dtype == NULL || output_dtype == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: one or more required parameter was "
              "not provided for method %d\n", method);
        return;
    }

    methods[method].send_fn = send_fn;
    methods[method].recv_fn = recv_fn;
    methods[method].method_data = method_data;

    methods[method].method_dtype = method_dtype;
    methods[method].request_dtype = request_dtype;
    methods[method].output_dtype = output_dtype;
    methods[method].output_size = output_size;
}

bool dp_method_enabled(struct data_provider *provider,
                       enum dp_targets target,
                       enum dp_methods method)
{
    struct dp_target *dp_target;

    if (target >= DP_TARGET_SENTINEL || method >= DP_METHOD_SENTINEL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: Invalid target or method ID\n");
        return false;
    }

    if (provider == NULL || provider->targets == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, "Target %s is not yet initialized\n",
              dp_target_to_string(target));
        return false;
    }

    dp_target = provider->targets[target];
    if (dp_target == NULL || dp_target->initialized == false) {
        DEBUG(SSSDBG_TRACE_FUNC, "Target %s is not configured\n",
              dp_target_to_string(target));
        return false;
    }

    if (dp_target->methods[method].send_fn == NULL) {
        return false;
    }

    return true;
}

errno_t dp_find_method(struct data_provider *provider,
                       enum dp_targets target,
                       enum dp_methods method,
                       struct dp_method **_execute)
{
    struct dp_method *execute;

    if (target >= DP_TARGET_SENTINEL || method >= DP_METHOD_SENTINEL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: Invalid target or method ID\n");
        return ERR_INTERNAL;
    }

    if (!dp_target_initialized(provider->targets, target)) {
        DEBUG(SSSDBG_CONF_SETTINGS, "Target [%s] is not initialized\n",
              dp_target_to_string(target));
        return ERR_MISSING_DP_TARGET;
    }

    execute = &provider->targets[target]->methods[method];
    if (execute->send_fn == NULL || execute->recv_fn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Bug: Invalid combination of target [%s] and method [%d]\n",
              dp_target_to_string(target), method);
        return ERR_INTERNAL;
    }

    *_execute = execute;

    return EOK;
}
