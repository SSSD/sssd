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

#include "providers/backend.h"
#include "providers/data_provider/dp_private.h"
#include "providers/data_provider/dp.h"
#include "tests/cmocka/common_mock.h"

static struct dp_method *mock_dp_methods(TALLOC_CTX *mem_ctx)
{
    struct dp_method *methods;

    methods = talloc_zero_array(mem_ctx, struct dp_method,
                                DP_METHOD_SENTINEL + 1);
    assert_non_null(methods);

    return methods;
}

static struct dp_target **mock_dp_targets(TALLOC_CTX *mem_ctx)
{
    struct dp_target **targets;
    enum dp_targets type;

    targets = talloc_zero_array(mem_ctx, struct dp_target *,
                                DP_TARGET_SENTINEL + 1);
    assert_non_null(targets);

    for (type = 0; type != DP_TARGET_SENTINEL; type++) {
        targets[type] = talloc_zero(targets, struct dp_target);
        assert_non_null(targets[type]);

        targets[type]->name = dp_target_to_string(type);
        targets[type]->module_name = "test-module";
        targets[type]->module = NULL;
        targets[type]->methods = mock_dp_methods(targets[type]);
        targets[type]->initialized = true;
    }

    return targets;
}

struct data_provider *mock_dp(TALLOC_CTX *mem_ctx,
                              struct be_ctx *be_ctx)
{
    struct data_provider *provider;

    provider = talloc_zero(mem_ctx, struct data_provider);
    assert_non_null(provider);

    provider->ev = be_ctx->ev;
    provider->be_ctx = be_ctx;
    provider->terminating = false;
    provider->requests.index = 0;
    provider->requests.num_active = 0;
    provider->requests.active = NULL;
    provider->targets = mock_dp_targets(provider);
    provider->modules = NULL;

    be_ctx->provider = provider;

    return provider;
}

struct dp_method *mock_dp_get_methods(struct data_provider *provider,
                                      enum dp_targets target)
{
    struct dp_method *methods;

    assert_non_null(provider);
    assert_non_null(provider->targets);
    assert_non_null(provider->targets[target]);

    methods = provider->targets[target]->methods;
    assert_non_null(methods);

    return methods;
}

struct dp_req_params *mock_dp_req_params(TALLOC_CTX *mem_ctx,
                                         struct tevent_context *ev,
                                         struct be_ctx *be_ctx,
                                         struct sss_domain_info *domain,
                                         enum dp_targets target,
                                         enum dp_methods method)
{
    struct dp_req_params *params;

    params = talloc_zero(mem_ctx, struct dp_req_params);
    if (params == NULL) {
        return NULL;
    }

    params->ev = ev;
    params->be_ctx = be_ctx;
    params->domain = domain;
    params->target = target;
    params->method = method;

    return params;
}
