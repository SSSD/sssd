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
#include <dlfcn.h>

#include "config.h"
#include "providers/data_provider/dp.h"
#include "providers/data_provider/dp_private.h"
#include "providers/data_provider/dp_builtin.h"
#include "providers/backend.h"
#include "util/util.h"

#define DP_TARGET_INIT_FN "sssm_%s_%s_init"

#define DP_PROVIDER_OPT "%s_provider"
#define DP_ACCESS_PERMIT "permit"
#define DP_ACCESS_DENY "deny"
#define DP_NO_PROVIDER "none"

bool _dp_target_enabled(struct data_provider *provider,
                        const char *module_name,
                        ...)
{
    struct dp_target *target;
    enum dp_targets type;
    va_list ap;
    bool bret;

    if (provider == NULL || provider->targets == NULL) {
        return false;
    }

    bret = false;
    va_start(ap, module_name);
    while ((type = va_arg(ap, enum dp_targets)) != DP_TARGET_SENTINEL) {
        target = provider->targets[type];
        if (target == NULL || target->module_name == NULL) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Uninitialized target %s\n",
                  dp_target_to_string(type));
            continue;
        }

        if (module_name == NULL) {
            bret = true;
            goto done;
        }

        if (strcmp(target->module_name, module_name) == 0) {
            bret = true;
            goto done;
        }
    }

done:
    va_end(ap);
    return bret;
}

struct dp_module *dp_target_module(struct data_provider *provider,
                                   enum dp_targets target)
{
    if (provider == NULL || provider->targets == NULL) {
        return NULL;
    }

    if (target >= DP_TARGET_SENTINEL || provider->targets[target] == NULL) {
        return NULL;
    }

    return provider->targets[target]->module;
}

void *dp_get_module_data(struct dp_module *dp_module)
{
    return dp_module == NULL ? NULL : dp_module->module_data;
}

const char *dp_target_to_string(enum dp_targets target)
{
    switch (target) {
    case DPT_ID:
        return "id";
    case DPT_AUTH:
        return "auth";
    case DPT_ACCESS:
        return "access";
    case DPT_CHPASS:
        return "chpass";
    case DPT_SUDO:
        return "sudo";
    case DPT_AUTOFS:
        return "autofs";
    case DPT_SELINUX:
        return "selinux";
    case DPT_HOSTID:
        return "hostid";
    case DPT_SUBDOMAINS:
        return "subdomains";
    case DPT_SESSION:
        return "session";
    case DPT_RESOLVER:
        return "resolver";
    case DP_TARGET_SENTINEL:
        return NULL;
    }

    return NULL;
}

bool dp_target_initialized(struct dp_target **targets, enum dp_targets type)
{
    if (targets == NULL || targets[type] == NULL) {
        return false;
    }

    return targets[type]->initialized;
}

static const char *dp_target_module_name(struct dp_target **targets,
                                         enum dp_targets type)
{
    if (targets[type] == NULL) {
        return NULL;
    }

    return targets[type]->module_name;
}

static const char *dp_target_default_module(struct dp_target **targets,
                                            enum dp_targets target)
{
    switch (target) {
    case DPT_ID:
        return NULL;
    case DPT_ACCESS:
        return "permit";
    case DPT_CHPASS:
        return dp_target_module_name(targets, DPT_AUTH);
    case DP_TARGET_SENTINEL:
        return NULL;
    default:
        return dp_target_module_name(targets, DPT_ID);
    }
}

static errno_t dp_target_run_constructor(struct dp_target *target,
                                         struct be_ctx *be_ctx)
{
    char *fn_name = NULL;
    dp_target_init_fn fn;
    char *error;
    errno_t ret;

    fn_name = talloc_asprintf(target, DP_TARGET_INIT_FN,
                              target->module->name, target->name);
    if (fn_name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf() failed\n");
        return ENOMEM;
    }

    dlerror(); /* clear any error */
    fn = (dp_target_init_fn)dlsym(target->module->libhandle, fn_name);
    if (fn != NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, "Executing target [%s] constructor\n",
              target->name);

        ret = fn(target, be_ctx, target->module->module_data, target->methods);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE, "Target [%s] constructor failed "
                  "[%d]: %s\n", target->name, ret, sss_strerror(ret));
            goto done;
        }
    } else {
        error = dlerror();
        if (error == NULL || !target->explicitly_configured) {
            /* Not found. */
            ret = ELIBBAD;
            goto done;
        } else {
            /* Error. */
            DEBUG(SSSDBG_FATAL_FAILURE, "Unable to load target [%s] "
                  "constructor: %s\n", target->name, error);
            ret = ELIBBAD;
            goto done;
        }
    }

    target->initialized = true;
    ret = EOK;

done:
    talloc_free(fn_name);
    return ret;
}

static errno_t dp_target_special(struct be_ctx *be_ctx,
                                 struct dp_target *target,
                                 const char *module_name)
{
    if (strcasecmp(module_name, DP_NO_PROVIDER) == 0) {
        DEBUG(SSSDBG_TRACE_FUNC, "Target [%s] is explicitly disabled.\n",
              target->name);
        target->initialized = false;
        target->module = NULL;
        return EOK;
    }

    if (target->target == DPT_ACCESS) {
        if (strcmp(module_name, DP_ACCESS_PERMIT) == 0) {
            dp_set_method(target->methods, DPM_ACCESS_HANDLER,
                          dp_access_permit_handler_send, dp_access_permit_handler_recv, NULL,
                          void, struct pam_data, struct pam_data *);
            target->module = NULL;
            target->initialized = true;
            return EOK;
        }

        if (strcmp(module_name, DP_ACCESS_DENY) == 0) {
            dp_set_method(target->methods, DPM_ACCESS_HANDLER,
                          dp_access_deny_handler_send, dp_access_deny_handler_recv, NULL,
                          void, struct pam_data, struct pam_data *);
            target->module = NULL;
            target->initialized = true;
            return EOK;
        }
    }

    return EAGAIN;
}

static errno_t dp_target_init(struct be_ctx *be_ctx,
                              struct data_provider *provider,
                              struct dp_module **modules,
                              struct dp_target *target)
{
    errno_t ret;

    DEBUG(SSSDBG_TRACE_FUNC, "Initializing target [%s] with module [%s]\n",
          target->name, target->module_name);

    /* We have already name, module name and target set. We just load
     * the module and initialize it. */

    target->methods = talloc_zero_array(target, struct dp_method,
                                        DP_METHOD_SENTINEL + 1);
    if (target->methods == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero_array() failed\n");
        ret = ENOMEM;
        goto done;
    }

    /* Handle special cases that do not require opening a module. */
    ret = dp_target_special(be_ctx, target, target->module_name);
    if (ret == EOK || ret != EAGAIN) {
        goto done;
    }

    /* Load module first. Memory context is modules, not target here. */
    target->module = dp_load_module(modules, be_ctx, provider, modules,
                                    target->module_name);
    if (target->module == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to load module %s\n",
              target->module_name);
        ret = ELIBBAD;
        goto done;
    }

    /* Run constructor. */
    ret = dp_target_run_constructor(target, be_ctx);
    if (!target->explicitly_configured && (ret == ELIBBAD || ret == ENOTSUP)) {
        /* Target not found but it wasn't explicitly
         * configured so we shall just continue. */
        DEBUG(SSSDBG_CONF_SETTINGS, "Target [%s] is not supported by "
              "module [%s].\n", target->name, target->module_name);

        /* Target is not initialized in this case so we can free
         * its resources. However this is not an error so we return EOK. */
        talloc_zfree(target->methods);
        target->initialized = false;

        ret = EOK;
        goto done;
    } else if (ret != EOK) {
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_zfree(target->methods);
    }

    return ret;
}

static char *dp_get_module_name(TALLOC_CTX *mem_ctx,
                                struct confdb_ctx *confdb_ctx,
                                const char *conf_path,
                                struct dp_target **targets,
                                enum dp_targets type,
                                bool *_is_default)
{
    const char *name;
    const char *default_module;
    char *module;
    char *option;
    errno_t ret;

    name = dp_target_to_string(type);
    if (name == NULL) {
        return NULL;
    }

    option = talloc_asprintf(mem_ctx, DP_PROVIDER_OPT, name);
    if (option == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf() failed\n");
        return NULL;
    }

    ret = confdb_get_string(confdb_ctx, mem_ctx, conf_path,
                            option, NULL, &module);
    talloc_free(option);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to read provider value "
              "[%d]: %s\n", ret, sss_strerror(ret));
        return NULL;
    }

    if (module != NULL) {
        *_is_default = false;
        return module;
    }

    *_is_default = true;
    default_module = dp_target_default_module(targets, type);

    return talloc_strdup(mem_ctx, default_module);
}

static errno_t dp_load_configuration(struct confdb_ctx *cdb,
                                     const char *conf_path,
                                     struct dp_target **targets)
{
    enum dp_targets type;
    const char *name;
    bool is_default;
    char *module;
    errno_t ret;

    for (type = 0; type < DP_TARGET_SENTINEL; type++) {
        name = dp_target_to_string(type);
        if (name == NULL) {
            ret = ERR_INTERNAL;
            goto done;
        }

        module = dp_get_module_name(NULL, cdb, conf_path, targets,
                                    type, &is_default);
        if (module == NULL) {
            DEBUG(SSSDBG_CONF_SETTINGS, "No provider is specified for"
                  " [%s]\n", name);
            continue;
#ifndef BUILD_FILES_PROVIDER
        } else if (strcasecmp(module, "files") == 0) {
            DEBUG(SSSDBG_FATAL_FAILURE, "'files' provider is configured for '%s',"
                  " but support wasn't built\n", name);
            sss_log(SSS_LOG_CRIT,
                    "Unsupported provider 'files' is used in SSSD config.");
            ret = ERR_INVALID_CONFIG;
            goto done;
#endif
        } else {
            DEBUG(SSSDBG_CONF_SETTINGS, "Using [%s] provider for [%s]\n",
                  module, name);
        }

        targets[type]->explicitly_configured = is_default == false;
        targets[type]->name = name;
        targets[type]->target = type;
        targets[type]->module_name = talloc_steal(targets[type], module);
    }

    ret = EOK;

done:
    return ret;
}

static errno_t dp_load_targets(struct be_ctx *be_ctx,
                               struct data_provider *provider,
                               struct dp_target **targets,
                               struct dp_module **modules)
{
    enum dp_targets type;
    errno_t ret;

    /* We load the configuration first and store module name to each target.
     * This way we ensure that we have this information available during
     * module initialization. */

    ret = dp_load_configuration(be_ctx->cdb, be_ctx->conf_path, targets);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to load DP configuration "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    for (type = 0; type < DP_TARGET_SENTINEL; type++) {
        ret = dp_target_init(be_ctx, provider, modules, targets[type]);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to load target [%s] "
                  "[%d]: %s.\n", targets[type]->name, ret, sss_strerror(ret));
            ret = ERR_INTERNAL;
            goto done;
        }
    }

    ret = EOK;

done:
    return ret;
}

errno_t dp_init_targets(TALLOC_CTX *mem_ctx,
                        struct be_ctx *be_ctx,
                        struct data_provider *provider,
                        struct dp_module **modules)
{
    struct dp_target **targets;
    enum dp_targets type;
    errno_t ret;

    /* Even though we know the exact number of targets we will allocate
     * them all dynamically so we can have correct talloc hierarchy where
     * all private data are attached to the target they belong to. */

    targets = talloc_zero_array(mem_ctx, struct dp_target *,
                                DP_TARGET_SENTINEL + 1);
    if (targets == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (type = 0; type != DP_TARGET_SENTINEL; type++) {
        targets[type] = talloc_zero(targets, struct dp_target);
        if (targets[type] == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    /* We want this to be already available. */
    provider->targets = targets;

    ret = dp_load_targets(be_ctx, provider, targets, modules);

done:
    if (ret != EOK) {
        provider->targets = NULL;
        talloc_free(targets);
    }

    return ret;
}
