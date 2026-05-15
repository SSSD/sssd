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

#include <dlfcn.h>
#include "config.h"
#include "providers/data_provider/dp.h"
#include "providers/data_provider/dp_private.h"
#include "providers/backend.h"
#include "util/util.h"

/* There can be at most the same number of different modules loaded at
 * one time as the maximum number of defined targets. */
#define DP_MAX_MODULES DP_TARGET_SENTINEL

#define DP_MODULE_PATH DATA_PROVIDER_PLUGINS_PATH "/libsss_%s.so"
#define DP_MODULE_INIT_FN "sssm_%s_init"

static errno_t dp_module_open_lib(struct dp_module *module)
{
    char *libpath = NULL;
    errno_t ret;

    libpath = talloc_asprintf(module, DP_MODULE_PATH, module->name);
    if (libpath == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf() failed\n");
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "Loading module [%s] with path [%s]\n",
          module->name, libpath);

    module->libhandle = dlopen(libpath, RTLD_NOW);
    if (module->libhandle == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to load module [%s] with path "
              "[%s]: %s\n", module->name, libpath, dlerror());
        ret = ELIBACC;
        goto done;
    }

    ret = EOK;

done:
    talloc_free(libpath);
    return ret;
}

static errno_t dp_module_run_constructor(struct dp_module *module,
                                         struct be_ctx *be_ctx,
                                         struct data_provider *provider)
{
    char *fn_name;
    dp_module_init_fn fn;
    errno_t ret;

    fn_name = talloc_asprintf(module, DP_MODULE_INIT_FN, module->name);
    if (fn_name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf() failed\n");
        return ENOMEM;
    }

    fn = (dp_module_init_fn)dlsym(module->libhandle, fn_name);
    if (fn != NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, "Executing module [%s] constructor.\n",
              module->name);

        ret = fn(module, be_ctx, provider, module->name, &module->module_data);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE, "Module [%s] constructor failed "
                  "[%d]: %s\n", module->name, ret, sss_strerror(ret));
            goto done;
        }
    } else {
        DEBUG(SSSDBG_TRACE_FUNC, "No constructor found for module [%s].\n",
              module->name);
        module->module_data = NULL;
        ret = EOK;
        goto done;
    }

    ret = EOK;

done:
    talloc_free(fn_name);
    return ret;
}

static errno_t dp_module_find(struct dp_module **modules,
                              const char *name,
                              struct dp_module **_module,
                              unsigned int *_slot)
{
    unsigned int slot;

    for (slot = 0; modules[slot] != NULL; slot++) {
        if (strcmp(modules[slot]->name, name) == 0) {
            *_module = modules[slot];
            *_slot = slot;

            return EOK;
        }
    }

    if (slot == DP_MAX_MODULES) {
        /* This should not happen. */
        DEBUG(SSSDBG_CRIT_FAILURE, "All module slots are taken.\n");

        return ERR_INTERNAL;
    }

    *_module = NULL;
    *_slot = slot;

    return EOK;
}

static struct dp_module *dp_module_create(TALLOC_CTX *mem_ctx,
                                          struct be_ctx *be_ctx,
                                          struct data_provider *provider,
                                          const char *name)
{
    struct dp_module *module;
    errno_t ret;

    module = talloc_zero(mem_ctx, struct dp_module);
    if (module == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero() failed\n");
        ret = ENOMEM;
        goto done;
    }

    module->name = talloc_strdup(module, name);
    if (module->name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup() failed\n");
        ret = ENOMEM;
        goto done;
    }

    ret = dp_module_open_lib(module);
    if (ret != EOK) {
        goto done;
    }

    ret = dp_module_run_constructor(module, be_ctx, provider);
    if (ret != EOK) {
        goto done;
    }

    module->initialized = true;

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(module);
        return NULL;
    }

    return module;
}

struct dp_module *dp_load_module(TALLOC_CTX *mem_ctx,
                                 struct be_ctx *be_ctx,
                                 struct data_provider *provider,
                                 struct dp_module **modules,
                                 const char *name)
{
    struct dp_module *module;
    unsigned int free_slot;
    errno_t ret;

    ret = dp_module_find(modules, name, &module, &free_slot);
    if (ret != EOK) {
        return NULL;
    }

    if (module != NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, "Module [%s] is already loaded.\n", name);
        return module;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "About to load module [%s].\n", name);

    module = dp_module_create(mem_ctx, be_ctx, provider, name);
    if (module == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create DP module.\n");
        return NULL;
    }

    modules[free_slot] = module;

    return module;
}

errno_t dp_init_modules(TALLOC_CTX *mem_ctx, struct dp_module ***_modules)
{
    struct dp_module **modules;

    modules = talloc_zero_array(mem_ctx, struct dp_module *,
                                DP_MAX_MODULES + 1);
    if (modules == NULL) {
        return ENOMEM;
    }

    *_modules = modules;

    return EOK;
}
