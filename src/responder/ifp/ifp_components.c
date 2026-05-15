/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

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

#include <string.h>
#include <talloc.h>
#include <signal.h>
#include <errno.h>
#include <utime.h>

#include "config.h"
#include "confdb/confdb.h"
#include "util/util.h"
#include "responder/common/responder.h"
#include "responder/ifp/ifp_components.h"

#define PATH_MONITOR    IFP_PATH_COMPONENTS "/monitor"
#define PATH_RESPONDERS IFP_PATH_COMPONENTS "/Responders"
#define PATH_BACKENDS   IFP_PATH_COMPONENTS "/Backends"

enum component_type {
    COMPONENT_MONITOR,
    COMPONENT_RESPONDER,
    COMPONENT_BACKEND
};

static bool responder_exists(const char *name)
{
    const char * const *svc = get_known_services();
    int i;

    for (i = 0; svc[i] != NULL; i++) {
        if (strcmp(svc[i], name) == 0) {
            return true;
        }
    }

    return false;
}

static bool backend_exists(struct confdb_ctx *confdb, const char *name)
{
    char **names = NULL;
    errno_t ret;
    int i;

    ret = confdb_list_all_domain_names(NULL, confdb, &names);
    if (ret != EOK) {
        return false;
    }

    for (i = 0; names[i] != NULL; i++) {
        if (strcmp(names[i], name) == 0) {
            return true;
        }
    }

    return false;
}

static errno_t check_and_get_component_from_path(TALLOC_CTX *mem_ctx,
                                                 struct confdb_ctx *confdb,
                                                 const char *path,
                                                 enum component_type *_type,
                                                 char **_name)
{
    enum component_type type;
    char *name = NULL;
    errno_t ret;

    if (confdb == NULL || path == NULL) {
        return EINVAL;
    }

    if (strcmp(path, PATH_MONITOR) == 0) {
        type = COMPONENT_MONITOR;
        name = talloc_strdup(mem_ctx, "monitor");
        if (name == NULL) {
            ret = ENOMEM;
            goto done;
        }
    } else {
        name = sbus_opath_object_name(mem_ctx, path, PATH_RESPONDERS);
        if (name != NULL) {
            type = COMPONENT_RESPONDER;
        } else {
            name = sbus_opath_object_name(mem_ctx, path, PATH_BACKENDS);
            if (name != NULL) {
                type = COMPONENT_BACKEND;
            } else {
                ret = EINVAL;
                goto done;
            }
        }
    }

    if (strchr(name, '/') != NULL) {
        ret = EINVAL;
        goto done;
    }

    switch (type) {
    case COMPONENT_MONITOR:
        /* noop */
        break;
    case COMPONENT_RESPONDER:
        if (!responder_exists(name)) {
            ret = ENOENT;
            goto done;
        }
        break;
    case COMPONENT_BACKEND:
        if (!backend_exists(confdb, name)) {
            ret = ENOENT;
            goto done;
        }
        break;
    }

    if (_type != NULL) {
        *_type = type;
    }

    if (_name != NULL) {
        *_name = name;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(name);
    }

    return ret;
}

static errno_t list_responders(TALLOC_CTX *mem_ctx,
                               const char ***_list,
                               int *_num)
{
    const char **list = NULL;
    const char * const *svc = get_known_services();
    errno_t ret;
    int num;
    int i;

    for (num = 0; svc[num] != NULL; num++);

    list = talloc_zero_array(mem_ctx, const char*, num + 1);
    if (list == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < num; i++) {
        list[i] = sbus_opath_compose(list, PATH_RESPONDERS, svc[i]);
        if (list[i] == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    *_num = num;
    *_list = list;
    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(list);
    }

    return ret;
}

static errno_t list_backends(TALLOC_CTX *mem_ctx,
                             struct confdb_ctx *confdb,
                             const char ***_list,
                             int *_num)
{
    TALLOC_CTX *tmp_ctx = NULL;
    const char **list = NULL;
    char **names = NULL;
    errno_t ret;
    int num;
    int i;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = confdb_list_all_domain_names(tmp_ctx, confdb, &names);
    if (ret != EOK) {
        goto done;
    }

    for (num = 0; names[num] != NULL; num++);

    list = talloc_zero_array(tmp_ctx, const char*, num + 1);
    if (list == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < num; i++) {
        list[i] = sbus_opath_compose(list, PATH_BACKENDS, names[i]);
        if (list[i] == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    *_num = num;
    *_list = talloc_steal(mem_ctx, list);
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
ifp_list_components(TALLOC_CTX *mem_ctx,
                    struct sbus_request *sbus_req,
                    struct ifp_ctx *ctx,
                    const char ***_paths)
{
    TALLOC_CTX *tmp_ctx;
    const char **responders;
    const char **backends;
    const char **result;
    int num_responders;
    int num_backends;
    int num;
    int i;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory!\n");
        return ENOMEM;
    }

    ret = list_responders(tmp_ctx, &responders, &num_responders);
    if (ret != EOK) {
        goto done;
    }

    ret = list_backends(tmp_ctx, ctx->rctx->cdb, &backends, &num_backends);
    if (ret != EOK) {
        goto done;
    }

    num = num_responders + num_backends + 1;
    result = talloc_zero_array(mem_ctx, const char *, num + 1);
    if (result == NULL) {
        ret = ENOMEM;
        goto done;
    }

    result[0] = PATH_MONITOR;

    for (i = 0; i < num_responders; i++) {
        result[i + 1] = talloc_steal(result, responders[i]);
    }

    for (i = 0; i < num_backends; i++) {
        result[i + num_responders + 1] = talloc_steal(result, backends[i]);
    }

    *_paths = result;

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}


errno_t
ifp_list_responders(TALLOC_CTX *mem_ctx,
                    struct sbus_request *sbus_req,
                    struct ifp_ctx *ctx,
                    const char ***_paths)
{
    const char **result;
    int num;
    errno_t ret;

    ret = list_responders(mem_ctx, &result, &num);
    if (ret != EOK) {
        return ret;
    }

    *_paths = result;

    return EOK;
}

errno_t
ifp_list_backends(TALLOC_CTX *mem_ctx,
                  struct sbus_request *sbus_req,
                  struct ifp_ctx *ctx,
                  const char ***_paths)
{
    const char **result;
    int num;
    errno_t ret;

    ret = list_backends(mem_ctx, ctx->rctx->cdb, &result, &num);
    if (ret != EOK) {
        return ret;
    }

    *_paths = result;

    return EOK;
}

errno_t
ifp_find_monitor(TALLOC_CTX *mem_ctx,
                 struct sbus_request *sbus_req,
                 struct ifp_ctx *ctx,
                 const char **_path)
{
    *_path = PATH_MONITOR;

    return EOK;
}


errno_t
ifp_find_responder_by_name(TALLOC_CTX *mem_ctx,
                           struct sbus_request *sbus_req,
                           struct ifp_ctx *ctx,
                           const char *name,
                           const char **_path)
{
    const char *result;

    if (responder_exists(name)) {
        result = sbus_opath_compose(mem_ctx, PATH_RESPONDERS, name);
        if (result == NULL) {
            return ENOMEM;
        }

        *_path = result;
        return EOK;
    }

    DEBUG(SSSDBG_MINOR_FAILURE, "Responder \"%s\" does not exist", name);
    return ENOENT;
}

errno_t
ifp_find_backend_by_name(TALLOC_CTX *mem_ctx,
                         struct sbus_request *sbus_req,
                         struct ifp_ctx *ctx,
                         const char *name,
                         const char **_path)
{
    const char *result;

    if (backend_exists(ctx->rctx->cdb, name)) {
        result = sbus_opath_compose(mem_ctx, PATH_BACKENDS, name);
        if (result == NULL) {
            return ENOMEM;
        }

        *_path = result;
        return EOK;
    }

    DEBUG(SSSDBG_MINOR_FAILURE, "Backend \"%s\" does not exist", name);
    return ENOENT;
}

errno_t
ifp_component_get_name(TALLOC_CTX *mem_ctx,
                       struct sbus_request *sbus_req,
                       struct ifp_ctx *ctx,
                       const char **_out)
{
    char *name;
    errno_t ret;

    ret = check_and_get_component_from_path(mem_ctx, ctx->rctx->cdb,
                                            sbus_req->path, NULL, &name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unknown object [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    *_out = name;

    return EOK;
}

errno_t
ifp_component_get_debug_level(TALLOC_CTX *mem_ctx,
                              struct sbus_request *sbus_req,
                              struct ifp_ctx *ctx,
                              uint32_t *_out)
{
    TALLOC_CTX *tmp_ctx;
    const char *confdb_path = NULL;
    enum component_type type;
    char *name;
    int level;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory!\n");
        return ENOMEM;
    }

    ret = check_and_get_component_from_path(tmp_ctx, ctx->rctx->cdb,
                                            sbus_req->path, &type, &name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unknown object [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    switch (type) {
    case COMPONENT_MONITOR:
        confdb_path = CONFDB_MONITOR_CONF_ENTRY;
        break;
    case COMPONENT_RESPONDER:
        confdb_path = talloc_asprintf(tmp_ctx, CONFDB_SERVICE_PATH_TMPL, name);
        break;
    case COMPONENT_BACKEND:
        confdb_path = talloc_asprintf(tmp_ctx, CONFDB_DOMAIN_PATH_TMPL, name);
        break;
    }

    if (confdb_path == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory\n");
        ret = ENOMEM;
        goto done;
    }

    ret = confdb_get_int(ctx->rctx->cdb, confdb_path,
                         CONFDB_SERVICE_DEBUG_LEVEL, SSSDBG_DEFAULT, &level);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to retrieve configuration option"
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    *_out = level;

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t
ifp_component_get_enabled(TALLOC_CTX *mem_ctx,
                          struct sbus_request *sbus_req,
                          struct ifp_ctx *ctx,
                          bool *_out)
{
    TALLOC_CTX *tmp_ctx;
    enum component_type type;
    const char *param = NULL;
    char **values;
    char *name;
    errno_t ret;
    int i;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory!\n");
        return ENOMEM;
    }

    ret = check_and_get_component_from_path(tmp_ctx, ctx->rctx->cdb,
                                            sbus_req->path, &type, &name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unknown object [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    switch (type) {
    case COMPONENT_MONITOR:
        *_out = true;
        ret = EOK;
        goto done;
    case COMPONENT_RESPONDER:
        param = CONFDB_MONITOR_ACTIVE_SERVICES;
        break;
    case COMPONENT_BACKEND:
        param = CONFDB_MONITOR_ACTIVE_DOMAINS;
        break;
    }

    ret = confdb_get_string_as_list(ctx->rctx->cdb, tmp_ctx,
                                    CONFDB_MONITOR_CONF_ENTRY, param, &values);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to retrieve configuration option"
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    for (i = 0; values[i] != NULL; i++) {
        if (strcmp(values[i], name) == 0) {
            *_out = true;
            break;
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t
ifp_component_get_type(TALLOC_CTX *mem_ctx,
                       struct sbus_request *sbus_req,
                       struct ifp_ctx *ctx,
                       const char **_out)
{
    enum component_type type;
    errno_t ret;

    ret = check_and_get_component_from_path(mem_ctx, ctx->rctx->cdb,
                                            sbus_req->path, &type, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unknown object [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    switch (type) {
    case COMPONENT_MONITOR:
        *_out = "monitor";
        break;
    case COMPONENT_RESPONDER:
        *_out = "responder";
        break;
    case COMPONENT_BACKEND:
        *_out = "backend";
        break;
    }

    return EOK;
}

errno_t
ifp_backend_get_providers(TALLOC_CTX *mem_ctx,
                          struct sbus_request *sbus_req,
                          struct ifp_ctx *ctx,
                          const char ***_out)
{
    TALLOC_CTX *tmp_ctx;
    const char *confdb_path;
    char *name;
    enum component_type type;
    const char **out;
    char *value;
    static const char *providers[] = {CONFDB_DOMAIN_ID_PROVIDER,
                                      CONFDB_DOMAIN_AUTH_PROVIDER,
                                      CONFDB_DOMAIN_ACCESS_PROVIDER,
                                      CONFDB_DOMAIN_CHPASS_PROVIDER,
                                      CONFDB_DOMAIN_SUDO_PROVIDER,
                                      CONFDB_DOMAIN_AUTOFS_PROVIDER,
                                      CONFDB_DOMAIN_SELINUX_PROVIDER,
                                      CONFDB_DOMAIN_HOSTID_PROVIDER,
                                      CONFDB_DOMAIN_SUBDOMAINS_PROVIDER,
                                      CONFDB_DOMAIN_SESSION_PROVIDER};
    int num_providers = sizeof(providers) / sizeof(providers[0]);
    errno_t ret;
    int i;
    int j;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = check_and_get_component_from_path(tmp_ctx, ctx->rctx->cdb,
                                            sbus_req->path, &type, &name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unknown object [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    if (type != COMPONENT_BACKEND) {
        ret = EINVAL;
        goto done;
    }

    confdb_path = talloc_asprintf(tmp_ctx, CONFDB_DOMAIN_PATH_TMPL, name);
    if (confdb_path == NULL) {
        ret = ENOMEM;
        goto done;
    }

    out = talloc_zero_array(tmp_ctx, const char *, num_providers + 1);
    if (out == NULL) {
        ret = ENOMEM;
        goto done;
    }

    j = 0;
    for (i = 0; i < num_providers; i++) {
        ret = confdb_get_string(ctx->rctx->cdb, tmp_ctx, confdb_path,
                                providers[i], NULL, &value);
        if (ret != EOK) {
            goto done;
        }

        if (value == NULL) {
            continue;
        }

        out[j] = talloc_asprintf(out, "%s=%s", providers[i], value);
        if (out[j] == NULL) {
            ret = ENOMEM;
            goto done;
        }

        j++;
    }

    *_out = talloc_steal(mem_ctx, out);

done:
    talloc_free(tmp_ctx);

    return ret;
}
