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

#ifdef HAVE_CONFIG_LIB
#include "util/sss_config.h"
#endif

#define PATH_MONITOR    INFOPIPE_COMPONENT_PATH_PFX "/monitor"
#define PATH_RESPONDERS INFOPIPE_COMPONENT_PATH_PFX "/Responders"
#define PATH_BACKENDS   INFOPIPE_COMPONENT_PATH_PFX "/Backends"

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
    const char *name = NULL;
    char *safe_name = NULL;
    errno_t ret;

    if (confdb == NULL || path == NULL) {
        return EINVAL;
    }

    if (strcmp(path, PATH_MONITOR) == 0) {
        type = COMPONENT_MONITOR;
        name = "monitor";
    } else {
        name = ifp_path_strip_prefix(path, PATH_RESPONDERS "/");
        if (name != NULL) {
            type = COMPONENT_RESPONDER;
        } else {
            name = ifp_path_strip_prefix(path, PATH_BACKENDS "/");
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

    safe_name = ifp_bus_path_unescape(mem_ctx, name);
    if (safe_name == NULL) {
        ret = ENOMEM;
        goto done;
    }

    switch (type) {
    case COMPONENT_MONITOR:
        /* noop */
        break;
    case COMPONENT_RESPONDER:
        if (!responder_exists(safe_name)) {
            ret = ENOENT;
            goto done;
        }
        break;
    case COMPONENT_BACKEND:
        if (!backend_exists(confdb, safe_name)) {
            ret = ENOENT;
            goto done;
        }
        break;
    }

    if (_type != NULL) {
        *_type = type;
    }

    if (_name != NULL) {
        *_name = safe_name;
    }

    ret = EOK;

done:
    return ret;
}

static errno_t change_debug_level_tmp(struct confdb_ctx *confdb,
                                      const char *name,
                                      enum component_type type,
                                      uint32_t level)
{
    TALLOC_CTX *tmp_ctx = NULL;
    const char *confdb_path = NULL;
    const char **values = NULL;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
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
        ret = ENOMEM;
        goto done;
    }

    values = talloc_zero_array(tmp_ctx, const char*, 2);
    if (values == NULL) {
        ret = ENOMEM;
        goto done;
    }

    values[0] = talloc_asprintf(tmp_ctx, "0x%.4x", level);
    if (values[0] == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = confdb_add_param(confdb, true, confdb_path,
                           CONFDB_SERVICE_DEBUG_LEVEL, values);
    if (ret != EOK) {
        goto done;
    }

    /* reload the configuration */
    if (kill(getppid(), SIGHUP) != 0) {
        ret = errno;
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
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

    list = talloc_array(mem_ctx, const char*, num);
    if (list == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < num; i++) {
        list[i] = ifp_reply_objpath(list, PATH_RESPONDERS, svc[i]);
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

    list = talloc_array(tmp_ctx, const char*, num);
    if (list == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < num; i++) {
        list[i] = ifp_reply_objpath(list, PATH_BACKENDS, names[i]);
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

int ifp_list_components(struct sbus_request *dbus_req, void *data)
{
    struct ifp_ctx *ctx = NULL;
    DBusError *error = NULL;
    const char **responders = NULL;
    const char **backends = NULL;
    const char **result = NULL;
    int num_responders;
    int num_backends;
    int num;
    int i;
    errno_t ret;

    ctx = talloc_get_type(data, struct ifp_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid ifp context!\n");
        ret = EINVAL;
        goto done;
    }

    ret = list_responders(dbus_req, &responders, &num_responders);
    if (ret != EOK) {
        goto done;
    }

    ret = list_backends(dbus_req, ctx->rctx->cdb, &backends, &num_backends);
    if (ret != EOK) {
        goto done;
    }

    num = num_responders + num_backends + 1;
    result = talloc_array(dbus_req, const char*, num);
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

    ret = EOK;

done:
    if (ret != EOK) {
        error = sbus_error_new(dbus_req, DBUS_ERROR_FAILED,
                               "%s", strerror(ret));
        return sbus_request_fail_and_finish(dbus_req, error);
    }

    return infopipe_iface_ListComponents_finish(dbus_req, result, num);
}

int ifp_list_responders(struct sbus_request *dbus_req, void *data)
{
    DBusError *error = NULL;
    const char **result = NULL;
    int num;
    errno_t ret;

    ret = list_responders(dbus_req, &result, &num);
    if (ret != EOK) {
        error = sbus_error_new(dbus_req, DBUS_ERROR_FAILED,
                               "%s", strerror(ret));
        return sbus_request_fail_and_finish(dbus_req, error);
    }

    return infopipe_iface_ListResponders_finish(dbus_req, result, num);
}

int ifp_list_backends(struct sbus_request *dbus_req, void *data)
{
    struct ifp_ctx *ctx = NULL;
    DBusError *error = NULL;
    const char **result = NULL;
    int num;
    errno_t ret;

    ctx = talloc_get_type(data, struct ifp_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid ifp context!\n");
        ret = EINVAL;
        goto done;
    }

    ret = list_backends(dbus_req, ctx->rctx->cdb, &result, &num);

done:
    if (ret != EOK) {
        error = sbus_error_new(dbus_req, DBUS_ERROR_FAILED,
                               "%s", strerror(ret));
        return sbus_request_fail_and_finish(dbus_req, error);
    }

    return infopipe_iface_ListBackends_finish(dbus_req, result, num);
}

int ifp_find_monitor(struct sbus_request *dbus_req, void *data)
{
    return infopipe_iface_FindMonitor_finish(dbus_req, PATH_MONITOR);
}

int ifp_find_responder_by_name(struct sbus_request *dbus_req,
                               void *data,
                               const char *arg_name)
{
    DBusError *error = NULL;
    const char *result = NULL;

    if (responder_exists(arg_name)) {
        result = ifp_reply_objpath(dbus_req, PATH_RESPONDERS, arg_name);
        if (result == NULL) {
            return sbus_request_fail_and_finish(dbus_req, NULL);
        }
    } else {
        error = sbus_error_new(dbus_req, DBUS_ERROR_FAILED,
                               "Responder \"%s\" does not exist", arg_name);
        return sbus_request_fail_and_finish(dbus_req, error);
    }

    return infopipe_iface_FindResponderByName_finish(dbus_req, result);
}

int ifp_find_backend_by_name(struct sbus_request *dbus_req,
                             void *data,
                             const char *arg_name)
{
    struct ifp_ctx *ctx = NULL;
    DBusError *error = NULL;
    const char *result = NULL;

    ctx = talloc_get_type(data, struct ifp_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid ifp context!\n");
        error = sbus_error_new(dbus_req, DBUS_ERROR_FAILED,
                               "%s\n", strerror(EINVAL));
        return sbus_request_fail_and_finish(dbus_req, error);
    }

    if (backend_exists(ctx->rctx->cdb, arg_name)) {
        result = ifp_reply_objpath(dbus_req, PATH_BACKENDS, arg_name);
        if (result == NULL) {
            return sbus_request_fail_and_finish(dbus_req, NULL);
        }
    } else {
        error = sbus_error_new(dbus_req, DBUS_ERROR_FAILED,
                               "Backend \"%s\" does not exist", arg_name);
        return sbus_request_fail_and_finish(dbus_req, error);
    }

    return infopipe_iface_FindBackendByName_finish(dbus_req, result);
}

int ifp_component_enable(struct sbus_request *dbus_req, void *data)
{
#ifndef HAVE_CONFIG_LIB
    return sbus_request_fail_and_finish(dbus_req,
                sbus_error_new(dbus_req, DBUS_ERROR_NOT_SUPPORTED, NULL));
#else
    struct ifp_ctx *ctx = NULL;
    DBusError *error = NULL;
    const char *path = dbus_message_get_path(dbus_req->message);
    char *name = NULL;
    enum component_type type;
    struct sss_config_ctx *config_ctx = NULL;
    errno_t ret;

    ctx = talloc_get_type(data, struct ifp_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid ifp context!\n");
        ret = EINVAL;
        goto done;
    }

    ret = check_and_get_component_from_path(dbus_req, ctx->rctx->cdb,
                                            path, &type, &name);
    if (ret != EOK) {
        goto done;
    }

    config_ctx = sss_config_open(dbus_req, NULL, CONFDB_DEFAULT_CONFIG_FILE);
    if (config_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    switch (type) {
    case COMPONENT_MONITOR:
        error = sbus_error_new(dbus_req, DBUS_ERROR_NOT_SUPPORTED, NULL);
        goto done;
        break;
    case COMPONENT_RESPONDER:
        ret = sss_config_service_enable(config_ctx, name);
        break;
    case COMPONENT_BACKEND:
        ret = sss_config_domain_enable(config_ctx, name);
        break;
    }

    if (ret != EOK) {
        goto done;
    }

    ret = sss_config_save(config_ctx);
    if (ret != EOK) {
        goto done;
    }

done:
    sss_config_close(&config_ctx);

    if (ret == ENOMEM) {
        return sbus_request_fail_and_finish(dbus_req, NULL);
    } else if (error != NULL) {
        return sbus_request_fail_and_finish(dbus_req, error);
    } else if (ret != EOK) {
        error = sbus_error_new(dbus_req, DBUS_ERROR_FAILED, "%s", strerror(ret));
        return sbus_request_fail_and_finish(dbus_req, error);
    }

    return infopipe_component_Enable_finish(dbus_req);
#endif
}

int ifp_component_disable(struct sbus_request *dbus_req, void *data)
{
#ifndef HAVE_CONFIG_LIB
    return sbus_request_fail_and_finish(dbus_req,
                sbus_error_new(dbus_req, DBUS_ERROR_NOT_SUPPORTED, NULL));
#else
    struct ifp_ctx *ctx = NULL;
    DBusError *error = NULL;
    const char *path = dbus_message_get_path(dbus_req->message);
    char *name = NULL;
    enum component_type type;
    struct sss_config_ctx *config_ctx = NULL;
    errno_t ret;

    ctx = talloc_get_type(data, struct ifp_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid ifp context!\n");
        ret = EINVAL;
        goto done;
    }

    ret = check_and_get_component_from_path(dbus_req, ctx->rctx->cdb,
                                            path, &type, &name);
    if (ret != EOK) {
        goto done;
    }

    config_ctx = sss_config_open(dbus_req, NULL, CONFDB_DEFAULT_CONFIG_FILE);
    if (config_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    switch (type) {
    case COMPONENT_MONITOR:
        error = sbus_error_new(dbus_req, DBUS_ERROR_NOT_SUPPORTED, NULL);
        goto done;
        break;
    case COMPONENT_RESPONDER:
        ret = sss_config_service_disable(config_ctx, name);
        break;
    case COMPONENT_BACKEND:
        ret = sss_config_domain_disable(config_ctx, name);
        break;
    }

    if (ret != EOK) {
        goto done;
    }

    ret = sss_config_save(config_ctx);
    if (ret != EOK) {
        goto done;
    }

done:
    sss_config_close(&config_ctx);

    if (ret == ENOMEM) {
        return sbus_request_fail_and_finish(dbus_req, NULL);
    } else if (error != NULL) {
        return sbus_request_fail_and_finish(dbus_req, error);
    } else if (ret != EOK) {
        error = sbus_error_new(dbus_req, DBUS_ERROR_FAILED, "%s", strerror(ret));
        return sbus_request_fail_and_finish(dbus_req, error);
    }

    return infopipe_component_Disable_finish(dbus_req);
#endif
}

int ifp_component_change_debug_level(struct sbus_request *dbus_req,
                                     void *data,
                                     uint32_t arg_new_level)
{
#ifndef HAVE_CONFIG_LIB
    return sbus_request_fail_and_finish(dbus_req,
                sbus_error_new(dbus_req, DBUS_ERROR_NOT_SUPPORTED, NULL));
#else
    struct ifp_ctx *ctx = NULL;
    DBusError *error = NULL;
    const char *path = dbus_message_get_path(dbus_req->message);
    char *name = NULL;
    enum component_type type;
    struct sss_config_ctx *config_ctx = NULL;
    const char *section = NULL;
    errno_t ret;

    ctx = talloc_get_type(data, struct ifp_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid ifp context!\n");
        ret = EINVAL;
        goto done;
    }

    ret = check_and_get_component_from_path(dbus_req, ctx->rctx->cdb,
                                            path, &type, &name);
    if (ret != EOK) {
        goto done;
    }

    switch (type) {
    case COMPONENT_MONITOR:
        section = "sssd";
        break;
    case COMPONENT_RESPONDER:
        section = name;
        break;
    case COMPONENT_BACKEND:
        section = talloc_asprintf(dbus_req, "domain/%s", name);
        break;
    }

    if (section == NULL) {
        ret = ENOMEM;
        goto done;
    }

    config_ctx = sss_config_open(dbus_req, NULL, CONFDB_DEFAULT_CONFIG_FILE);
    if (config_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_config_set_debug_level(config_ctx, section, arg_new_level);
    if (ret != EOK) {
        goto done;
    }

    ret = sss_config_save(config_ctx);
    if (ret != EOK) {
        goto done;
    }

    ret = change_debug_level_tmp(ctx->rctx->cdb, name, type, arg_new_level);
    if (ret != EOK) {
        goto done;
    }

done:
    sss_config_close(&config_ctx);

    if (ret == ENOMEM) {
        return sbus_request_fail_and_finish(dbus_req, NULL);
    } else if (ret != EOK) {
        error = sbus_error_new(dbus_req, DBUS_ERROR_FAILED, "%s", strerror(ret));
        return sbus_request_fail_and_finish(dbus_req, error);
    }

    return infopipe_component_ChangeDebugLevel_finish(dbus_req);
#endif
}

int ifp_component_change_debug_level_tmp(struct sbus_request *dbus_req,
                                         void *data,
                                         uint32_t arg_new_level)
{
    struct ifp_ctx *ctx = NULL;
    DBusError *error = NULL;
    const char *path = dbus_message_get_path(dbus_req->message);
    char *name = NULL;
    enum component_type type;
    errno_t ret;

    ctx = talloc_get_type(data, struct ifp_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid ifp context!\n");
        ret = EINVAL;
        goto done;
    }

    ret = check_and_get_component_from_path(dbus_req, ctx->rctx->cdb,
                                            path, &type, &name);
    if (ret != EOK) {
        goto done;
    }

    ret = change_debug_level_tmp(ctx->rctx->cdb, name, type, arg_new_level);
    if (ret != EOK) {
        goto done;
    }

    /* Touch configuration file to make sure debug level is reloaded. */
    if (utime(CONFDB_DEFAULT_CONFIG_FILE, NULL) == -1) {
        ret = errno;
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        error = sbus_error_new(dbus_req, DBUS_ERROR_FAILED, "%s", strerror(ret));
        return sbus_request_fail_and_finish(dbus_req, error);
    }

    return infopipe_component_ChangeDebugLevelTemporarily_finish(dbus_req);
}

void ifp_component_get_name(struct sbus_request *dbus_req,
                            void *data,
                            const char **_out)
{
    struct ifp_ctx *ctx = NULL;
    const char *path = dbus_message_get_path(dbus_req->message);
    char *name = NULL;
    errno_t ret;

    *_out = NULL;

    ctx = talloc_get_type(data, struct ifp_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid ifp context!\n");
        return;
    }

    ret = check_and_get_component_from_path(dbus_req, ctx->rctx->cdb,
                                            path, NULL, &name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unknown object [%d]: %s\n",
                                 ret, strerror(ret));
        return;
    }

    *_out = name;
}

void ifp_component_get_debug_level(struct sbus_request *dbus_req,
                                   void *data,
                                   uint32_t *_out)
{
    struct ifp_ctx *ctx = NULL;
    const char *path = dbus_message_get_path(dbus_req->message);
    const char *confdb_path = NULL;
    char *name = NULL;
    enum component_type type;
    int level;
    errno_t ret;

    *_out = 0;

    ctx = talloc_get_type(data, struct ifp_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid ifp context!\n");
        return;
    }

    ret = check_and_get_component_from_path(dbus_req, ctx->rctx->cdb,
                                            path, &type, &name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unknown object [%d]: %s\n",
                                 ret, strerror(ret));
        return;
    }

    switch (type) {
    case COMPONENT_MONITOR:
        confdb_path = CONFDB_MONITOR_CONF_ENTRY;
        break;
    case COMPONENT_RESPONDER:
        confdb_path = talloc_asprintf(dbus_req, CONFDB_SERVICE_PATH_TMPL, name);
        break;
    case COMPONENT_BACKEND:
        confdb_path = talloc_asprintf(dbus_req, CONFDB_DOMAIN_PATH_TMPL, name);
        break;
    }

    if (confdb_path == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory\n");
        return;
    }

    ret = confdb_get_int(ctx->rctx->cdb, confdb_path,
                         CONFDB_SERVICE_DEBUG_LEVEL, SSSDBG_DEFAULT, &level);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to retrieve configuration option"
                                 "[%d]: %s\n", ret, strerror(ret));
        return;
    }

    *_out = level;
}

void ifp_component_get_enabled(struct sbus_request *dbus_req,
                               void *data,
                               bool *_out)
{
    struct ifp_ctx *ctx = NULL;
    const char *path = dbus_message_get_path(dbus_req->message);
    const char *param = NULL;
    char **values = NULL;
    char *name = NULL;
    enum component_type type;
    errno_t ret;
    int i;

    *_out = false;

    ctx = talloc_get_type(data, struct ifp_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid ifp context!\n");
        return;
    }

    ret = check_and_get_component_from_path(dbus_req, ctx->rctx->cdb,
                                            path, &type, &name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unknown object [%d]: %s\n",
                                 ret, strerror(ret));
        return;
    }

    switch (type) {
    case COMPONENT_MONITOR:
        *_out = true;
        return;
    case COMPONENT_RESPONDER:
        param = CONFDB_MONITOR_ACTIVE_SERVICES;
        break;
    case COMPONENT_BACKEND:
        param = CONFDB_MONITOR_ACTIVE_DOMAINS;
        break;
    }

    ret = confdb_get_string_as_list(ctx->rctx->cdb, dbus_req,
                                    CONFDB_MONITOR_CONF_ENTRY, param, &values);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to retrieve configuration option"
                                 "[%d]: %s\n", ret, strerror(ret));
        return;
    }

    for (i = 0; values[i] != NULL; i++) {
        if (strcmp(values[i], name) == 0) {
            *_out = true;
            return;
        }
    }
}

void ifp_component_get_type(struct sbus_request *dbus_req,
                            void *data,
                            const char **_out)
{
    struct ifp_ctx *ctx = NULL;
    const char *path = dbus_message_get_path(dbus_req->message);
    enum component_type type;
    errno_t ret;

    *_out = NULL;

    ctx = talloc_get_type(data, struct ifp_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid ifp context!\n");
        return;
    }

    ret = check_and_get_component_from_path(dbus_req, ctx->rctx->cdb,
                                            path, &type, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unknown object [%d]: %s\n",
                                 ret, strerror(ret));
        return;
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
}

void ifp_backend_get_providers(struct sbus_request *dbus_req,
                               void *data,
                               const char ***_out,
                               int *_out_len)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct ifp_ctx *ctx = NULL;
    const char *path = dbus_message_get_path(dbus_req->message);
    const char *confdb_path = NULL;
    char *name = NULL;
    enum component_type type;
    const char **out = NULL;
    char *value = NULL;
    static const char *providers[] = {CONFDB_DOMAIN_ID_PROVIDER,
                                      CONFDB_DOMAIN_AUTH_PROVIDER,
                                      CONFDB_DOMAIN_ACCESS_PROVIDER,
                                      CONFDB_DOMAIN_CHPASS_PROVIDER,
                                      CONFDB_DOMAIN_SUDO_PROVIDER,
                                      CONFDB_DOMAIN_AUTOFS_PROVIDER,
                                      CONFDB_DOMAIN_SELINUX_PROVIDER,
                                      CONFDB_DOMAIN_HOSTID_PROVIDER,
                                      CONFDB_DOMAIN_SUBDOMAINS_PROVIDER};
    int num_providers = sizeof(providers) / sizeof(providers[0]);
    errno_t ret;
    int i;
    int j;

    *_out = NULL;
    *_out_len = 0;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return;
    }

    ctx = talloc_get_type(data, struct ifp_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid ifp context!\n");
        return;
    }

    ret = check_and_get_component_from_path(tmp_ctx, ctx->rctx->cdb,
                                            path, &type, &name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unknown object [%d]: %s\n",
                                 ret, strerror(ret));
        return;
    }

    if (type != COMPONENT_BACKEND) {
        return;
    }

    confdb_path = talloc_asprintf(tmp_ctx, CONFDB_DOMAIN_PATH_TMPL, name);
    if (confdb_path == NULL) {
        return;
    }

    out = talloc_zero_array(tmp_ctx, const char*, num_providers);
    if (out == NULL) {
        return;
    }

    j = 0;
    for (i = 0; i < num_providers; i++) {
        ret = confdb_get_string(ctx->rctx->cdb, tmp_ctx, confdb_path,
                                providers[i], NULL, &value);
        if (ret != EOK) {
            return;
        }

        if (value == NULL) {
            continue;
        }

        out[j] = talloc_asprintf(out, "%s=%s", providers[i], value);
        if (out[j] == NULL) {
            return;
        }

        j++;
    }

    *_out = talloc_steal(dbus_req, out);
    *_out_len = j;

    talloc_free(tmp_ctx);
    return;
}
