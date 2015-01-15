/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2015 Red Hat

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
#include <string.h>

#include "db/sysdb.h"
#include "util/util.h"
#include "sbus/sssd_dbus_errors.h"
#include "responder/common/responder.h"
#include "responder/common/responder_cache_req.h"
#include "responder/ifp/ifp_users.h"

char * ifp_users_build_path_from_msg(TALLOC_CTX *mem_ctx,
                                     struct sss_domain_info *domain,
                                     struct ldb_message *msg)
{
    const char *uid;

    uid = ldb_msg_find_attr_as_string(msg, SYSDB_UIDNUM, NULL);

    if (uid == NULL) {
        return NULL;
    }

    return sbus_opath_compose(mem_ctx, IFP_PATH_USERS, domain->name, uid);
}

static void ifp_users_find_by_name_done(struct tevent_req *req);

int ifp_users_find_by_name(struct sbus_request *sbus_req,
                           void *data,
                           const char *name)
{
    struct ifp_ctx *ctx;
    struct tevent_req *req;

    ctx = talloc_get_type(data, struct ifp_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid pointer!\n");
        return ERR_INTERNAL;
    }

    req = cache_req_user_by_name_send(sbus_req, ctx->rctx->ev, ctx->rctx,
                                      ctx->ncache, ctx->neg_timeout, 0,
                                      NULL, name);
    if (req == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(req, ifp_users_find_by_name_done, sbus_req);

    return EOK;
}

static void
ifp_users_find_by_name_done(struct tevent_req *req)
{
    DBusError *error;
    struct sbus_request *sbus_req;
    struct sss_domain_info *domain;
    struct ldb_result *result;
    char *object_path;
    errno_t ret;

    sbus_req = tevent_req_callback_data(req, struct sbus_request);

    ret = cache_req_user_by_name_recv(sbus_req, req, &result, &domain, NULL);
    talloc_zfree(req);
    if (ret == ENOENT) {
        error = sbus_error_new(sbus_req, SBUS_ERROR_NOT_FOUND,
                               "User not found");
        goto done;
    } else if (ret != EOK) {
        error = sbus_error_new(sbus_req, DBUS_ERROR_FAILED, "Failed to fetch "
                               "user [%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    object_path = ifp_users_build_path_from_msg(sbus_req, domain,
                                                result->msgs[0]);
    if (object_path == NULL) {
        error = sbus_error_new(sbus_req, SBUS_ERROR_INTERNAL,
                               "Failed to compose object path");
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        sbus_request_fail_and_finish(sbus_req, error);
        return;
    }

    iface_ifp_users_FindByName_finish(sbus_req, object_path);
    return;
}

static void ifp_users_find_by_id_done(struct tevent_req *req);

int ifp_users_find_by_id(struct sbus_request *sbus_req,
                         void *data,
                         uint32_t id)
{
    struct ifp_ctx *ctx;
    struct tevent_req *req;

    ctx = talloc_get_type(data, struct ifp_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid pointer!\n");
        return ERR_INTERNAL;
    }

    req = cache_req_user_by_id_send(sbus_req, ctx->rctx->ev, ctx->rctx,
                                    ctx->ncache, ctx->neg_timeout, 0,
                                    NULL, id);
    if (req == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(req, ifp_users_find_by_id_done, sbus_req);

    return EOK;
}

static void
ifp_users_find_by_id_done(struct tevent_req *req)
{
    DBusError *error;
    struct sbus_request *sbus_req;
    struct sss_domain_info *domain;
    struct ldb_result *result;
    char *object_path;
    errno_t ret;

    sbus_req = tevent_req_callback_data(req, struct sbus_request);

    ret = cache_req_user_by_id_recv(sbus_req, req, &result, &domain);
    talloc_zfree(req);
    if (ret == ENOENT) {
        error = sbus_error_new(sbus_req, SBUS_ERROR_NOT_FOUND,
                               "User not found");
        goto done;
    } else if (ret != EOK) {
        error = sbus_error_new(sbus_req, DBUS_ERROR_FAILED, "Failed to fetch "
                               "user [%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    object_path = ifp_users_build_path_from_msg(sbus_req, domain,
                                                result->msgs[0]);
    if (object_path == NULL) {
        error = sbus_error_new(sbus_req, SBUS_ERROR_INTERNAL,
                               "Failed to compose object path");
        goto done;
    }

done:
    if (ret != EOK) {
        sbus_request_fail_and_finish(sbus_req, error);
        return;
    }

    iface_ifp_users_FindByID_finish(sbus_req, object_path);
    return;
}

int ifp_users_list_by_name(struct sbus_request *sbus_req,
                           void *data,
                           const char *filter,
                           uint32_t limit)
{
    return EOK;
}

int ifp_users_list_by_domain_and_name(struct sbus_request *sbus_req,
                                      void *data,
                                      const char *domain,
                                      const char *filter,
                                      uint32_t limit)
{
    return EOK;
}
