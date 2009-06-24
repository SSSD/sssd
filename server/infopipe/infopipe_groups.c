/*
   SSSD

   InfoPipe

   Copyright (C) Stephen Gallagher <sgallagh@redhat.com>	2009

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

#include <dbus/dbus.h>
#include <ldb.h>
#include <time.h>
#include "util/util.h"
#include "util/btreemap.h"
#include "confdb/confdb.h"
#include "infopipe/infopipe.h"
#include "infopipe/infopipe_private.h"
#include "infopipe/sysbus.h"
#include "db/sysdb.h"

struct infp_creategroup_ctx {
    struct infp_req_ctx *infp_req;
    char **groupnames;
    uint32_t name_count;
    uint32_t index;
    struct sysdb_handle *handle;
};

static void infp_do_group_create(struct sysdb_handle *handle, void *pvt);
static void infp_do_group_create_callback(void *pvt, int status,
                                          struct ldb_result *res)
{
    char *error_msg = NULL;
    DBusMessage *reply = NULL;
    struct infp_creategroup_ctx *grcreate_req =
        talloc_get_type(pvt, struct infp_creategroup_ctx);

    if (status != EOK) {
        sysdb_transaction_done(grcreate_req->handle, status);

        if (status == EEXIST) {
            error_msg =
                talloc_asprintf(grcreate_req,
                                "Group [%s] already exists on domain [%s]",
                                grcreate_req->groupnames[grcreate_req->index],
                                grcreate_req->infp_req->domain->name);
            reply = dbus_message_new_error(grcreate_req->infp_req->req_message,
                                           DBUS_ERROR_FILE_EXISTS,
                                           error_msg);
            if (reply)
                sbus_conn_send_reply(grcreate_req->infp_req->sconn, reply);
        }
        else {
            infp_return_failure(grcreate_req->infp_req, NULL);
        }
        talloc_free(grcreate_req);
        return;
    }

    /* Status is okay, add the next group */
    grcreate_req->index++;
    if (grcreate_req->index < grcreate_req->name_count) {
        infp_do_group_create(grcreate_req->handle, grcreate_req);
        return;
    }

    /* We have no more usernames to add, so commit the transaction */
    sysdb_transaction_done(grcreate_req->handle, status);

    infp_return_success(grcreate_req->infp_req);
    talloc_free(grcreate_req);
    return;
}

static void infp_do_group_create(struct sysdb_handle *handle, void *pvt)
{
    int ret;
    struct infp_creategroup_ctx *grcreate_req =
        talloc_get_type(pvt, struct infp_creategroup_ctx);

    grcreate_req->handle = handle;

    ret = sysdb_add_group(grcreate_req->handle,
                          grcreate_req->infp_req->domain,
                          grcreate_req->groupnames[grcreate_req->index], 0,
                          infp_do_group_create_callback, grcreate_req);
    if (ret != EOK) {
        DEBUG(0, ("Could not invoke sysdb_add_group\n"));
        sysdb_transaction_done(grcreate_req->handle, ret);
        infp_return_failure(grcreate_req->infp_req, NULL);
        talloc_free(grcreate_req);
        return;
    }
}

int infp_groups_create(DBusMessage *message, struct sbus_conn_ctx *sconn)
{
    DBusMessage *reply;
    DBusError error;
    struct infp_creategroup_ctx *grcreate_req;
    char *einval_msg;
    int ret, i;

    /* Arguments */
    char **arg_grnames = NULL;
    int arg_grnames_count;
    const char *arg_domain;

    grcreate_req = talloc_zero(NULL, struct infp_creategroup_ctx);
    if(grcreate_req == NULL) {
        ret = ENOMEM;
        goto error;
    }

    /* Create an infp_req_ctx */
    grcreate_req->infp_req = infp_req_init(grcreate_req, message, sconn);
    if(grcreate_req->infp_req == NULL) {
        ret = EIO;
        goto error;
    }

    dbus_error_init(&error);
    if (!dbus_message_get_args(message, &error,
                               DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
                                 &arg_grnames, &arg_grnames_count,
                               DBUS_TYPE_STRING, &arg_domain,
                               DBUS_TYPE_INVALID)) {
        DEBUG(0, ("Parsing arguments to %s failed: %s:%s\n",
                  INFP_GROUPS_CREATE, error.name, error.message));
        einval_msg = talloc_strdup(grcreate_req, error.message);
        dbus_error_free(&error);
        goto einval;
    }

    /* FIXME: Allow creating groups on domains other than LOCAL */
    if (strcasecmp(arg_domain, "LOCAL") != 0) {
        goto denied;
    }

    grcreate_req->infp_req->domain =
                infp_get_domain_obj(grcreate_req->infp_req->infp, arg_domain);
    if (grcreate_req->infp_req->domain == NULL) {
        einval_msg = talloc_strdup(grcreate_req, "Invalid domain.");
        goto einval;
    }

    /* Check permissions */
    if (!infp_get_permissions(grcreate_req->infp_req->caller,
                              grcreate_req->infp_req->domain,
                              INFP_OBJ_TYPE_GROUP,
                              NULL,
                              INFP_ACTION_TYPE_CREATE,
                              INFP_ATTR_TYPE_INVALID)) goto denied;

    grcreate_req->groupnames = talloc_array(grcreate_req,
                                            char *,
                                            arg_grnames_count);
    if (grcreate_req->groupnames == NULL) {
        ret = ENOMEM;
        goto error;
    }

    grcreate_req->name_count = arg_grnames_count;
    for (i = 0; i < arg_grnames_count; i++) {
        grcreate_req->groupnames[i] = talloc_strdup(grcreate_req->groupnames,
                                                    arg_grnames[i]);
        if (grcreate_req->groupnames[i] == NULL) {
            ret = ENOMEM;
            goto error;
        }
    }
    dbus_free_string_array(arg_grnames);
    arg_grnames = NULL;

    grcreate_req->index = 0;
    ret = sysdb_transaction(grcreate_req,
                            grcreate_req->infp_req->infp->sysdb,
                            infp_do_group_create,
                            grcreate_req);

    if (ret != EOK) goto error;

    return EOK;

denied:
    reply = dbus_message_new_error(message, DBUS_ERROR_ACCESS_DENIED, NULL);
    if(reply == NULL) {
        ret = ENOMEM;
        goto error;
    }
    /* send reply */
    sbus_conn_send_reply(sconn, reply);
    dbus_message_unref(reply);

    talloc_free(grcreate_req);
    return EOK;

einval:
    reply = dbus_message_new_error(message,
                                   DBUS_ERROR_INVALID_ARGS,
                                   einval_msg);
    if (reply == NULL) {
        ret = ENOMEM;
        goto error;
    }
    sbus_conn_send_reply(sconn, reply);
    dbus_message_unref(reply);
    if (arg_grnames) dbus_free_string_array(arg_grnames);
    talloc_free(grcreate_req);
    return EOK;

error:
    if (arg_grnames) dbus_free_string_array(arg_grnames);
    if(grcreate_req) infp_return_failure(grcreate_req->infp_req, NULL);
    talloc_free(grcreate_req);
    return ret;
}

struct infp_deletegroup_ctx {
    struct infp_req_ctx *infp_req;
    struct ldb_dn *gr_dn;
    struct sysdb_handle *handle;
};

static void infp_do_group_delete_callback(void *pvt, int status,
                                          struct ldb_result *res)
{
    struct infp_deletegroup_ctx *grdel_req =
        talloc_get_type(pvt, struct infp_deletegroup_ctx);

    /* Commit or cancel the transaction, based on the status */
    sysdb_transaction_done(grdel_req->handle, status);

    if (status != EOK) {
        DEBUG(0, ("Failed to delete group from sysdb. Error code %d\n",
                  status));
        infp_return_failure(grdel_req->infp_req, NULL);
        talloc_free(grdel_req);
        return;
    }

    infp_return_success(grdel_req->infp_req);
    talloc_free(grdel_req);
}

static void infp_do_group_delete(struct sysdb_handle *handle, void *pvt)
{
    int ret;
    struct infp_deletegroup_ctx *grdel_req =
        talloc_get_type(pvt, struct infp_deletegroup_ctx);

    grdel_req->handle = handle;

    ret = sysdb_delete_entry(grdel_req->handle,
                             grdel_req->gr_dn,
                             infp_do_group_delete_callback,
                             grdel_req);
    if (ret != EOK) {
        DEBUG(0, ("Could not delete group entry\n"));
        infp_return_failure(grdel_req->infp_req, NULL);
        talloc_free(grdel_req);
        return;
    }
}

int infp_groups_delete(DBusMessage *message, struct sbus_conn_ctx *sconn)
{
    DBusMessage *reply;
    DBusError error;
    char *einval_msg;
    int ret;
    struct infp_deletegroup_ctx *grdel_req;

    /* Arguments */
    const char *arg_grname;
    const char *arg_domain;

    grdel_req = talloc_zero(NULL, struct infp_deletegroup_ctx);
    if(grdel_req == NULL) {
        ret = ENOMEM;
        goto error;
    }

    /* Create an infp_req_ctx */
    grdel_req->infp_req = infp_req_init(grdel_req, message, sconn);
    if(grdel_req->infp_req == NULL) {
        ret = EIO;
        goto error;
    }

    dbus_error_init(&error);
    if(!dbus_message_get_args(message, &error,
                              DBUS_TYPE_STRING, &arg_grname,
                              DBUS_TYPE_STRING, &arg_domain,
                              DBUS_TYPE_INVALID)) {
        DEBUG(0, ("Parsing arguments to %s failed: %s:%s\n",
                  INFP_GROUPS_DELETE, error.name, error.message));
        einval_msg = talloc_strdup(grdel_req, error.message);
        dbus_error_free(&error);
        goto einval;
    }

    /* FIXME: Allow deleting groups from domains other than LOCAL */
    if(strcasecmp(arg_domain, "LOCAL") != 0) {
        goto denied;
    }

    grdel_req->infp_req->domain =
                    infp_get_domain_obj(grdel_req->infp_req->infp, arg_domain);
    if (grdel_req->infp_req->domain == NULL) {
        einval_msg = talloc_strdup(grdel_req, "Invalid domain.");
        goto einval;
    }

    /* Check permissions */
    if (!infp_get_permissions(grdel_req->infp_req->caller,
                              grdel_req->infp_req->domain,
                              INFP_OBJ_TYPE_GROUP,
                              NULL,
                              INFP_ACTION_TYPE_CREATE,
                              INFP_ATTR_TYPE_INVALID)) goto denied;

    grdel_req->gr_dn = sysdb_group_dn(grdel_req->infp_req->infp->sysdb,
                                      grdel_req,
                                      grdel_req->infp_req->domain->name,
                                      arg_grname);
    if(grdel_req->gr_dn == NULL) {
        DEBUG(0, ("Could not construct a group_dn for deletion.\n"));
        ret = EIO;
        goto error;
    }

    ret = sysdb_transaction(grdel_req,
                            grdel_req->infp_req->infp->sysdb,
                            infp_do_group_delete,
                            grdel_req);
    if (ret != EOK) {
        DEBUG(0, ("Unable to start transaction to delete group\n"));
        goto error;
    }

    return EOK;

denied:
    reply = dbus_message_new_error(message, DBUS_ERROR_ACCESS_DENIED, NULL);
    if(reply == NULL) {
        ret = ENOMEM;
        goto error;
    }
    /* send reply */
    sbus_conn_send_reply(sconn, reply);
    dbus_message_unref(reply);

    talloc_free(grdel_req);
    return EOK;

einval:
    reply = dbus_message_new_error(message,
                                   DBUS_ERROR_INVALID_ARGS,
                                   einval_msg);
    if (reply == NULL) {
        ret = ENOMEM;
        goto error;
    }
    sbus_conn_send_reply(sconn, reply);
    dbus_message_unref(reply);
    talloc_free(grdel_req);
    return EOK;

error:
    if (grdel_req) infp_return_failure(grdel_req->infp_req, NULL);
    talloc_free(grdel_req);
    return ret;
}

enum infp_gr_member_types {
    INFP_GR_MEM_USER = 0,
    INFP_GR_MEM_GROUP
};

struct infp_groupmember_ctx {
    struct infp_req_ctx *infp_req;
    struct ldb_dn *group_dn;
    char **membernames;
    uint32_t member_count;
    uint32_t index;
    uint8_t member_type;
    uint8_t modify_type;
    struct sysdb_handle *handle;
};

static void infp_do_member(struct sysdb_handle *handle, void *pvt);

static void infp_do_member_callback(void *pvt, int status,
                                    struct ldb_result *res)
{
    char *fail_msg;
    DBusMessage *reply = NULL;
    struct infp_groupmember_ctx *grmod_req =
        talloc_get_type(pvt, struct infp_groupmember_ctx);

    /* Check the results of the current add */
    if(status != EOK) goto fail;

    /* Check if there are more members to process */
    grmod_req->index++;
    if(grmod_req->index < grmod_req->member_count) {
        infp_do_member(grmod_req->handle, grmod_req);
        return;
    }

    /* This was the last member. Commit the transaction */
    sysdb_transaction_done(grmod_req->handle, EOK);

    /* Send an ack reply */
    reply = dbus_message_new_method_return(grmod_req->infp_req->req_message);
    if(reply) {
        sbus_conn_send_reply(grmod_req->infp_req->sconn, reply);
        dbus_message_unref(reply);
    }

    talloc_free(grmod_req);
    return;

fail:
sysdb_transaction_done(grmod_req->handle, status);
    fail_msg = talloc_asprintf(grmod_req, "Could not modify group");
    infp_return_failure(grmod_req->infp_req, fail_msg);
    talloc_free(grmod_req);
    return;
}

static void infp_do_member(struct sysdb_handle *handle, void *pvt)
{
    int ret;
    struct ldb_dn *member_dn;
    struct infp_groupmember_ctx *grmod_req =
        talloc_get_type(pvt, struct infp_groupmember_ctx);

    grmod_req->handle = handle;

    if (grmod_req->member_type == INFP_GR_MEM_USER) {
        member_dn =
            sysdb_user_dn(grmod_req->infp_req->infp->sysdb,
                          grmod_req,
                          grmod_req->infp_req->domain->name,
                          grmod_req->membernames[grmod_req->index]);
        if (member_dn == NULL) goto error;
    }
    else if (grmod_req->member_type == INFP_GR_MEM_GROUP) {
        member_dn =
            sysdb_group_dn(grmod_req->infp_req->infp->sysdb,
                           grmod_req,
                           grmod_req->infp_req->domain->name,
                           grmod_req->membernames[grmod_req->index]);
        if (member_dn == NULL) goto error;
    }
    else goto error;

    if (grmod_req->modify_type == INFP_ACTION_TYPE_ADDMEMBER) {
        ret = sysdb_add_group_member(grmod_req->handle,
                                     member_dn,
                                     grmod_req->group_dn,
                                     infp_do_member_callback,
                                     grmod_req);
    }
    else if (grmod_req->modify_type == INFP_ACTION_TYPE_REMOVEMEMBER) {
        ret = sysdb_remove_group_member(grmod_req->handle,
                                        member_dn,
                                        grmod_req->group_dn,
                                        infp_do_member_callback,
                                        grmod_req);
    }
    if (ret != EOK) goto error;

    return;

error:
    infp_return_failure(grmod_req->infp_req, NULL);
    talloc_free(grmod_req);
    return;
}

static int infp_groups_modify_members(DBusMessage *message,
                                      struct sbus_conn_ctx *sconn,
                                      uint8_t modify_type)
{
    DBusMessage *reply;
    DBusError error;
    struct infp_groupmember_ctx *grmod_req;
    char *einval_msg;
    int ret, i;

    /* Arguments */
    const char *arg_group;
    const char *arg_domain;
    char **arg_members = NULL;
    int arg_member_count;
    uint8_t arg_membertype;

    grmod_req = talloc_zero(NULL, struct infp_groupmember_ctx);
    if (grmod_req == NULL) {
        ret = ENOMEM;
        goto error;
    }

    /* Create an infp_req_ctx */
    grmod_req->infp_req = infp_req_init(grmod_req, message, sconn);
    if(grmod_req->infp_req == NULL) {
        ret = EIO;
        goto error;
    }

    dbus_error_init(&error);
    if (!dbus_message_get_args(message, &error,
                               DBUS_TYPE_STRING, &arg_group,
                               DBUS_TYPE_STRING, &arg_domain,
                               DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
                                   &arg_members, &arg_member_count,
                               DBUS_TYPE_BYTE, &arg_membertype,
                               DBUS_TYPE_INVALID)) {
        DEBUG(0, ("Parsing arguments to %s failed: %s:%s\n",
                  INFP_GROUPS_ADD_MEMBERS, error.name, error.message));
        einval_msg = talloc_strdup(grmod_req, error.message);
        dbus_error_free(&error);
        goto einval;
    }

    /* FIXME: Allow modifying groups on domains other than LOCAL */
    if (strcasecmp(arg_domain, "LOCAL") != 0) {
        goto denied;
    }

    grmod_req->infp_req->domain =
                    infp_get_domain_obj(grmod_req->infp_req->infp, arg_domain);
    /* Check for a valid domain */
    if (grmod_req->infp_req->domain == NULL) {
        einval_msg = talloc_strdup(grmod_req, "Invalid domain.");
        goto einval;
    }

    /* Check permissions */
    if (!infp_get_permissions(grmod_req->infp_req->caller,
                              grmod_req->infp_req->domain,
                              INFP_OBJ_TYPE_GROUP,
                              arg_group,
                              modify_type,
                              INFP_ATTR_TYPE_INVALID)) goto denied;

    grmod_req->member_count = arg_member_count;
    grmod_req->membernames = talloc_array(grmod_req, char *,
                                             arg_member_count);
    if (grmod_req == NULL) {
        ret = ENOMEM;
        goto error;
    }
    for (i = 0; i < arg_member_count; i++) {
        grmod_req->membernames[i] = talloc_strdup(grmod_req->membernames,
                                                     arg_members[i]);
        if(grmod_req->membernames[i] == NULL) {
            ret = ENOMEM;
            goto error;
        }
    }
    dbus_free_string_array(arg_members);
    arg_members = NULL;

    grmod_req->group_dn =
        sysdb_group_dn(grmod_req->infp_req->infp->sysdb,
                       grmod_req,
                       grmod_req->infp_req->domain->name,
                       arg_group);
    if (grmod_req->group_dn == NULL) {
        ret = EIO;
        goto error;
    }

    grmod_req->index = 0;
    grmod_req->modify_type = modify_type;
    grmod_req->member_type = arg_membertype;
    if ((grmod_req->member_type != INFP_GR_MEM_USER) &&
        (grmod_req->member_type != INFP_GR_MEM_GROUP)) {
        einval_msg = talloc_strdup(grmod_req,
                                   "Invalid member type");
        goto einval;
    }

    ret = sysdb_transaction(grmod_req,
                            grmod_req->infp_req->infp->sysdb,
                            infp_do_member,
                            grmod_req);
    if (ret != EOK) goto error;

    return EOK;

denied:
    reply = dbus_message_new_error(message, DBUS_ERROR_ACCESS_DENIED, NULL);
    if(reply == NULL) {
        ret = ENOMEM;
        goto error;
    }
    /* send reply */
    sbus_conn_send_reply(sconn, reply);
    dbus_message_unref(reply);

    if (arg_members) dbus_free_string_array(arg_members);
    talloc_free(grmod_req);
    return EOK;

einval:
    reply = dbus_message_new_error(message,
                                   DBUS_ERROR_INVALID_ARGS,
                                   einval_msg);
    if (reply == NULL) {
        ret = ENOMEM;
        goto error;
    }
    sbus_conn_send_reply(sconn, reply);
    dbus_message_unref(reply);
    if (arg_members) dbus_free_string_array(arg_members);
    talloc_free(grmod_req);
    return EOK;

error:
    if (arg_members) dbus_free_string_array(arg_members);
    talloc_free(grmod_req);
    return ret;
}

int infp_groups_add_members(DBusMessage *message,
                            struct sbus_conn_ctx *sconn)
{
    return infp_groups_modify_members(message, sconn,
                                      INFP_ACTION_TYPE_ADDMEMBER);
}

int infp_groups_remove_members(DBusMessage *message,
                               struct sbus_conn_ctx *sconn)
{
    return infp_groups_modify_members(message, sconn,
                                      INFP_ACTION_TYPE_REMOVEMEMBER);
}

struct infp_setgid_ctx {
    struct infp_req_ctx *infp_req;
    char *group_name;
    gid_t gid;
    struct sysdb_handle *handle;
};

static void infp_do_gid_callback(void *ptr,
                                 int status,
                                 struct ldb_result *res)
{
    char *error_msg = NULL;
    struct infp_setgid_ctx *grmod_req =
        talloc_get_type(ptr, struct infp_setgid_ctx);

    /* Commit or cancel the transaction, based on the
     * return status
     */
    sysdb_transaction_done(grmod_req->handle, status);

    if(status != EOK) {
        if (status == ENOENT) {
            error_msg = talloc_strdup(grmod_req, "No such group");
        }
        infp_return_failure(grmod_req->infp_req, error_msg);
        talloc_free(grmod_req);
        return;
    }

    infp_return_success(grmod_req->infp_req);
    talloc_free(grmod_req);
}

static void infp_do_gid(struct sysdb_handle *handle, void *pvt)
{
    int ret;
    DBusMessage *reply;
    char *error_msg;
    gid_t max;
    struct infp_setgid_ctx *grmod_req =
        talloc_get_type(pvt, struct infp_setgid_ctx);
    grmod_req->handle = handle;

    ret = sysdb_set_group_gid(grmod_req->handle,
                              grmod_req->infp_req->domain,
                              grmod_req->group_name,
                              grmod_req->gid,
                              infp_do_gid_callback,
                              grmod_req);
    if (ret != EOK) {
        if(ret == EDOM) {
            /* GID was out of range */
            max = grmod_req->infp_req->domain->id_max?
                  grmod_req->infp_req->domain->id_max:
                  (gid_t)-1;
            error_msg = talloc_asprintf(grmod_req,
                                        "GID %u outside the range [%u..%u]",
                                        grmod_req->gid,
                                        grmod_req->infp_req->domain->id_min,
                                        max);
            reply = dbus_message_new_error(grmod_req->infp_req->req_message,
                                           DBUS_ERROR_LIMITS_EXCEEDED,
                                           error_msg);
            if (reply) sbus_conn_send_reply(grmod_req->infp_req->sconn, reply);
        }
        infp_return_failure(grmod_req->infp_req, NULL);
        talloc_free(grmod_req);
        return;
    }
}

int infp_groups_set_gid(DBusMessage *message, struct sbus_conn_ctx *sconn)
{
    DBusMessage *reply;
    DBusError error;
    char *einval_msg;
    struct infp_setgid_ctx *grmod_req;
    int ret;

    /* Arguments */
    const char *arg_group;
    const char *arg_domain;
    const gid_t arg_gid;

    grmod_req = talloc_zero(NULL, struct infp_setgid_ctx);
    if (grmod_req == NULL) {
        ret = ENOMEM;
        goto error;
    }

    /* Create an infp_req_ctx */
    grmod_req->infp_req = infp_req_init(grmod_req, message, sconn);
    if(grmod_req->infp_req == NULL) {
        ret = EIO;
        goto error;
    }

    dbus_error_init(&error);
    if (!dbus_message_get_args(message, &error,
                               DBUS_TYPE_STRING, &arg_group,
                               DBUS_TYPE_STRING, &arg_domain,
                               DBUS_TYPE_UINT32, &arg_gid,
                               DBUS_TYPE_INVALID)) {
        DEBUG(0, ("Parsing arguments to %s failed: %s:%s\n",
                  INFP_GROUPS_SET_GID, error.name, error.message));
        einval_msg = talloc_strdup(grmod_req, error.message);
        dbus_error_free(&error);
        goto einval;
    }

    /* FIXME: Allow modifying groups on domains other than LOCAL */
    if (strcasecmp(arg_domain, "LOCAL") != 0) {
        goto denied;
    }

    grmod_req->infp_req->domain =
                    infp_get_domain_obj(grmod_req->infp_req->infp, arg_domain);
    /* Check for a valid domain */
    if (grmod_req->infp_req->domain == NULL) {
        einval_msg = talloc_strdup(grmod_req, "Invalid domain.");
        goto einval;
    }

    /* Check permissions */
    if (!infp_get_permissions(grmod_req->infp_req->caller,
                              grmod_req->infp_req->domain,
                              INFP_OBJ_TYPE_GROUP,
                              arg_group,
                              INFP_ACTION_TYPE_MODIFY,
                              INFP_ATTR_TYPE_GROUPID)) goto denied;

    grmod_req->gid = arg_gid;
    grmod_req->group_name = talloc_strdup(grmod_req, arg_group);
    if (grmod_req->group_name == NULL) {
        ret = ENOMEM;
        goto error;
    }

    ret = sysdb_transaction(grmod_req,
                            grmod_req->infp_req->infp->sysdb,
                            infp_do_gid,
                            grmod_req);
    if (ret != EOK) goto error;

    return EOK;

denied:
    reply = dbus_message_new_error(message, DBUS_ERROR_ACCESS_DENIED, NULL);
    if(reply == NULL) {
        ret = ENOMEM;
        goto error;
    }
    /* send reply */
    sbus_conn_send_reply(sconn, reply);
    dbus_message_unref(reply);

    talloc_free(grmod_req);
    return EOK;

einval:
    reply = dbus_message_new_error(message,
                                   DBUS_ERROR_INVALID_ARGS,
                                   einval_msg);
    if (reply == NULL) {
        ret = ENOMEM;
        goto error;
    }
    sbus_conn_send_reply(sconn, reply);
    dbus_message_unref(reply);
    talloc_free(grmod_req);
    return EOK;

error:
    if(grmod_req) infp_return_failure(grmod_req->infp_req, NULL);
    talloc_free(grmod_req);
    return ret;
}
