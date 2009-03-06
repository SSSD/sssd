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

static int attr_comparator(const void *key1, const void *key2);
static int username_comparator(const void *key1, const void *key2);

struct infp_getcached_ctx {
    struct infp_req_ctx *infp_req;
    struct sysdb_req *sysdb_req;
    char **usernames;
    uint64_t min_last_login;
};
static void infp_users_get_cached_callback(void *ptr,
                                           int status,
                                           struct ldb_result *res)
{
    DBusMessage *reply;
    DBusMessageIter iter, array_iter;
    dbus_bool_t dbret;
    int i;
    char *username;
    struct infp_getcached_ctx *infp_getcached_req =
        talloc_get_type(ptr, struct infp_getcached_ctx);

    if (status != LDB_SUCCESS) {
        DEBUG(0, ("Failed to enumerate users in the cache db.\n"));
        talloc_free(infp_getcached_req);
        return;
    }

    /* Construct a reply */
    reply = dbus_message_new_method_return(infp_getcached_req->infp_req->req_message);
    if(reply == NULL) {
        talloc_free(infp_getcached_req);
        return;
    }

    dbus_message_iter_init_append(reply, &iter);
    dbret = dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
                                             "s", &array_iter);
    if (!dbret) goto error;

    for (i = 0; i < res->count; i++) {
        username = talloc_strdup(infp_getcached_req,
                                 ldb_msg_find_attr_as_string(res->msgs[i],
                                                             SYSDB_NAME,
                                                             NULL));
        if (username != NULL) {
            dbret = dbus_message_iter_append_basic(&array_iter,
                                                   DBUS_TYPE_STRING, &username);
            if (!dbret) goto error;
        }
    }
    dbret = dbus_message_iter_close_container(&iter, &array_iter);
    if(!dbret) goto error;

    sbus_conn_send_reply(infp_getcached_req->infp_req->sconn, reply);
    dbus_message_unref(reply);

    talloc_free(infp_getcached_req);
    return;

error:
    DEBUG(0,
          ("Critical error constructing reply message for %s\n",
            INFP_USERS_GET_CACHED));
    dbus_message_unref(reply);
    talloc_free(infp_getcached_req);
    return;
}

int infp_users_get_cached(DBusMessage *message, struct sbus_conn_ctx *sconn)
{
    DBusMessage *reply;
    DBusError error;
    dbus_bool_t dbret;
    char *einval_msg;
    char *search_expression;
    struct infp_getcached_ctx *infp_getcached_req;
    int ret;

    /* Arguments */
    const char *arg_domain;
    const uint64_t arg_minlastlogin;

    infp_getcached_req = talloc_zero(NULL, struct infp_getcached_ctx);
    if (infp_getcached_req == NULL) {
        ret = ENOMEM;
        goto error;
    }

    /* Create an infp_req_ctx */
    infp_getcached_req->infp_req = infp_req_init(infp_getcached_req,
                                                 message, sconn);
    if (infp_getcached_req->infp_req == NULL) {
        ret = EIO;
        goto error;
    }

    dbus_error_init(&error);
    dbret = dbus_message_get_args(message, &error,
                                  DBUS_TYPE_STRING, &arg_domain,
                                  DBUS_TYPE_UINT64, &arg_minlastlogin,
                                  DBUS_TYPE_INVALID);
    if(!dbret) {
        DEBUG(0, ("Parsing arguments to %s failed: %s:%s\n",
                INFP_USERS_GET_CACHED, error.name, error.message));
        einval_msg = talloc_strdup(infp_getcached_req, error.message);
        dbus_error_free(&error);
        goto einval;
    }

    infp_getcached_req->min_last_login = arg_minlastlogin;

    infp_getcached_req->infp_req->domain =
        btreemap_get_value(infp_getcached_req->infp_req->infp->domain_map,
                           (const void *)arg_domain);
    /* Check for a valid domain */
    if(infp_getcached_req->infp_req->domain == NULL) {
        einval_msg = talloc_strdup(infp_getcached_req, "Invalid domain.");
        goto einval;
    }

    /* NOTE: not checking permissions since the
     * information here is all visible in NSS as well
     */

    /* Call sysdb_enumpwent with special search parameters */
    search_expression = talloc_asprintf(infp_getcached_req,
                                        SYSDB_GETCACHED_FILTER,
                                        infp_getcached_req->min_last_login);
    ret = sysdb_enumpwent(infp_getcached_req,
                          infp_getcached_req->infp_req->infp->sysdb,
                          infp_getcached_req->infp_req->domain->name,
                          infp_getcached_req->infp_req->domain->legacy,
                          search_expression,
                          infp_users_get_cached_callback, infp_getcached_req);
    if(ret != EOK) {
        DEBUG(0, ("Could not read from the cache database.\n"));
        goto error;
    }

    return EOK;

einval:
    reply = dbus_message_new_error(message,
                                   DBUS_ERROR_INVALID_ARGS,
                                   einval_msg);
    if(reply == NULL) {
        ret = ENOMEM;
        goto error;
    }

    sbus_conn_send_reply(sconn, reply);
    dbus_message_unref(reply);
    talloc_free(infp_getcached_req);
    return EOK;

error:
    talloc_free(infp_getcached_req);
    return ret;
}

struct infp_createuser_ctx {
    struct infp_req_ctx *infp_req;
    struct sysdb_req *sysdb_req;

    char *username;
    char *fullname;
    char *homedir;
    char *shell;
};

static void infp_do_user_create_callback(void *pvt,
                                         int status,
                                         struct ldb_result *res)
{
    char *error_msg = NULL;
    DBusMessage *reply = NULL;
    struct infp_createuser_ctx *infp_createuser_req = talloc_get_type(pvt, struct infp_createuser_ctx);

    /* Commit the transaction if it we got a successful response, or cancel it if we did not */
    sysdb_transaction_done(infp_createuser_req->sysdb_req, status);

    /* Verify that the addition completed successfully
     * If LDB returned an error, run a search to determine
     * if it was due the requested username already being
     * in use
     */
    if (status == EOK) {
        /* Return reply ack */
        reply = dbus_message_new_method_return(infp_createuser_req->infp_req->req_message);
    }
    else if (status == EEXIST) {
        /* Return error, user already exists */
        error_msg = talloc_asprintf(infp_createuser_req,
                                    "User [%s] already exists on domain [%s]",
                                    infp_createuser_req->username,
                                    infp_createuser_req->infp_req->domain->name);
        reply = dbus_message_new_error(infp_createuser_req->infp_req->req_message,
                                       DBUS_ERROR_FILE_EXISTS,
                                       error_msg);
    }
    else {
        /* Unknown error occurred. Print DEBUG message */
        DEBUG(0, ("Failed to create user in the sysdb. Error code %d\n", status));
        talloc_free(infp_createuser_req);
        return;
    }

    if (reply) {
        sbus_conn_send_reply(infp_createuser_req->infp_req->sconn, reply);
        dbus_message_unref(reply);
    }
    talloc_free(infp_createuser_req);
}

static void infp_do_user_create(struct sysdb_req *req, void *pvt)
{
    int ret;
    struct infp_createuser_ctx *infp_createuser_req = talloc_get_type(pvt, struct infp_createuser_ctx);
    infp_createuser_req->sysdb_req = req;

    ret = sysdb_add_user(infp_createuser_req->sysdb_req,
                         infp_createuser_req->infp_req->domain,
                         infp_createuser_req->username,
                         0, 0,
                         infp_createuser_req->fullname,
                         infp_createuser_req->homedir,
                         infp_createuser_req->shell,
                         infp_do_user_create_callback,
                         infp_createuser_req);
    if (ret != EOK) {
        DEBUG(0, ("Could not invoke sysdb_add_user\n"));
        sysdb_transaction_done(infp_createuser_req->sysdb_req, ret);
        talloc_free(infp_createuser_req);
        return;
    }
}

int infp_users_create(DBusMessage *message, struct sbus_conn_ctx *sconn)
{
    DBusMessage *reply;
    DBusError error;
    dbus_bool_t dbret;
    char *einval_msg;
    struct infp_createuser_ctx *infp_createuser_req;
    int ret;

    /* Arguments */
    const char *arg_domain;
    const char *arg_username;
    const char *arg_fullname;
    const char *arg_homedir;
    const char *arg_shell;

    infp_createuser_req = talloc_zero(NULL, struct infp_createuser_ctx);
    if (infp_createuser_req == NULL) {
        ret = ENOMEM;
        goto error;
    }

    /* Create an infp_req_ctx */
    infp_createuser_req->infp_req = infp_req_init(infp_createuser_req,
                                                  message, sconn);
    if (infp_createuser_req->infp_req == NULL) {
        ret = EIO;
        goto error;
    }

    dbus_error_init(&error);
    dbret = dbus_message_get_args(message, &error,
                                  DBUS_TYPE_STRING, &arg_username,
                                  DBUS_TYPE_STRING, &arg_domain,
                                  DBUS_TYPE_STRING, &arg_fullname,
                                  DBUS_TYPE_STRING, &arg_homedir,
                                  DBUS_TYPE_STRING, &arg_shell,
                                  DBUS_TYPE_INVALID);
    if (!dbret) {
        DEBUG(0, ("Parsing arguments to %s failed: %s:%s\n", INFP_USERS_CREATE, error.name, error.message));
        einval_msg = talloc_strdup(infp_createuser_req, error.message);
        dbus_error_free(&error);
        goto einval;
    }

    /* FIXME: Allow creating users on domains other than LOCAL */
    if (strcasecmp(arg_domain, "LOCAL") != 0) {
        goto denied;
    }

    infp_createuser_req->infp_req->domain = btreemap_get_value(infp_createuser_req->infp_req->infp->domain_map,
                                                               (const void *)arg_domain);
    /* Check for a valid domain */
    if(infp_createuser_req->infp_req->domain == NULL) {
        einval_msg = talloc_strdup(infp_createuser_req, "Invalid domain.");
        goto einval;
    }

    if (strlen(arg_username)) {
        infp_createuser_req->username = talloc_strdup(infp_createuser_req, arg_username);
        if (infp_createuser_req->username == NULL) {
            ret = ENOMEM;
            goto error;
        }
    } else {
        einval_msg = talloc_strdup(infp_createuser_req, "No username provided");
        goto einval;
    }

    infp_createuser_req->fullname = NULL;
    if (strlen(arg_fullname)) {
        infp_createuser_req->fullname = talloc_strdup(infp_createuser_req, arg_username);
        if(infp_createuser_req->fullname == NULL) {
            ret = ENOMEM;
            goto error;
        }
    }

    infp_createuser_req->homedir = NULL;
    if (strlen(arg_homedir)) {
        infp_createuser_req->homedir = talloc_strdup(infp_createuser_req, arg_username);
        if(infp_createuser_req->homedir == NULL) {
            ret = ENOMEM;
            goto error;
        }
    }

    /* Check permissions */
    if(!infp_get_permissions(infp_createuser_req->infp_req->caller,
                             infp_createuser_req->infp_req->domain,
                             INFP_OBJ_TYPE_USER,
                             NULL,
                             INFP_ACTION_TYPE_CREATE,
                             INFP_ATTR_TYPE_INVALID)) goto denied;

    ret = sysdb_transaction(infp_createuser_req,
                            infp_createuser_req->infp_req->infp->sysdb,
                            infp_do_user_create,
                            infp_createuser_req);
    if (ret != EOK) {
        DEBUG(0,("Unable to start transaction to create user\n"));
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

    talloc_free(infp_createuser_req);
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
    talloc_free(infp_createuser_req);
    return EOK;

error:
    talloc_free(infp_createuser_req);
    return ret;
}

struct infp_deleteuser_ctx {
    struct infp_req_ctx *infp_req;
    char *username;
    struct sysdb_req *sysdb_req;
    struct ldb_dn *user_dn;
};

static void infp_do_user_delete_callback(void *pvt, int status,
                                         struct ldb_result *res)
{
    DBusMessage *reply = NULL;
    struct infp_deleteuser_ctx *infp_deleteuser_req =
        talloc_get_type(pvt, struct infp_deleteuser_ctx);

    /* Commit the transaction if it we got a successful response, or cancel it if we did not */
    sysdb_transaction_done(infp_deleteuser_req->sysdb_req, status);

    if (status != EOK) {
        DEBUG(0, ("Failed to delete user from sysdb. Error code %d", status));
        talloc_free(infp_deleteuser_req);
        return;
    }

    reply = dbus_message_new_method_return(infp_deleteuser_req->infp_req->req_message);
    if(reply) {
        sbus_conn_send_reply(infp_deleteuser_req->infp_req->sconn,
                             reply);
        dbus_message_unref(reply);
    }
    talloc_free(infp_deleteuser_req);
}

static void infp_do_user_delete(struct sysdb_req *req, void *pvt)
{
    int ret;
    struct infp_deleteuser_ctx *infp_deleteuser_req = talloc_get_type(pvt, struct infp_deleteuser_ctx);

    infp_deleteuser_req->sysdb_req = req;

    infp_deleteuser_req->user_dn = sysdb_user_dn(infp_deleteuser_req->infp_req->infp->sysdb,
                                                 infp_deleteuser_req,
                                                 infp_deleteuser_req->infp_req->domain->name,
                                                 infp_deleteuser_req->username);
    if(infp_deleteuser_req->user_dn == NULL) {
        DEBUG(0, ("Could not construct a user_dn for deletion.\n"));
        talloc_free(infp_deleteuser_req);
        return;
    }

    ret = sysdb_delete_entry(infp_deleteuser_req->sysdb_req,
                             infp_deleteuser_req->user_dn,
                             infp_do_user_delete_callback,
                             infp_deleteuser_req);
    if(ret != EOK) {
        DEBUG(0,("Could not delete user entry.\n"));
        talloc_free(infp_deleteuser_req);
        return;
    }
}

int infp_users_delete(DBusMessage *message, struct sbus_conn_ctx *sconn)
{
    DBusMessage *reply = NULL;
    DBusError error;
    dbus_bool_t dbret;
    char *einval_msg = NULL;
    struct infp_deleteuser_ctx *infp_deleteuser_req;
    int ret;

    /* Arguments */
    const char *arg_username;
    const char *arg_domain;

    infp_deleteuser_req = talloc_zero(NULL, struct infp_deleteuser_ctx);
    if (infp_deleteuser_req == NULL) {
        ret = ENOMEM;
        goto error;
    }

    /* Create an infp_req_ctx */
    infp_deleteuser_req->infp_req = infp_req_init(infp_deleteuser_req,
                                                  message,
                                                  sconn);
    if (infp_deleteuser_req->infp_req == NULL) {
        ret = EIO;
        goto error;
    }

    /* Process the arguments */
    dbus_error_init(&error);
    dbret = dbus_message_get_args(message, &error,
                                  DBUS_TYPE_STRING, &arg_username,
                                  DBUS_TYPE_STRING, &arg_domain,
                                  DBUS_TYPE_INVALID);
    if (!dbret) {
        DEBUG(0, ("Parsing arguments to %s failed: %s:%s\n",
                INFP_USERS_DELETE, error.name, error.message));
        einval_msg = talloc_strdup(infp_deleteuser_req, error.message);
        dbus_error_free(&error);
        goto einval;
    }

    /* FIXME: Allow deleting users from domains other than local */
    if(strcasecmp(arg_domain, "LOCAL") != 0) {
        goto denied;
    }

    infp_deleteuser_req->infp_req->domain =
        btreemap_get_value(infp_deleteuser_req->infp_req->infp->domain_map,
                           (const void *)arg_domain);
    /* Check for a valid domain */
    if(infp_deleteuser_req->infp_req->domain == NULL) {
        einval_msg = talloc_strdup(infp_deleteuser_req, "Invalid domain.");
        goto einval;
    }

    if (strlen(arg_username)) {
        infp_deleteuser_req->username = talloc_strdup(infp_deleteuser_req, arg_username);
        if (infp_deleteuser_req->username == NULL) {
            ret = ENOMEM;
            goto error;
        }
    } else {
        einval_msg = talloc_strdup(infp_deleteuser_req, "No username provided");
        goto einval;
    }

    /* Check permissions */
    if(!infp_get_permissions(infp_deleteuser_req->infp_req->caller,
                             infp_deleteuser_req->infp_req->domain,
                             INFP_OBJ_TYPE_USER,
                             NULL,
                             INFP_ACTION_TYPE_DELETE,
                             INFP_ACTION_TYPE_INVALID)) goto denied;

    ret = sysdb_transaction(infp_deleteuser_req,
                            infp_deleteuser_req->infp_req->infp->sysdb,
                            infp_do_user_delete,
                            infp_deleteuser_req);
    if (ret != EOK) {
        DEBUG(0, ("Unable to start transaction to delete user\n"));
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

    talloc_free(infp_deleteuser_req);
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
    talloc_free(infp_deleteuser_req);
    return EOK;

error:
    talloc_free(infp_deleteuser_req);
    return ret;
}

struct infp_getattr_ctx {
    struct infp_req_ctx *infp_req;
    char **usernames;
    uint32_t username_count;
    const char **attributes;
    uint32_t attr_count;
    uint32_t index;
    bool check_provider;

    /* The results array must have username_count elements */
    struct btreemap **results;
};

static int infp_get_attr_lookup(struct infp_getattr_ctx *infp_getattr_req);

struct infp_attr_variant {
    int dbus_type;
    int subtype;
    int count;
    void *data;
};

/* We are restricting variants to three basic types:
 * Fixed (Numeric) types
 * Strings
 * Arrays of fixed (numeric) types
 */
static int infp_user_getattr_append_dict(TALLOC_CTX *mem_ctx,
                                         DBusMessageIter *iter,
                                         struct btreemap *map)
{
    int ret, i;
    char **attrs;
    struct infp_attr_variant *value;
    char *vartype;
    char *subtype;
    int attr_count;
    DBusMessageIter array_iter;
    DBusMessageIter dict_iter;
    DBusMessageIter variant_iter;
    DBusMessageIter fixed_array_iter;
    dbus_bool_t dbret;

    ret = btreemap_get_keys(mem_ctx, map, (const void ***)&attrs, &attr_count);
    if (ret != EOK) {
        return ret;
    }

    /* DICTs are an array of dict pairs */
    dbret = dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "{sv}", &array_iter);
    if (!dbret) {
        ret = ENOMEM;
        goto error;
    }

    i = 0;
    while (i < attr_count) {
        if (strcasecmp(attrs[i], SYSDB_LAST_UPDATE) == 0) {
            /* Skip lastUpdate. We shouldn't be returning this */
            i++;
            continue;
        }

        /* Create the variant value */
        value = talloc_get_type(btreemap_get_value(map, attrs[i]), struct infp_attr_variant);
        if (value == NULL) {
            /* Skip any entries that returned an empty value */
            i++;
            continue;
        }

        /* Open a dict container for this pair */
        dbret = dbus_message_iter_open_container(&array_iter, DBUS_TYPE_DICT_ENTRY, NULL, &dict_iter);
        if (!dbret) {
            ret = ENOMEM;
            goto error;
        }
        /* Write the dict key */
        dbret = dbus_message_iter_append_basic(&dict_iter, DBUS_TYPE_STRING, &attrs[i]);
        if (!dbret) {
            ret = ENOMEM;
            goto error;
        }

        vartype = NULL;
        subtype = NULL;
        if (sbus_is_dbus_string_type(value->dbus_type)) {
            /* String types are strings, object paths and signatures */
            vartype = talloc_asprintf(mem_ctx, "%c", value->dbus_type);
            if (vartype == NULL) {
                ret = ENOMEM;
                goto error;
            }
            dbret = dbus_message_iter_open_container(&dict_iter, DBUS_TYPE_VARIANT, vartype, &variant_iter);
            if (!dbret) {
                ret = ENOMEM;
                goto error;
            }
            dbret = dbus_message_iter_append_basic(&variant_iter, DBUS_TYPE_STRING, &value->data);
            if (!dbret) {
                ret = ENOMEM;
                goto error;
            }
            talloc_free(vartype);
            vartype = NULL;
        }

        else if (sbus_is_dbus_fixed_type(value->dbus_type)) {
            /* Fixed types are booleans, bytes, the integral types and the floating-point types */
            vartype = talloc_asprintf(mem_ctx, "%c", value->dbus_type);
            if (vartype == NULL) {
                ret = ENOMEM;
                goto error;
            }
            dbret = dbus_message_iter_open_container(&dict_iter, DBUS_TYPE_VARIANT, vartype, &variant_iter);
            if (!dbret) {
                ret = ENOMEM;
                goto error;
            }
            dbret = dbus_message_iter_append_basic(&variant_iter, value->dbus_type, value->data);
            if (!dbret) {
                ret = ENOMEM;
                goto error;
            }
            talloc_free(vartype);
            vartype = NULL;
        }

        else if (value->dbus_type == DBUS_TYPE_ARRAY) {
            if(sbus_is_dbus_fixed_type(value->subtype)) {
                /* Only support adding arrays of fixed types or strings for now */

                subtype = talloc_asprintf(mem_ctx, "a%c", value->subtype);
                if (subtype == NULL) {
                    ret = ENOMEM;
                    goto error;
                }
                dbret = dbus_message_iter_open_container(&dict_iter, DBUS_TYPE_VARIANT, subtype, &variant_iter);
                if (!dbret) {
                    ret = ENOMEM;
                    goto error;
                }

                dbret = dbus_message_iter_open_container(&variant_iter, DBUS_TYPE_ARRAY, subtype, &fixed_array_iter);
                if (!dbret) {
                    ret = ENOMEM;
                    goto error;
                }

                dbret = dbus_message_iter_append_fixed_array(&fixed_array_iter, value->subtype, &value->data, value->count);
                if(!dbret) {
                    ret = ENOMEM;
                    goto error;
                }

                dbret = dbus_message_iter_close_container(&variant_iter, &fixed_array_iter);
                if(!dbret) {
                    ret = ENOMEM;
                    goto error;
                }
            }
            else {
                ret = EINVAL;
                goto error;
            }
        }

        else {
            /* Value type not yet supported */
            DEBUG(0, ("Attempted to create DICT value for something not a basic type or fixed array [%d]\n", value->dbus_type));
            ret = EINVAL;
            goto error;
        }

        /* Close the variant */
        dbret = dbus_message_iter_close_container(&dict_iter, &variant_iter);
        if(!dbret) {
            ret = ENOMEM;
            goto error;
        }

        /* Close the dict */
        dbret = dbus_message_iter_close_container(&array_iter, &dict_iter);
        if(!dbret) {
            ret = ENOMEM;
            goto error;
        }
        i++;
    }

    /* Close the dict array */
    dbret = dbus_message_iter_close_container(iter, &array_iter);
    if(!dbret) {
        ret = ENOMEM;
        goto error;
    }

    return EOK;

error:
    talloc_free(attrs);
    talloc_free(vartype);
    talloc_free(subtype);
    return ret;
}

static int create_getattr_result_map(TALLOC_CTX *mem_ctx, struct infp_getattr_ctx *infp_getattr_req,
                                     struct ldb_result *res, struct btreemap **results)
{
    int i, ret;
    int attr_type;
    struct infp_attr_variant *variant;
    const struct ldb_val *val;

    /* Iterate through the requested attributes */
    for (i=0; i < infp_getattr_req->attr_count; i++) {
        /* Ignore any attributes we don't care about */
        attr_type = infp_get_attribute_type(infp_getattr_req->attributes[i]);
        if (attr_type != INFP_ATTR_TYPE_INVALID) {
            variant = talloc_zero(mem_ctx, struct infp_attr_variant);
            if (variant == NULL) {
                ret = ENOMEM;
                goto end;
            }

            variant->dbus_type = infp_get_user_attr_dbus_type(attr_type, &variant->subtype);
            if (sbus_is_dbus_string_type(variant->dbus_type)) {
                variant->data = (void *)talloc_strdup(variant, ldb_msg_find_attr_as_string(res->msgs[0],
                                                                                           infp_getattr_req->attributes[i], NULL));
                if (variant->data == NULL) {
                    talloc_free(variant);
                    continue;
                }
            }
            else if (sbus_is_dbus_fixed_type(variant->dbus_type)) {
                /* We'll treat all fixed(numeric) types as UINT64 internally
                 * These will be correctly converted to their true types
                 * when being marshalled on the wire.
                 */
                variant->data = (void *)talloc(variant, uint64_t);
                if (variant->data == NULL) {
                    talloc_free(variant);
                    continue;
                }

                *(uint64_t *)variant->data = ldb_msg_find_attr_as_uint64(res->msgs[0], infp_getattr_req->attributes[i], 0);
            }
            else if (variant->dbus_type == DBUS_TYPE_ARRAY) {
                switch(variant->subtype) {
                case DBUS_TYPE_BYTE:
                    /* Byte array (binary data) */
                    val = ldb_msg_find_ldb_val(res->msgs[0], infp_getattr_req->attributes[i]);
                    if (val == NULL || val->length <= 0) {
                        talloc_free(variant);
                        continue;
                    }
                    variant->data = talloc_memdup(variant, val->data, val->length);
                    if (variant->data == NULL) {
                        talloc_free(variant);
                        continue;
                    }
                    variant->count = val->length;
                    break;

                default:
                    /* Unsupported array type */
                    talloc_free(variant);
                    continue;
                }

            }
            else {
                /* Unsupported type */
                talloc_free(variant);
                continue;
            }

            /* Add the variant to the map */
            ret = btreemap_set_value(mem_ctx, results, (const void *)infp_getattr_req->attributes[i], variant, attr_comparator);
            if (ret != EOK) {
                talloc_free(variant);
            }
        }
    }

    ret = EOK;

end:
    return ret;
}

static void infp_get_attr_lookup_callback(void *ptr, int ldb_status, struct ldb_result *res)
{
    int ret;
    int i;
    bool call_provider = false;
    int timeout;
    uint64_t lastUpdate;
    DBusMessage *reply = NULL;
    DBusMessageIter iter;
    DBusMessageIter array_iter;
    struct infp_getattr_ctx *infp_getattr_req = talloc_get_type(ptr, struct infp_getattr_ctx);

    DEBUG(9, ("Processing results for user [%s]\n", infp_getattr_req->usernames[infp_getattr_req->index]));

    /* Process the current results */
    if (ldb_status != LDB_SUCCESS) {
        DEBUG(0, ("Critical error reading from sysdb.\n"));
        goto done;
    }

    if(infp_getattr_req->check_provider) {
        switch(res->count) {
        case 0:
            call_provider = true;
            break;

        case 1:
            timeout = infp_getattr_req->infp_req->infp->cache_timeout;
            lastUpdate = ldb_msg_find_attr_as_uint64(res->msgs[0],
                                                     SYSDB_LAST_UPDATE, 0);
            if (lastUpdate + timeout < time(NULL)) {
                call_provider = true;
            }
            break;

        default:
            DEBUG(0, ("GetUser call returned more than one result. This probably means the sysdb is corrupt!\n"));
            goto done;
        }
    }

    if (call_provider) {
        /* FIXME call the provider */
    }

    switch (res->count) {
    case 0:
        DEBUG(2, ("No results for GetUser"));
        infp_getattr_req->results[infp_getattr_req->index] = NULL;
        break;

    case 1:
        /* Create the result map */
        ret = create_getattr_result_map(infp_getattr_req, infp_getattr_req, res,
                                        &infp_getattr_req->results[infp_getattr_req->index]);
        if (ret != EOK) {
            DEBUG(0, ("Unable to create result map!\n"));
            goto done;
        }
        break;
    default:
        /* We received more than one result. This is bad */
        DEBUG(0, ("GetUser call returned more than one result. This probably means the sysdb is corrupt!\n"));
        goto done;
    }

    /* If there are more usernames remaining in the list, re-enter the loop */
    infp_getattr_req->index++;
    if (infp_getattr_req->index < infp_getattr_req->username_count) {
        ret = infp_get_attr_lookup(infp_getattr_req);
        if (ret != EOK) {
            DEBUG(0, ("Could not read from cache database\n"));
            goto done;
        }
        return;
    }

    /* No more names remain, return the result DICTs */
    reply = dbus_message_new_method_return(infp_getattr_req->infp_req->req_message);
    if (reply == NULL) {
        goto done;
    }

    dbus_message_iter_init_append(reply, &iter);

    dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "a{sv}", &array_iter);
    i = 0;
    while (i < infp_getattr_req->username_count) {
        ret = infp_user_getattr_append_dict(infp_getattr_req, &array_iter, infp_getattr_req->results[i]);
        if (ret != EOK) {
            DEBUG(0, ("Unable to append response DICT\n"));
            goto done;
        }
        i++;
    }
    dbus_message_iter_close_container(&iter, &array_iter);

    sbus_conn_send_reply(infp_getattr_req->infp_req->sconn, reply);

done:
    if(reply) dbus_message_unref(reply);
    talloc_free(infp_getattr_req);
}

int infp_get_user_attr_dbus_type(int attr_type, int *subtype)
{
    int dbus_type;
    *subtype = DBUS_TYPE_INVALID;

    switch(attr_type) {
    case INFP_ATTR_TYPE_DEFAULTGROUP:
    case INFP_ATTR_TYPE_GECOS:
    case INFP_ATTR_TYPE_HOMEDIR:
    case INFP_ATTR_TYPE_SHELL:
    case INFP_ATTR_TYPE_FULLNAME:
    case INFP_ATTR_TYPE_LOCALE:
    case INFP_ATTR_TYPE_KEYBOARD:
    case INFP_ATTR_TYPE_SESSION:
        dbus_type = DBUS_TYPE_STRING;
        break;
    case INFP_ATTR_TYPE_LAST_LOGIN:
        dbus_type = DBUS_TYPE_UINT64;
        break;
    case INFP_ATTR_TYPE_USERPIC:
        dbus_type = DBUS_TYPE_ARRAY;
        *subtype = DBUS_TYPE_BYTE;
        break;
    default:
        dbus_type = DBUS_TYPE_INVALID;
    }
    return dbus_type;
}

static int attr_comparator(const void *key1, const void *key2)
{
    return strcmp((const char *)key1, (const char *)key2);
}

static int infp_get_attr_lookup(struct infp_getattr_ctx *infp_getattr_req)
{
    uint32_t i;
    int ret;
    char **attributes;
    const char *last_update;
    int attr_count;

    DEBUG(9, ("Processing lookup for user [%s]\n", infp_getattr_req->usernames[infp_getattr_req->index]));

    if (infp_getattr_req->index >= infp_getattr_req->username_count) {
        /* Avoid index bound issues */
        return EINVAL;
    }

    /* Check permissions */
    i=0;
    infp_getattr_req->results[infp_getattr_req->index] = NULL;
    while(i < infp_getattr_req->attr_count) {
        if(infp_get_permissions(infp_getattr_req->infp_req->caller,
                                infp_getattr_req->infp_req->domain,
                                INFP_OBJ_TYPE_USER,
                                infp_getattr_req->usernames[infp_getattr_req->index],
                                INFP_ACTION_TYPE_READ,
                                infp_get_attribute_type(infp_getattr_req->attributes[i]))
        ) {
            /* Add this attribute as a key to the result map
             * This will guarantee that we are requesting only unique attributes
             * that we have permission to read
             */
            ret = btreemap_set_value(infp_getattr_req, &infp_getattr_req->results[infp_getattr_req->index],
                                     infp_getattr_req->attributes[i], NULL, attr_comparator);
            if (ret != EOK) {
                return ret;
            }
        }
        i++;
    }

    /* Always add SYSDB_LAST_UPDATE to the list, we won't return it */
    last_update = talloc_strdup(infp_getattr_req, SYSDB_LAST_UPDATE);
    ret = btreemap_set_value(infp_getattr_req, &infp_getattr_req->results[infp_getattr_req->index],
                             last_update, NULL, attr_comparator);
    if (ret != EOK) {
        return ret;
    }

    /* Prepare the list of attributes to request from the sysdb */
    attr_count = 0;
    ret = btreemap_get_keys(infp_getattr_req,
                            infp_getattr_req->results[infp_getattr_req->index],
                            (const void ***)&attributes, &attr_count);
    if (ret != EOK) {
        return ret;
    }

    if (attr_count == 1) {
        /* There were zero authorized attributes in the list
         * No need to call sysdb, just move to the next username
         * The single attribute was SYSDB_LAST_UPDATE which we
         * added manually.
         */
        infp_getattr_req->index++;
        return infp_get_attr_lookup(infp_getattr_req);
    }

    /* Add a trailing NULL entry (required for sysdb) */
    attributes = talloc_realloc(infp_getattr_req, attributes, char *, attr_count+1);
    if (attributes == NULL) {
        return ENOMEM;
    }
    attributes[attr_count] = NULL;

    /* Call into the sysdb for the requested attributes */
    ret = sysdb_get_user_attr(infp_getattr_req,
                              infp_getattr_req->infp_req->infp->sysdb,
                              infp_getattr_req->infp_req->domain->name,
                              infp_getattr_req->usernames[infp_getattr_req->index],
                              (const char **)attributes,
                              infp_getattr_req->infp_req->domain->legacy,
                              infp_get_attr_lookup_callback, infp_getattr_req);

    return EOK;
}

static const char **infp_get_all_attributes(TALLOC_CTX *mem_ctx,
                                            uint32_t *attr_count)
{
    const char **attributes;
    int offset = 0;

    *attr_count = 10;
    attributes = talloc_array(mem_ctx, const char *, *attr_count);
    if (attributes == NULL) {
        return NULL;
    }

    attributes[offset++] = SYSDB_USER_ATTR_DEFAULTGROUP;
    attributes[offset++] = SYSDB_USER_ATTR_GECOS;
    attributes[offset++] = SYSDB_USER_ATTR_HOMEDIR;
    attributes[offset++] = SYSDB_USER_ATTR_SHELL;
    attributes[offset++] = SYSDB_USER_ATTR_FULLNAME;
    attributes[offset++] = SYSDB_USER_ATTR_LOCALE;
    attributes[offset++] = SYSDB_USER_ATTR_KEYBOARD;
    attributes[offset++] = SYSDB_USER_ATTR_SESSION;
    attributes[offset++] = SYSDB_USER_ATTR_LAST_LOGIN;
    attributes[offset++] = SYSDB_USER_ATTR_USERPIC;

    return attributes;
}

/* GetUserAttributes(ARRAY(STRING) usernames,
 *                   STRING domain,
 *                   ARRAY(STRING) filter)
 */
int infp_users_get_attr(DBusMessage *message, struct sbus_conn_ctx *sconn)
{
    int ret, i;
    DBusMessage *reply;
    DBusError error;
    dbus_bool_t dbret;
    char **usernames;
    uint32_t username_count;
    char *domain;
    char **attributes;
    uint32_t attr_count;
    struct infp_getattr_ctx *infp_getattr_req;

    usernames = NULL;
    attributes = NULL;
    /* Get the arguments to GetAttributes */
    dbus_error_init(&error);
    dbret = dbus_message_get_args(message, &error,
                                  DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &usernames, &username_count,
                                  DBUS_TYPE_STRING, &domain,
                                  DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &attributes, &attr_count,
                                  DBUS_TYPE_INVALID);
    if(!dbret) {
        DEBUG(0, ("Parsing arguments failed: %s:%s\n", error.name, error.message));
        dbus_free_string_array(usernames);
        dbus_free_string_array(attributes);

        reply = dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS, error.message);
        if (reply == NULL) {
            return ENOMEM;
        }
        sbus_conn_send_reply(sconn, reply);

        dbus_message_unref(reply);
        dbus_error_free(&error);

        return EOK;
    }

    if (username_count < 1) {
        /* No usernames received. Return an error */
        reply = dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS, "No usernames specified.");
        if (reply == NULL) {
            ret = ENOMEM;
            goto end;
        }
        sbus_conn_send_reply(sconn, reply);

        dbus_free_string_array(usernames);
        dbus_free_string_array(attributes);
        dbus_message_unref(reply);
        ret = EOK;
        goto end;
    }

    /* Create a infp_getattr_ctx */
    infp_getattr_req = talloc_zero(NULL, struct infp_getattr_ctx);
    if (infp_getattr_req == NULL) {
        ret = ENOMEM;
        goto end;
    }

    /* Create an infp_req_ctx */
    infp_getattr_req->infp_req = infp_req_init(infp_getattr_req,
                                               message, sconn);
    if (infp_getattr_req->infp_req == NULL) {
        ret = EIO;
        goto end;
    }

    infp_getattr_req->infp_req->domain = btreemap_get_value(infp_getattr_req->infp_req->infp->domain_map, (const void *)domain);
    infp_getattr_req->check_provider = strcasecmp(domain, "LOCAL");

    /* Copy the username list */
    infp_getattr_req->usernames = talloc_array(infp_getattr_req, char *, username_count);
    if (infp_getattr_req->usernames == NULL) {
        ret = ENOMEM;
        goto end;
    }

    i = 0;
    while (i < username_count) {
        DEBUG(9, ("Request for user [%s]\n", usernames[i]));
        infp_getattr_req->usernames[i] = talloc_strdup(infp_getattr_req->usernames, usernames[i]);
        if (infp_getattr_req == NULL) {
            ret = ENOMEM;
            goto end;
        }
        i++;
    }
    infp_getattr_req->username_count = username_count;

    /* Copy the attribute list */
    if (attr_count > 0) {
        infp_getattr_req->attributes = talloc_array(infp_getattr_req,
                                                   const char *, attr_count);
        if (infp_getattr_req->attributes == NULL) {
            ret = ENOMEM;
            goto end;
        }
        i = 0;
        while (i < attr_count) {
            infp_getattr_req->attributes[i] = talloc_strdup(infp_getattr_req, attributes[i]);
            if (infp_getattr_req == NULL) {
                ret = ENOMEM;
                goto end;
            }
            i++;
        }
        infp_getattr_req->attr_count = attr_count;
    } else {
        /* No attributes specified in the call means retrieve all possible */
        infp_getattr_req->attributes = infp_get_all_attributes(infp_getattr_req, &infp_getattr_req->attr_count);
        if (infp_getattr_req->attributes == NULL) {
            ret = ENOMEM;
            goto end;
        }
    }

    infp_getattr_req->index = 0;

    /* Prepare the result list */
    infp_getattr_req->results = talloc_array(infp_getattr_req, struct btreemap *, attr_count);
    if (infp_getattr_req->results == NULL) {
        ret = ENOMEM;
        goto end;
    }

    /* Look up the first username and start the async loop */
    ret = infp_get_attr_lookup(infp_getattr_req);
    if (ret != EOK) {
        DEBUG(0, ("Could not read from cache database\n"));
    }

end:
    dbus_free_string_array(usernames);
    dbus_free_string_array(attributes);
    if (ret != EOK) {
        talloc_free(infp_getattr_req);
    }
    return ret;
}

static int username_comparator(const void *key1, const void *key2)
{
    return strcmp((const char *)key1, (const char *)key2);
}

struct infp_setattr_ctx {
    struct infp_req_ctx *infp_req;
    const char **usernames;
    int username_count;
    uint32_t index;
    struct sysdb_req *sysdb_req;

    /* Array of sysdb_attrs objects
     * The number of elements in this array
     * is equal to the username count;
     */
    struct sysdb_attrs **changes;
};
static void infp_do_user_set_attr(struct sysdb_req *req, void *pvt);
static void infp_do_user_set_attr_callback(void *ptr, int ldb_status, struct ldb_result *res)
{
    DBusMessage *reply;
    struct infp_setattr_ctx *infp_setattr_req;

    infp_setattr_req = talloc_get_type(ptr, struct infp_setattr_ctx);

    /* Check the ldb_result */
    if (ldb_status != LDB_SUCCESS) {
        DEBUG(0, ("Failed to store user attributes to the sysdb\n"));
        /* Cancel the transaction */
        sysdb_transaction_done(infp_setattr_req->sysdb_req, sysdb_error_to_errno(ldb_status));
        talloc_free(infp_setattr_req);
        return;
    }

    /* Process any remaining users */
    infp_setattr_req->index++;
    if(infp_setattr_req->index < infp_setattr_req->username_count) {
        infp_do_user_set_attr(infp_setattr_req->sysdb_req, infp_setattr_req);
        return;
    }

    /* This was the last user. Commit the transaction */
    sysdb_transaction_done(infp_setattr_req->sysdb_req, EOK);

    /* Send reply ack */
    reply = dbus_message_new_method_return(infp_setattr_req->infp_req->req_message);
    if(reply == NULL) {
        talloc_free(infp_setattr_req);
        return;
    }
    sbus_conn_send_reply(infp_setattr_req->infp_req->sconn, reply);
    dbus_message_unref(reply);
    talloc_free(infp_setattr_req);
}

static void infp_do_user_set_attr(struct sysdb_req *req, void *pvt)
{
    int ret;
    struct infp_setattr_ctx *infp_setattr_req;

    infp_setattr_req = talloc_get_type(pvt, struct infp_setattr_ctx);
    infp_setattr_req->sysdb_req = req;

    DEBUG(9, ("Setting attributes for user [%s]\n", infp_setattr_req->usernames[infp_setattr_req->index]));
    ret = sysdb_set_user_attr(infp_setattr_req->sysdb_req,
                              infp_setattr_req->infp_req->infp->sysdb,
                              infp_setattr_req->infp_req->domain->name,
                              infp_setattr_req->usernames[infp_setattr_req->index],
                              infp_setattr_req->changes[infp_setattr_req->index],
                              infp_do_user_set_attr_callback, infp_setattr_req);
    if(ret != EOK) {
        DEBUG(0, ("Failed to set attributes for user [%s]. Cancelling transaction\n", infp_setattr_req->usernames[infp_setattr_req->index]));
        sysdb_transaction_done(req, ret);
        talloc_free(infp_setattr_req);
    }
}

int infp_users_set_attr(DBusMessage *message, struct sbus_conn_ctx *sconn)
{
    TALLOC_CTX *dict_ctx;
    DBusMessage *reply;
    DBusMessageIter iter, array_iter, dict_array_iter;
    DBusMessageIter dict_iter, variant_iter;
    dbus_bool_t dbret;
    char *domain_name;
    char *einval_msg;
    const char *recv_username;
    const char *dict_key;
    char *username;
    char *val_key;
    char *values;
    char **attributes;
    int user_count, change_count;
    int change_map_count, dict_entry_count;
    int added_entries;
    int current_type;
    int attr_type, variant_type;
    int subtype;
    struct infp_setattr_ctx *infp_setattr_req;
    struct btreemap *username_map;
    struct btreemap *value_map;
    struct btreemap *change_map;
    struct btreemap **change_array;
    struct btreemap **tmp_array;
    struct ldb_val *val;
    int ret, i, j;

    /* Create a infp_setattr_ctx */
    infp_setattr_req = talloc_zero(NULL, struct infp_setattr_ctx);
    if(infp_setattr_req == NULL) {
        ret = ENOMEM;
        goto error;
    }

    /* Create an infp_req_ctx */
    infp_setattr_req->infp_req = infp_req_init(infp_setattr_req,
                                               message, sconn);
    if (infp_setattr_req->infp_req == NULL) {
        ret = EIO;
        goto error;
    }

    /* Process the arguments to SetUserAttributes */
    dbret = dbus_message_iter_init(message, &iter);
    if (!dbret) {
        einval_msg = talloc_strdup(infp_setattr_req, "No arguments received.");
        goto einval;
    }

    /* Get the list of usernames to process */
    current_type = dbus_message_iter_get_arg_type(&iter);
    if (current_type != DBUS_TYPE_ARRAY) {
        einval_msg = talloc_strdup(infp_setattr_req, "Expected username list.");
        goto einval;
    }
    if(dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_STRING) {
        einval_msg = talloc_strdup(infp_setattr_req, "Expected username list.");
        goto einval;
    }
    /* Recurse into the array */
    user_count = 0;
    dbus_message_iter_recurse(&iter, &array_iter);
    username_map = NULL;
    while((current_type=dbus_message_iter_get_arg_type(&array_iter)) != DBUS_TYPE_INVALID) {
        dbus_message_iter_get_basic(&array_iter, &recv_username);
        username = talloc_strdup(infp_setattr_req, recv_username);
        if (username == NULL) {
            ret = ENOMEM;
            goto error;
        }
        ret = btreemap_set_value(infp_setattr_req, &username_map,
                                 (const void *)username, NULL, username_comparator);
        if (ret != EOK) goto error;

        user_count++;
        dbus_message_iter_next(&array_iter);
    }

    if (user_count == 0) {
        /* No users passed in */
        einval_msg = talloc_strdup(infp_setattr_req, "No usernames provided.");
        goto einval;
    }

    ret = btreemap_get_keys(infp_setattr_req, username_map,
                            (const void ***)&infp_setattr_req->usernames, &infp_setattr_req->username_count);
    if (ret != EOK) goto error;

    /* Verify that the usernames were all unique.
     * If the count of usernames we added differs from the count we're
     * getting back, then at least one was a duplicate.
     */
    if (infp_setattr_req->username_count != user_count) {
        einval_msg = talloc_strdup(infp_setattr_req, "Usernames were not unique.");
        goto einval;
    }

    /* Get the domain name */
    dbus_message_iter_next(&iter);
    if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING) {
        einval_msg = talloc_strdup(infp_setattr_req, "No domain provided.\n");
        goto einval;
    }
    dbus_message_iter_get_basic(&iter, &domain_name);

    infp_setattr_req->infp_req->domain = btreemap_get_value(infp_setattr_req->infp_req->infp->domain_map,
                                                            (const void *)domain_name);
    if(infp_setattr_req->infp_req->domain == NULL) {
        einval_msg = talloc_strdup(infp_setattr_req, "Invalid domain.");
        goto einval;
    }

    /* Get the array of change DICT entries */
    dbus_message_iter_next(&iter);
    current_type = dbus_message_iter_get_arg_type(&iter);
    if (current_type != DBUS_TYPE_ARRAY) {
        einval_msg = talloc_strdup(infp_setattr_req, "Expected change list.");
        goto einval;
    }
    if(dbus_message_iter_get_element_type(&iter) != DBUS_TYPE_ARRAY) {
        einval_msg = talloc_strdup(infp_setattr_req, "Expected array of DICT entry arrays.");
        goto einval;
    }

    change_count = 0;
    change_array = NULL;
    dbus_message_iter_recurse(&iter, &array_iter);
    if(dbus_message_iter_get_element_type(&array_iter) != DBUS_TYPE_DICT_ENTRY) {
        einval_msg = talloc_strdup(infp_setattr_req, "Expected array of DICT entries.");
        goto einval;
    }
    while((current_type=dbus_message_iter_get_arg_type(&array_iter)) != DBUS_TYPE_INVALID) {
        /* Descend into the DICT array */
        dbus_message_iter_recurse(&array_iter, &dict_array_iter);

        /* Create a new talloc context to contain the values from this DICT array */
        dict_ctx = talloc_new(infp_setattr_req);
        if(dict_ctx == NULL) {
            ret = ENOMEM;
            goto error;
        }
        value_map = NULL;
        dict_entry_count = 0;

        while((current_type=dbus_message_iter_get_arg_type(&dict_array_iter)) != DBUS_TYPE_INVALID) {
            change_count++;
            /* Descend into the DICT entry */
            dbus_message_iter_recurse(&dict_array_iter, &dict_iter);
            /* Key must be a string */
            if (dbus_message_iter_get_arg_type(&dict_iter) != DBUS_TYPE_STRING) {
                einval_msg = talloc_strdup(infp_setattr_req, "DICT entries must be keyed on strings.");
                goto einval;
            }
            dbus_message_iter_get_basic(&dict_iter, &dict_key);
            if((attr_type = infp_get_attribute_type(dict_key)) == INFP_ATTR_TYPE_INVALID) {
                /* Continue to the next DICT entry (ignoring unrecognized attributes) */
                change_count--; /* Don't include ignored values in the count */
                dbus_message_iter_next(&dict_array_iter);
                continue;
            }
            val_key = talloc_strdup(dict_ctx, dict_key);
            if(val_key == NULL) {
                ret = ENOMEM;
                goto error;
            }

            /* Value is a variant */
            variant_type = infp_get_user_attr_dbus_type(attr_type, &subtype);
            if(variant_type == DBUS_TYPE_INVALID) {
                /* This shouldn't happen since the attr_type is valid.
                 * If this failed, it's a coding error.
                 */
                DEBUG(0, ("Critical error, valid attribute type could not be paired with a D-BUS type.\n"));
                ret = EIO;
                goto error;
            }

            dbus_message_iter_next(&dict_iter);
            if (dbus_message_iter_get_arg_type(&dict_iter) != DBUS_TYPE_VARIANT) {
                einval_msg = talloc_strdup(infp_setattr_req, "DICT value must be a variant.");
                goto einval;
            }
            dbus_message_iter_recurse(&dict_iter, &variant_iter);

            if (dbus_message_iter_get_arg_type(&variant_iter) != variant_type) {
                einval_msg = talloc_asprintf(infp_setattr_req, "DICT value did not match required type of key [%s]. Expected [%c], received [%c]\n", dict_key, variant_type, dbus_message_iter_get_arg_type(&dict_iter));
                goto einval;
            }

            if(variant_type == DBUS_TYPE_ARRAY) {
                current_type=dbus_message_iter_get_element_type(&variant_iter);
                if (!sbus_is_dbus_fixed_type(current_type)) {
                    /* We only support fixed-type arrays right now */
                    einval_msg = talloc_asprintf(infp_setattr_req, "Invalid array type.");
                }
            }

            ret = infp_get_ldb_val_from_dbus(dict_ctx, &variant_iter, &val, variant_type, subtype);
            if (ret != EOK) {
                /* Could not create an LDB val from this variant */
                DEBUG(0, ("Error, valid attribute type could not be converted to an ldb_val.\n"));
                goto error;
            }

            ret = btreemap_set_value(dict_ctx, &value_map,
                                     (const void *)val_key, val,
                                     attr_comparator);
            if (ret != EOK) {
                DEBUG(0, ("Could not add change value to the value map.\n"));
                goto error;
            }

            dict_entry_count++;
            dbus_message_iter_next(&dict_array_iter);
        }

        /* Verify that all of the dict entries were unique */
        ret = btreemap_get_keys(dict_ctx, value_map,
                                (const void ***)&values, &added_entries);
        if (ret != EOK) goto error;

        if (added_entries != dict_entry_count) {
            einval_msg = talloc_strdup(infp_setattr_req, "Attributes to change were not unique.");
            goto einval;
        }

        /* Add the map to an array */
        tmp_array = talloc_realloc(infp_setattr_req, change_array, struct btreemap *, change_count);
        if(tmp_array == NULL) {
            ret = ENOMEM;
            goto error;
        }
        change_array = tmp_array;
        change_array[change_count-1] = value_map;

        dbus_message_iter_next(&array_iter);
    }

    if (change_count != infp_setattr_req->username_count && change_count != 1) {
        /* Change counts must be one-to-one with the number of users,
         * or else exactly one for all users.
         */
        einval_msg = talloc_strdup(infp_setattr_req, "Count of change DICTs not equal to one or count of usernames.");
        goto einval;
    }

    /* Check permissions and create the sysdb_attrs change list */
    infp_setattr_req->changes = talloc_array(infp_setattr_req, struct sysdb_attrs *, infp_setattr_req->username_count);
    for (i = 0; i < infp_setattr_req->username_count; i++) {
        if (change_count == 1)
            change_map = change_array[0];
        else
            change_map = change_array[i];

        ret = btreemap_get_keys(dict_ctx, change_map,
                                (const void ***)&attributes, &change_map_count);
        if (ret != EOK) goto error;

        infp_setattr_req->changes[i] = sysdb_new_attrs(infp_setattr_req);
        if (infp_setattr_req->changes[i] == NULL) {
            ret = ENOMEM;
            goto error;
        }
        for (j = 0; j < change_map_count; j++) {
            /* Add it to the sydb_attrs change list if permission is granted */
            if (infp_get_permissions(infp_setattr_req->infp_req->caller,
                                     infp_setattr_req->infp_req->domain,
                                     INFP_OBJ_TYPE_USER,
                                     infp_setattr_req->usernames[i],
                                     INFP_ACTION_TYPE_MODIFY,
                                     infp_get_attribute_type(attributes[j])))
            {
                ret = sysdb_attrs_add_val(infp_setattr_req->changes[i], attributes[j],
                                          btreemap_get_value(change_map, attributes[j]));
                if (ret != EOK) {
                    goto error;
                }
            }
        }
    }

    infp_setattr_req->index = 0;
    ret = sysdb_transaction(infp_setattr_req, infp_setattr_req->infp_req->infp->sysdb,
                            infp_do_user_set_attr, infp_setattr_req);
    if (ret != EOK) {
        DEBUG(0, ("Could not write to the cache database.\n"))
        goto error;
    }

    return EOK;

einval:
    reply = dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS, einval_msg);
    if(reply == NULL) {
        ret = ENOMEM;
        goto error;
    }

    sbus_conn_send_reply(sconn, reply);
    dbus_message_unref(reply);

    talloc_free(infp_setattr_req);
    return EOK;

error:
    talloc_free(infp_setattr_req);
    return ret;
}

struct infp_setuid_ctx {
    struct infp_req_ctx *infp_req;
    struct sysdb_req *sysdb_req;
    struct sysdb_attrs *uid_attr;
    char *username;
};

static void infp_do_user_set_uid_callback(void *ptr, int ldb_status, struct ldb_result *res)
{
    DBusMessage *reply;
    struct infp_setuid_ctx *infp_setuid_req = talloc_get_type(ptr, struct infp_setuid_ctx);

    /* Commit or cancel the transaction, based on the ldb_status */
    sysdb_transaction_done(infp_setuid_req->sysdb_req, sysdb_error_to_errno(ldb_status));

    /* Check the LDB result */
    if (ldb_status != LDB_SUCCESS) {
        DEBUG(0, ("Failed to store user uid to the sysdb\n"));
        talloc_free(infp_setuid_req);
        return;
    }

    /* Send reply ack */
    reply = dbus_message_new_method_return(infp_setuid_req->infp_req->req_message);
    if(reply == NULL) {
        talloc_free(infp_setuid_req);
        return;
    }
    sbus_conn_send_reply(infp_setuid_req->infp_req->sconn, reply);
    dbus_message_unref(reply);
    talloc_free(infp_setuid_req);
}

static void infp_do_user_set_uid(struct sysdb_req *req, void *pvt)
{
    int ret;
    struct infp_setuid_ctx *infp_setuid_req;

    infp_setuid_req = talloc_get_type(pvt, struct infp_setuid_ctx);
    infp_setuid_req->sysdb_req = req;

    DEBUG(9, ("Setting UID for user [%s]\n", infp_setuid_req->username));
    ret = sysdb_set_user_attr(infp_setuid_req->sysdb_req,
                              infp_setuid_req->infp_req->infp->sysdb,
                              infp_setuid_req->infp_req->domain->name,
                              infp_setuid_req->username,
                              infp_setuid_req->uid_attr,
                              infp_do_user_set_uid_callback, infp_setuid_req);
    if (ret != EOK) {
        DEBUG(0, ("Could not invoke sysdb_set_user_attr"));
        sysdb_transaction_done(infp_setuid_req->sysdb_req, ret);
        talloc_free(infp_setuid_req);
        return;
    }
}

int infp_users_set_uid(DBusMessage *message, struct sbus_conn_ctx *sconn)
{
    DBusMessage *reply;
    DBusError error;
    dbus_bool_t dbret;
    char *einval_msg;
    struct infp_setuid_ctx *infp_setuid_req;
    int ret;

    /* Arguments */
    const char *arg_username;
    const char *arg_domain;
    const int arg_uid;

    infp_setuid_req = talloc_zero(NULL, struct infp_setuid_ctx);
    if (infp_setuid_req == NULL) {
        ret = ENOMEM;
        goto error;
    }

    /* Create an infp_req_ctx */
    infp_setuid_req->infp_req = infp_req_init(infp_setuid_req,
                                              message, sconn);
    if (infp_setuid_req->infp_req == NULL) {
        ret = EIO;
        goto error;
    }

    dbus_error_init(&error);
    dbret = dbus_message_get_args(message, &error,
                                  DBUS_TYPE_STRING, &arg_username,
                                  DBUS_TYPE_STRING, &arg_domain,
                                  DBUS_TYPE_UINT32, &arg_uid,
                                  DBUS_TYPE_INVALID);
    if (!dbret) {
        DEBUG(0, ("Parsing arguments to SetUserUID failed: %s:%s\n", error.name, error.message));
        einval_msg = talloc_strdup(infp_setuid_req, error.message);
        dbus_error_free(&error);
        goto einval;
    }

    infp_setuid_req->username = talloc_strdup(infp_setuid_req, arg_username);

    infp_setuid_req->infp_req->domain = btreemap_get_value(infp_setuid_req->infp_req->infp->domain_map,
                                                           (const void *)arg_domain);
    /* Check for a valid domain */
    if(infp_setuid_req->infp_req->domain == NULL) {
        einval_msg = talloc_strdup(infp_setuid_req, "Invalid domain.");
        goto einval;
    }

    /* Check the domain MIN and MAX */
    if((arg_uid < infp_setuid_req->infp_req->domain->id_min) || /* Requested UID < than minimum */
            ((infp_setuid_req->infp_req->domain->id_max > infp_setuid_req->infp_req->domain->id_min) && /* Maximum exists and is greater than minimum */
             (arg_uid > infp_setuid_req->infp_req->domain->id_max))) { /* Requested UID > maximum */
        einval_msg = talloc_asprintf(infp_setuid_req, "UID out of range for this domain. Minimum: %u Maximum: %u\n",
                                     infp_setuid_req->infp_req->domain->id_min,
                                     infp_setuid_req->infp_req->domain->id_max?infp_setuid_req->infp_req->domain->id_max:(uid_t)-1);
        goto einval;
    }

    /* Check permissions */
    if(!infp_get_permissions(infp_setuid_req->infp_req->caller,
                             infp_setuid_req->infp_req->domain,
                             INFP_OBJ_TYPE_USER,
                             infp_setuid_req->username,
                             INFP_ACTION_TYPE_MODIFY,
                             INFP_ATTR_TYPE_USERID))
    {
        reply = dbus_message_new_error(message, DBUS_ERROR_ACCESS_DENIED, NULL);
        if(reply == NULL) {
            ret = ENOMEM;
            goto error;
        }
        /* send reply */
        sbus_conn_send_reply(sconn, reply);
        dbus_message_unref(reply);

        talloc_free(infp_setuid_req);
        return EOK;
    }

    infp_setuid_req->uid_attr = sysdb_new_attrs(infp_setuid_req);
    if (infp_setuid_req->uid_attr == NULL) {
        ret = ENOMEM;
        goto error;
    }
    sysdb_attrs_add_long(infp_setuid_req->uid_attr, SYSDB_UIDNUM, arg_uid);

    ret = sysdb_transaction(infp_setuid_req, infp_setuid_req->infp_req->infp->sysdb,
                            infp_do_user_set_uid, infp_setuid_req);
    if(ret != EOK) {
        DEBUG(0, ("Could not write to the cache database.\n"));
        goto error;
    }

    return EOK;

einval:
    reply = dbus_message_new_error(message, DBUS_ERROR_NOT_SUPPORTED, einval_msg);
    if(reply == NULL) {
        ret = ENOMEM;
        goto error;
    }

    /* send reply */
    sbus_conn_send_reply(sconn, reply);
    dbus_message_unref(reply);

    talloc_free(infp_setuid_req);
    return EOK;

error:
    talloc_free(infp_setuid_req);
    return ret;
}
