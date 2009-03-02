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

int infp_users_get_cached(DBusMessage *message, struct sbus_conn_ctx *sconn)
{
    DBusMessage *reply;

    reply = dbus_message_new_error(message, DBUS_ERROR_NOT_SUPPORTED, "Not yet implemented");

    /* send reply */
    sbus_conn_send_reply(sconn, reply);

    dbus_message_unref(reply);
    return EOK;
}

int infp_users_create(DBusMessage *message, struct sbus_conn_ctx *sconn)
{
    DBusMessage *reply;

    reply = dbus_message_new_error(message, DBUS_ERROR_NOT_SUPPORTED, "Not yet implemented");

    /* send reply */
    sbus_conn_send_reply(sconn, reply);

    dbus_message_unref(reply);
    return EOK;
}

int infp_users_delete(DBusMessage *message, struct sbus_conn_ctx *sconn)
{
    DBusMessage *reply;

    reply = dbus_message_new_error(message, DBUS_ERROR_NOT_SUPPORTED, "Not yet implemented");

    /* send reply */
    sbus_conn_send_reply(sconn, reply);

    dbus_message_unref(reply);
    return EOK;
}

struct infp_getattr_ctx {
    char *caller;
    struct sss_domain_info *domain;
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

        DEBUG(99, ("DBUS_TYPE: [%c] for attribute [%s]\n", value->dbus_type, attrs[i]));

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
            DEBUG(99, ("Marshalling array, subtype [%c]\n", value->subtype));
            if(sbus_is_dbus_fixed_type(value->subtype)) {
                DEBUG(99, ("Marshalling fixed array\n"));
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
    DBusMessage *reply;
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
    talloc_free(infp_getattr_req);
}

int infp_get_user_attr_dbus_type(int attr_type, int *subtype)
{
    int dbus_type;

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
        if(infp_get_permissions(infp_getattr_req->caller,
                                infp_getattr_req->domain,
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
                              infp_getattr_req->domain,
                              infp_getattr_req->usernames[infp_getattr_req->index],
                              (const char **)attributes,
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
        sbus_conn_send_reply(sconn, reply);

        dbus_message_unref(reply);
        dbus_error_free(&error);

        return EOK;
    }

    if (username_count < 1) {
        /* No usernames received. Return an error */
        reply = dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS, "No usernames specified.");
        sbus_conn_send_reply(sconn, reply);

        dbus_free_string_array(usernames);
        dbus_free_string_array(attributes);
        dbus_message_unref(reply);
        ret = EOK;
    }

    /* Create a infp_getattr_ctx */
    infp_getattr_req = talloc_zero(NULL, struct infp_getattr_ctx);
    if (infp_getattr_req == NULL) {
        ret = ENOMEM;
        goto end;
    }

    /* Create an infp_req_ctx */
    infp_getattr_req->infp_req = talloc_zero(infp_getattr_req, struct infp_req_ctx);
    if (infp_getattr_req == NULL) {
        ret = ENOMEM;
        goto end;
    }
    infp_getattr_req->infp_req->infp = talloc_get_type(sbus_conn_get_private_data(sconn), struct infp_ctx);
    infp_getattr_req->infp_req->sconn = sconn;
    infp_getattr_req->infp_req->req_message = message;
    infp_getattr_req->domain = btreemap_get_value(infp_getattr_req->infp_req->infp->domain_map, (const void *)domain);
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

    infp_getattr_req->caller = sysbus_get_caller(infp_getattr_req, message, sconn);
    if (infp_getattr_req->caller == NULL) {
        ret = EIO;
        goto end;
    }

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

int infp_users_set_attr(DBusMessage *message, struct sbus_conn_ctx *sconn)
{
    DBusMessage *reply;

    reply = dbus_message_new_error(message, DBUS_ERROR_NOT_SUPPORTED, "Not yet implemented");

    /* send reply */
    sbus_conn_send_reply(sconn, reply);

    dbus_message_unref(reply);
    return EOK;
}

int infp_users_set_uid(DBusMessage *message, struct sbus_conn_ctx *sconn)
{
    DBusMessage *reply;

    reply = dbus_message_new_error(message, DBUS_ERROR_NOT_SUPPORTED, "Not yet implemented");

    /* send reply */
    sbus_conn_send_reply(sconn, reply);

    dbus_message_unref(reply);
    return EOK;
}
