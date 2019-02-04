/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2017 Red Hat

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

#include <errno.h>
#include <string.h>
#include <dbus/dbus.h>

#include "util/util.h"
#include "sbus/sbus_request.h"
#include "sbus/sbus_private.h"
#include "sbus/interface/sbus_iterator_readers.h"
#include "sbus/interface/sbus_iterator_writers.h"
#include "sbus/interface_dbus/sbus_dbus_server.h"

static errno_t
sbus_open_variant(DBusMessageIter *parent,
                  DBusMessageIter *sub,
                  const char *type)
{
    dbus_bool_t dbret;

    dbret = dbus_message_iter_open_container(parent, DBUS_TYPE_VARIANT,
                                             type, sub);
    if (!dbret) {
        return ENOMEM;
    }

    return EOK;
}

static errno_t
sbus_open_dict(DBusMessageIter *parent,
               DBusMessageIter *sub)
{
    dbus_bool_t dbret;

    dbret = dbus_message_iter_open_container(parent, DBUS_TYPE_ARRAY,
                DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
                DBUS_TYPE_STRING_AS_STRING
                DBUS_TYPE_VARIANT_AS_STRING
                DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
                sub);
    if (!dbret) {
        return ENOMEM;
    }

    return EOK;
}

static errno_t
sbus_open_dict_entry(DBusMessageIter *parent,
                     DBusMessageIter *sub)
{
    dbus_bool_t dbret;

    dbret = dbus_message_iter_open_container(parent, DBUS_TYPE_DICT_ENTRY,
                                             NULL, sub);
    if (!dbret) {
        return ENOMEM;
    }

    return EOK;
}

static errno_t
sbus_close_iterator(DBusMessageIter *parent,
                    DBusMessageIter *sub)
{
    dbus_bool_t dbret;

    dbret = dbus_message_iter_close_container(parent, sub);
    if (!dbret) {
        return EIO;
    }

    return EOK;
}

static errno_t
sbus_create_dummy_message(TALLOC_CTX *mem_ctx,
                          DBusMessage **_msg,
                          DBusMessageIter *_write_iter)
{
    DBusMessage *msg;
    errno_t ret;

    msg = dbus_message_new(DBUS_MESSAGE_TYPE_METHOD_CALL);
    if (msg == NULL) {
        return ENOMEM;
    }

    /* Set fake serial number for reply. */
    dbus_message_set_serial(msg, 1);

    ret = sbus_message_bound(mem_ctx, msg);
    if (ret != EOK) {
        dbus_message_unref(msg);
        return ret;
    }

    dbus_message_iter_init_append(msg, _write_iter);

    *_msg = msg;

    return EOK;
}

static errno_t
sbus_copy_iterator_value(DBusMessageIter *from,
                         DBusMessageIter *to);

static errno_t
sbus_copy_iterator_fixed_array(DBusMessageIter *from,
                               DBusMessageIter *to,
                               int type)
{
    DBusMessageIter from_sub;
    DBusMessageIter to_sub;
    dbus_bool_t dbret;
    const char *typestr;
    void *fixed;
    int count;

    typestr = dbus_message_type_to_string(type);
    if (typestr == NULL) {
        return ERR_INTERNAL;
    }

    dbret = dbus_message_iter_open_container(to, DBUS_TYPE_ARRAY,
                                             typestr, &to_sub);
    if (!dbret) {
        return EIO;
    }

    dbus_message_iter_recurse(from, &from_sub);
    dbus_message_iter_get_fixed_array(&from_sub, &fixed, &count);

    dbret = dbus_message_iter_append_fixed_array(&to_sub, type, &fixed, count);
    if (!dbret) {
        goto fail;
    }

    dbret = dbus_message_iter_close_container(to, &to_sub);
    if (!dbret) {
        goto fail;
    }

    return EOK;

fail:
    dbus_message_iter_abandon_container(to, &to_sub);
    return EIO;
}

static errno_t
sbus_copy_iterator_container(DBusMessageIter *from,
                             DBusMessageIter *to,
                             int type)
{
    DBusMessageIter from_sub;
    DBusMessageIter to_sub;
    const char *signature;
    dbus_bool_t dbret;
    errno_t ret;

    dbus_message_iter_recurse(from, &from_sub);

    if (type == DBUS_TYPE_DICT_ENTRY) {
        /* This is a special case. Dictionary entries do not have any specific
         * signature when we open their container. */
        signature = NULL;
    } else {
        signature = dbus_message_iter_get_signature(&from_sub);
        if (signature == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    dbret = dbus_message_iter_open_container(to, type, signature, &to_sub);
    if (!dbret) {
        return EIO;
    }

    ret = sbus_copy_iterator_value(&from_sub, &to_sub);
    if (ret != EOK) {
        ret = EIO;
        goto done;
    }

    dbret = dbus_message_iter_close_container(to, &to_sub);
    if (!dbret) {
        ret = EIO;
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        dbus_message_iter_abandon_container(to, &to_sub);
    }

    return ret;
}

static errno_t
sbus_copy_iterator_value(DBusMessageIter *from,
                         DBusMessageIter *to)
{
    void *basic;
    dbus_bool_t dbret;
    int element_type;
    int type;
    errno_t ret;

    do {
        type = dbus_message_iter_get_arg_type(from);

        if (type == DBUS_TYPE_INVALID) {
            /* We have reached the end of the message. */
            return EOK;
        }

        /* If this is a basic type, we just write it to its destination. */
        if (dbus_type_is_basic(type)) {
            dbus_message_iter_get_basic(from, &basic);
            dbret = dbus_message_iter_append_basic(to, type, &basic);
            if (!dbret) {
                return EIO;
            }

            continue;
        }

        if (type == DBUS_TYPE_ARRAY) {
            element_type = dbus_message_iter_get_element_type(from);

            /* Fixed types can be copied at once. Otherwise we treat it
             * as any other container. */
            if (dbus_type_is_fixed(element_type)) {
                ret = sbus_copy_iterator_fixed_array(from, to, element_type);
                if (ret != EOK) {
                    return ret;
                }

                continue;
            }
        }

        /* If this is a container, we need to descend into it and open
         * this container in the destination iterator. */
        if (dbus_type_is_container(type)) {
            ret = sbus_copy_iterator_container(from, to, type);
            if (ret != EOK) {
                return ret;
            }

            continue;
        }

        DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected type [%d]\n", type);
        return ERR_INTERNAL;
    } while (dbus_message_iter_next(from));

    return EOK;
}

static errno_t
sbus_copy_message_to_dictionary(const char *name,
                                DBusMessage *msg,
                                DBusMessageIter *to)
{
    DBusMessageIter entry;
    DBusMessageIter from;
    dbus_bool_t dbret;
    errno_t ret;

    /* Open dictionary entry iterator. */
    ret = sbus_open_dict_entry(to, &entry);
    if (ret != EOK) {
        return ret;
    }

    /* Append property name as key. */
    ret = sbus_iterator_write_s(&entry, name);
    if (ret != EOK) {
        goto done;
    }

    /* Open message iterator for reading. */
    dbret = dbus_message_iter_init(msg, &from);
    if (!dbret) {
        ret = ENOMEM;
        goto done;
    }

    ret = sbus_copy_iterator_value(&from, &entry);
    if (ret != EOK) {
        goto done;
    }

    ret = sbus_close_iterator(to, &entry);

done:
    if (ret != EOK) {
        dbus_message_iter_abandon_container(to, &entry);
    }

    return ret;
}

static errno_t
sbus_request_property(TALLOC_CTX *mem_ctx,
                      struct sbus_connection *conn,
                      struct sbus_router *router,
                      const struct sbus_sender *sender,
                      enum sbus_property_access access,
                      const char *destination,
                      const char *path,
                      const char *interface_name,
                      const char *property_name,
                      struct sbus_request **_sbus_req,
                      const struct sbus_property **_property)
{
    const struct sbus_property *property;
    struct sbus_request *sbus_req;
    struct sbus_interface *iface;
    enum sbus_request_type type;

    iface = sbus_router_paths_lookup(router->paths, path, interface_name);
    if (iface == NULL) {
        return ERR_SBUS_UNKNOWN_INTERFACE;
    }

    property = sbus_interface_find_property(iface, access, property_name);
    if (property == NULL) {
        return ERR_SBUS_UNKNOWN_PROPERTY;
    }

    switch (access) {
    case SBUS_PROPERTY_READABLE:
        type = SBUS_REQUEST_PROPERTY_GET;
        break;
    case SBUS_PROPERTY_WRITABLE:
        type = SBUS_REQUEST_PROPERTY_SET;
        break;
    default:
        return EINVAL;
    }

    sbus_req = sbus_request_create(mem_ctx, conn, type, destination,
                                   interface_name, property_name, path);
    if (sbus_req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create request data!\n");
        return ENOMEM;
    }

    sbus_req->sender = sbus_sender_copy(sbus_req, sender);
    if (sbus_req->sender == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to copy sender data!\n");
        talloc_free(sbus_req);
        return ENOMEM;
    }

    *_sbus_req = sbus_req;
    *_property = property;

    return EOK;
}

struct sbus_properties_get_state {
    struct {
        DBusMessageIter *root;
        DBusMessageIter variant;
    } iter;
};

static void sbus_properties_get_done(struct tevent_req *subreq);

static struct tevent_req *
sbus_properties_get_send(TALLOC_CTX *mem_ctx,
                         struct tevent_context *ev,
                         struct sbus_request *sbus_req,
                         struct sbus_router *router,
                         const char *interface_name,
                         const char *property_name,
                         DBusMessageIter *write_iterator)
{
    struct sbus_properties_get_state *state;
    const struct sbus_property *property;
    struct sbus_request *property_req;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    DEBUG(SSSDBG_TRACE_ALL, "Requesting property: %s.%s of %s\n",
          interface_name, property_name, sbus_req->path);

    req = tevent_req_create(mem_ctx, &state, struct sbus_properties_get_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    ret = sbus_request_property(state, sbus_req->conn, router, sbus_req->sender,
                                SBUS_PROPERTY_READABLE, sbus_req->destination,
                                sbus_req->path, interface_name, property_name,
                                &property_req, &property);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot request property %s.%s [%d]: %s\n",
              interface_name, property_name, ret, sss_strerror(ret));
        goto done;
    }

    ret = sbus_check_access(router->conn, property_req);
    if (ret != EOK) {
        goto done;
    }

    state->iter.root = write_iterator;
    ret = sbus_open_variant(state->iter.root, &state->iter.variant,
                            property->type);
    if (ret != EOK) {
        goto done;
    }

    subreq = property->invoker.issue(state, ev, property_req,
                                     NULL, /* no keygen */
                                     &property->handler,
                                     NULL, /* no read iterator*/
                                     &state->iter.variant,
                                     NULL  /* no key */);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, sbus_properties_get_done, req);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void
sbus_properties_get_done(struct tevent_req *subreq)
{
    struct sbus_properties_get_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sbus_properties_get_state);

    ret = sbus_invoker_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        dbus_message_iter_abandon_container(state->iter.root,
                                            &state->iter.variant);
        goto done;
    }

    ret = sbus_close_iterator(state->iter.root, &state->iter.variant);

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static errno_t
sbus_properties_get_recv(TALLOC_CTX *mem_ctx,
                         struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct sbus_properties_getall_state {
    struct tevent_context *ev;
    struct sbus_router *router;
    struct sbus_request *sbus_req;
    const char *interface_name;

    struct {
        DBusMessageIter *root;
        DBusMessageIter dict;
        DBusMessageIter entry;
    } iter;

    struct {
        DBusMessage *msg;
        DBusMessageIter write_iter;
    } dummy;

    const struct sbus_property *properties;
    struct {
        const struct sbus_property *current;
        size_t index;
    } property;
};

static errno_t sdap_properties_getall_next(struct tevent_req *req);
static void sbus_properties_getall_done(struct tevent_req *subreq);

static struct tevent_req *
sbus_properties_getall_send(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct sbus_request *sbus_req,
                            struct sbus_router *router,
                            const char *interface_name,
                            DBusMessageIter *write_iterator)
{
    struct sbus_properties_getall_state *state;
    struct sbus_interface *iface;
    struct tevent_req *req;
    errno_t ret;

    DEBUG(SSSDBG_TRACE_ALL, "Requesting all properties: %s of %s\n",
          interface_name, sbus_req->path);

    req = tevent_req_create(mem_ctx, &state,
                            struct sbus_properties_getall_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    iface = sbus_router_paths_lookup(router->paths, sbus_req->path,
                                     interface_name);
    if (iface == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Unknown interface: %s\n", interface_name);
        ret = ERR_SBUS_UNKNOWN_INTERFACE;
        goto done;
    }

    state->ev = ev;
    state->router = router;
    state->sbus_req = sbus_req;
    state->interface_name = interface_name;
    state->properties = iface->properties;
    state->iter.root = write_iterator;

    /* Open array of <key, value> pairs. */
    ret = sbus_open_dict(state->iter.root, &state->iter.dict);
    if (ret != EOK) {
        goto done;
    }

    ret = sdap_properties_getall_next(req);
    if (ret == EOK) {
        /* There were no properties to return, we must close the container
         * so an empty result is sent back to the caller. */
        ret = sbus_close_iterator(state->iter.root, &state->iter.dict);
        goto done;
    } else if (ret != EAGAIN) {
        dbus_message_iter_abandon_container(state->iter.root,
                                            &state->iter.dict);
    }

    ret = EAGAIN;

done:
    if (ret == EOK) {
        tevent_req_done(req);
        tevent_req_post(req, ev);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static errno_t
sdap_properties_getall_next(struct tevent_req *req)
{
    struct sbus_properties_getall_state *state;
    const struct sbus_property *property;
    struct tevent_req *subreq;
    errno_t ret;

    state = tevent_req_data(req, struct sbus_properties_getall_state);

    /* There are no properties available. */
    if (state->properties == NULL) {
        return EOK;
    }

    do {
        property = &state->properties[state->property.index];
        state->property.current = property;
        state->property.index++;

        /* There are no more properties available. */
        if (property->name == NULL) {
            return EOK;
        }

        /* We are interested only in readable properties. */
    } while (property->access != SBUS_PROPERTY_READABLE);

    /* Create new message that we will use to fake an Get method request.
     * We will then copy its reply to the GetAll dictionary. */
    ret = sbus_create_dummy_message(state, &state->dummy.msg,
                                    &state->dummy.write_iter);
    if (ret != EOK) {
        return ret;
    }

    subreq = sbus_properties_get_send(state, state->ev, state->sbus_req,
                                      state->router, state->interface_name,
                                      property->name, &state->dummy.write_iter);
    if (subreq == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, sbus_properties_getall_done, req);

    return EAGAIN;
}

static void sbus_properties_getall_done(struct tevent_req *subreq)
{
    struct sbus_properties_getall_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sbus_properties_getall_state);

    ret = sbus_properties_get_recv(state, subreq);
    talloc_zfree(subreq);
    switch (ret) {
    case EOK:
        ret = sbus_copy_message_to_dictionary(state->property.current->name,
                                              state->dummy.msg,
                                              &state->iter.dict);
        if (ret != EOK) {
            goto done;
        }
        break;
    case ENOENT:
    case EACCES:
    case EPERM:
        /* These errors are not fatal. We will just skip this property. */
        DEBUG(SSSDBG_TRACE_FUNC, "Unable to get property %s.%s [%d]: %s\n",
              state->interface_name, state->property.current->name,
              ret, sss_strerror(ret));
        break;
    default:
        DEBUG(SSSDBG_MINOR_FAILURE, "Unable to get property %s.%s [%d]: %s\n",
              state->interface_name, state->property.current->name,
              ret, sss_strerror(ret));
        goto done;
    }

    dbus_message_unref(state->dummy.msg);
    ret = sdap_properties_getall_next(req);
    if (ret == EAGAIN) {
        /* Continue with next property. */
        return;
    } else if (ret != EOK) {
        goto done;
    }

    ret = sbus_close_iterator(state->iter.root, &state->iter.dict);
    if (ret != EOK) {
        goto done;
    }

done:
    if (ret != EOK) {
        dbus_message_iter_abandon_container(state->iter.root,
                                            &state->iter.dict);
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static errno_t
sbus_properties_getall_recv(TALLOC_CTX *mem_ctx,
                            struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

static errno_t
sbus_properties_set_parse(TALLOC_CTX *mem_ctx,
                          DBusMessageIter *read_iter,
                          const char **_interface_name,
                          const char **_property_name)
{
    const char *interface_name;
    const char *property_name;
    errno_t ret;

    ret = sbus_iterator_read_s(mem_ctx, read_iter, &interface_name);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_iterator_read_s(mem_ctx, read_iter, &property_name);
    if (ret != EOK) {
        return ret;
    }

    *_interface_name = interface_name;
    *_property_name = property_name;

    return EOK;
}

struct sbus_properties_set_state {
    DBusMessageIter variant_iterator;
};

static void sbus_properties_set_done(struct tevent_req *subreq);

static struct tevent_req *
sbus_properties_set_send(TALLOC_CTX *mem_ctx,
                         struct tevent_context *ev,
                         struct sbus_request *sbus_req,
                         struct sbus_router *router,
                         DBusMessageIter *read_iterator)
{
    struct sbus_properties_set_state *state;
    const struct sbus_property *property;
    struct sbus_request *property_req;
    struct tevent_req *subreq;
    struct tevent_req *req;
    const char *interface_name;
    const char *property_name;
    char *signature;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct sbus_properties_set_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    ret = sbus_properties_set_parse(state, read_iterator, &interface_name,
                                    &property_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to parse input message [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    DEBUG(SSSDBG_TRACE_ALL, "Setting property: %s.%s of %s\n",
          interface_name, property_name, sbus_req->path);

    ret = sbus_request_property(state, sbus_req->conn, router, sbus_req->sender,
                                SBUS_PROPERTY_WRITABLE, sbus_req->destination,
                                sbus_req->path, interface_name, property_name,
                                &property_req, &property);
    if (ret != EOK) {
        goto done;
    }

    ret = sbus_check_access(router->conn, property_req);
    if (ret != EOK) {
        goto done;
    }

    if (dbus_message_iter_get_arg_type(read_iterator) != DBUS_TYPE_VARIANT) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Setter argument is not inside variant!\n");
        ret = ERR_SBUS_INVALID_TYPE;
        goto done;
    }

    /* Recurse into variant to get iterator for new property value. */
    dbus_message_iter_recurse(read_iterator, &state->variant_iterator);
    signature = dbus_message_iter_get_signature(&state->variant_iterator);
    if (strcmp(property->type, signature) != 0) {
        ret = EINVAL;
        goto done;
    }

    subreq = property->invoker.issue(state, ev, property_req,
                                     NULL, /* no keygen */
                                     &property->handler,
                                     &state->variant_iterator,
                                     NULL, /* no write iterator*/
                                     NULL  /* no key */);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, sbus_properties_set_done, req);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void
sbus_properties_set_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);

    ret = sbus_invoker_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static errno_t
sbus_properties_set_recv(TALLOC_CTX *mem_ctx,
                         struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

errno_t
sbus_register_properties(struct sbus_router *router)
{

    SBUS_INTERFACE(iface,
        org_freedesktop_DBus_Properties,
        SBUS_METHODS(
            SBUS_ASYNC(METHOD, org_freedesktop_DBus_Properties, Get,
                       sbus_properties_get_send, sbus_properties_get_recv,
                       router),
            SBUS_ASYNC(METHOD, org_freedesktop_DBus_Properties, Set,
                       sbus_properties_set_send, sbus_properties_set_recv,
                       router),
            SBUS_ASYNC(METHOD, org_freedesktop_DBus_Properties, GetAll,
                       sbus_properties_getall_send, sbus_properties_getall_recv,
                       router)
        ),
        SBUS_WITHOUT_SIGNALS,
        SBUS_WITHOUT_PROPERTIES
    );

    struct sbus_path paths[] = {
        {"/", &iface},
        {"/*", &iface},
        {NULL, NULL}
    };

    return sbus_router_add_path_map(router, paths);
}
