/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2013 Red Hat

    InfoPipe responder: Utility functions

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

#include "db/sysdb.h"
#include "responder/ifp/ifp_private.h"

#define IFP_DEFAULT_ATTRS {SYSDB_NAME, SYSDB_UIDNUM,   \
                           SYSDB_GIDNUM, SYSDB_GECOS,  \
                           SYSDB_HOMEDIR, SYSDB_SHELL, \
                           NULL}

errno_t ifp_req_create(struct sbus_request *dbus_req,
                       struct ifp_ctx *ifp_ctx,
                       struct ifp_req **_ifp_req)
{
    struct ifp_req *ireq = NULL;
    errno_t ret;

    if (ifp_ctx->sysbus == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Responder not connected to sysbus!\n");
        return EINVAL;
    }

    ireq = talloc_zero(dbus_req, struct ifp_req);
    if (ireq == NULL) {
        return ENOMEM;
    }

    ireq->ifp_ctx = ifp_ctx;
    ireq->dbus_req = dbus_req;

    if (dbus_req->client == -1) {
        /* We got a sysbus message but couldn't identify the
         * caller? Bail out! */
        DEBUG(SSSDBG_CRIT_FAILURE,
              "BUG: Received a message without a known caller!\n");
        ret = EACCES;
        goto done;
    }

    ret = check_allowed_uids(dbus_req->client,
                             ifp_ctx->rctx->allowed_uids_count,
                             ifp_ctx->rctx->allowed_uids);
    if (ret == EACCES) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "User %"PRIi64" not in ACL\n", dbus_req->client);
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot check if user %"PRIi64" is present in ACL\n",
              dbus_req->client);
        goto done;
    }

    *_ifp_req = ireq;
    ret = EOK;
done:
    if (ret != EOK) {
        talloc_free(ireq);
    }
    return ret;
}

int ifp_req_create_handle_failure(struct sbus_request *dbus_req, errno_t err)
{
    if (err == EACCES) {
        return sbus_request_fail_and_finish(dbus_req,
                               sbus_error_new(dbus_req,
                                              DBUS_ERROR_ACCESS_DENIED,
                                              "User %"PRIi64" not in ACL\n",
                                              dbus_req->client));
    }

    return sbus_request_fail_and_finish(dbus_req,
                                        sbus_error_new(dbus_req,
                                            DBUS_ERROR_FAILED,
                                            "Cannot create IFP request\n"));
}

const char *ifp_path_strip_prefix(const char *path, const char *prefix)
{
    if (strncmp(path, prefix, strlen(prefix)) == 0) {
        return path + strlen(prefix);
    }

    return NULL;
}

/* The following path related functions are based on similar code in
 * storaged, just tailored to use talloc instead of glib
 */
char *ifp_bus_path_escape(TALLOC_CTX *mem_ctx, const char *path)
{
    size_t n;
    char *safe_path = NULL;
    TALLOC_CTX *tmp_ctx = NULL;

    /* The path must be valid */
    if (path == NULL) {
        return NULL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return NULL;
    }

    safe_path = talloc_strdup(tmp_ctx, "");
    if (safe_path == NULL) {
        goto done;
    }

    /* Special case for an empty string */
    if (strcmp(path, "") == 0) {
        /* the for loop would just fall through */
        safe_path = talloc_asprintf_append_buffer(safe_path, "_");
    }

    for (n = 0; path[n]; n++) {
        int c = path[n];
        /* D-Bus spec says:
         * *
         * * Each element must only contain the ASCII characters
         * "[A-Z][a-z][0-9]_"
         * */
        if ((c >= 'A' && c <= 'Z')
                || (c >= 'a' && c <= 'z')
                || (c >= '0' && c <= '9')) {
            safe_path = talloc_asprintf_append_buffer(safe_path, "%c", c);
            if (safe_path == NULL) {
                goto done;
            }
        } else {
            safe_path = talloc_asprintf_append_buffer(safe_path, "_%02x", c);
            if (safe_path == NULL) {
                goto done;
            }
        }
    }

    safe_path = talloc_steal(mem_ctx, safe_path);
done:
    talloc_free(tmp_ctx);
    return safe_path;
}

static inline int unhexchar(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }

    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }

    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }

    return -1;
}

char *ifp_bus_path_unescape(TALLOC_CTX *mem_ctx, const char *path)
{
    char *safe_path;
    const char *p;
    int a, b, c;
    TALLOC_CTX *tmp_ctx = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return NULL;
    }

    safe_path = talloc_strdup(tmp_ctx, "");
    if (safe_path == NULL) {
        goto done;
    }

    /* Special case for the empty string */
    if (strcmp(path, "_") == 0) {
        safe_path = talloc_steal(mem_ctx, safe_path);
        goto done;
    }

    for (p = path; *p; p++) {
        if (*p == '_') {
            /* There must be at least two more chars after underscore */
            if (p[1] == '\0' || p[2] == '\0') {
                safe_path = NULL;
                goto done;
            }

            if ((a = unhexchar(p[1])) < 0
                    || (b = unhexchar(p[2])) < 0) {
                /* Invalid escape code, let's take it literal then */
                c = '_';
            } else {
                c = ((a << 4) | b);
                p += 2;
            }
        } else  {
            c = *p;
        }

        safe_path = talloc_asprintf_append_buffer(safe_path, "%c", c);
        if (safe_path == NULL) {
            goto done;
        }
    }

    safe_path = talloc_steal(mem_ctx, safe_path);
done:
    talloc_free(tmp_ctx);
    return safe_path;
}

char *
_ifp_reply_objpath(TALLOC_CTX *mem_ctx, const char *base,
                   const char *part, ...)
{
    char *safe_part;
    char *path = NULL;
    va_list va;

    if (base == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Wrong object path base!\n");
        return NULL;
    }

    path = talloc_strdup(mem_ctx, base);
    if (path == NULL) return NULL;

    va_start(va, part);
    while (part != NULL) {
        safe_part = ifp_bus_path_escape(mem_ctx, part);
        if (safe_part == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not add [%s] to objpath\n", part);
            goto fail;
        }

        path = talloc_asprintf_append(path, "/%s", safe_part);
        talloc_free(safe_part);
        if (path == NULL) {
            goto fail;
        }

        part = va_arg(va, const char *);
    }
    va_end(va);

    return path;

fail:
    va_end(va);
    talloc_free(path);
    return NULL;
}

errno_t ifp_add_ldb_el_to_dict(DBusMessageIter *iter_dict,
                               struct ldb_message_element *el)
{
    DBusMessageIter iter_dict_entry;
    DBusMessageIter iter_dict_val;
    DBusMessageIter iter_array;
    dbus_bool_t dbret;
    unsigned int i;

    if (el == NULL) {
        return EINVAL;
    }

    dbret = dbus_message_iter_open_container(iter_dict,
                                             DBUS_TYPE_DICT_ENTRY, NULL,
                                             &iter_dict_entry);
    if (!dbret) {
        return ENOMEM;
    }

    /* Start by appending the key */
    dbret = dbus_message_iter_append_basic(&iter_dict_entry,
                                           DBUS_TYPE_STRING, &(el->name));
    if (!dbret) {
        return ENOMEM;
    }

    dbret = dbus_message_iter_open_container(&iter_dict_entry,
                                             DBUS_TYPE_VARIANT,
                                             DBUS_TYPE_ARRAY_AS_STRING
                                             DBUS_TYPE_STRING_AS_STRING,
                                             &iter_dict_val);
    if (!dbret) {
        return ENOMEM;
    }

    /* Open container for values */
    dbret = dbus_message_iter_open_container(&iter_dict_val,
                                 DBUS_TYPE_ARRAY, DBUS_TYPE_STRING_AS_STRING,
                                 &iter_array);
    if (!dbret) {
        return ENOMEM;
    }

    /* Now add all the values */
    for (i = 0; i < el->num_values; i++) {
        DEBUG(SSSDBG_TRACE_FUNC, "element [%s] has value [%s]\n",
              el->name, (const char *) el->values[i].data);

        dbret = dbus_message_iter_append_basic(&iter_array,
                                               DBUS_TYPE_STRING,
                                               &(el->values[i].data));
        if (!dbret) {
            return ENOMEM;
        }
    }

    dbret = dbus_message_iter_close_container(&iter_dict_val,
                                              &iter_array);
    if (!dbret) {
        return ENOMEM;
    }

    dbret = dbus_message_iter_close_container(&iter_dict_entry,
                                              &iter_dict_val);
    if (!dbret) {
        return ENOMEM;
    }

    dbret = dbus_message_iter_close_container(iter_dict,
                                              &iter_dict_entry);
    if (!dbret) {
        return ENOMEM;
    }

    return EOK;
}

static inline bool
attr_in_list(const char **list, size_t nlist, const char *str)
{
    size_t i;

    for (i = 0; i < nlist; i++) {
        if (strcasecmp(list[i], str) == 0) {
            break;
        }
    }

    return (i < nlist) ? true : false;
}

const char **
ifp_parse_attr_list(TALLOC_CTX *mem_ctx, const char *conf_str)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    const char **list = NULL;
    const char **res = NULL;
    int list_size;
    char **conf_list = NULL;
    int conf_list_size = 0;
    const char **allow = NULL;
    const char **deny = NULL;
    int ai = 0, di = 0, li = 0;
    int i;
    const char *defaults[] = IFP_DEFAULT_ATTRS;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return NULL;
    }

    if (conf_str) {
        ret = split_on_separator(tmp_ctx, conf_str, ',', true, true,
                                 &conf_list, &conf_list_size);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Cannot parse attribute ACL list  %s: %d\n", conf_str, ret);
            goto done;
        }

        allow = talloc_zero_array(tmp_ctx, const char *, conf_list_size);
        deny = talloc_zero_array(tmp_ctx, const char *, conf_list_size);
        if (allow == NULL || deny == NULL) {
            goto done;
        }
    }

    for (i = 0; i < conf_list_size; i++) {
        switch (conf_list[i][0]) {
            case '+':
                allow[ai] = conf_list[i] + 1;
                ai++;
                continue;
            case '-':
                deny[di] = conf_list[i] + 1;
                di++;
                continue;
            default:
                DEBUG(SSSDBG_CRIT_FAILURE, "ACL values must start with "
                      "either '+' (allow) or '-' (deny), got '%s'\n",
                      conf_list[i]);
                goto done;
        }
    }

    /* Assume the output will have to hold defauls and all the configured,
     * values, resize later
     */
    list_size = 0;
    while (defaults[list_size]) {
        list_size++;
    }
    list_size += conf_list_size;

    list = talloc_zero_array(tmp_ctx, const char *, list_size + 1);
    if (list == NULL) {
        goto done;
    }

    /* Start by copying explicitly allowed attributes */
    for (i = 0; i < ai; i++) {
        /* if the attribute is explicitly denied, skip it */
        if (attr_in_list(deny, di, allow[i])) {
            continue;
        }

        list[li] = talloc_strdup(list, allow[i]);
        if (list[li] == NULL) {
            goto done;
        }
        li++;

        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Added allowed attr %s to whitelist\n", allow[i]);
    }

    /* Add defaults */
    for (i = 0; defaults[i]; i++) {
        /* if the attribute is explicitly denied, skip it */
        if (attr_in_list(deny, di, defaults[i])) {
            continue;
        }

        list[li] = talloc_strdup(list, defaults[i]);
        if (list[li] == NULL) {
            goto done;
        }
        li++;

        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Added default attr %s to whitelist\n", defaults[i]);
    }

    res = talloc_steal(mem_ctx, list);
done:
    talloc_free(tmp_ctx);
    return res;
}

bool
ifp_attr_allowed(const char *whitelist[], const char *attr)
{
    size_t i;

    if (whitelist == NULL) {
        return false;
    }

    for (i = 0; whitelist[i]; i++) {
        if (strcasecmp(whitelist[i], attr) == 0) {
            break;
        }
    }

    return (whitelist[i]) ? true : false;
}
