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

#include <talloc.h>
#include <tevent.h>

#include "util/util.h"
#include "util/dlinklist.h"
#include "util/sss_ptr_hash.h"
#include "sbus/sbus_request.h"
#include "sbus/sbus_private.h"

static void
sbus_requests_disable_spies(struct sbus_request_list *item);

static void
sbus_requests_validate(struct sbus_request_list *list);

struct sbus_request_spy {
    struct sbus_request_list *item;
};

static int
sbus_requests_spy_destructor(struct sbus_request_spy *spy)
{
    struct sbus_request_list *item;

    item = spy->item;

    if (item->spy.conn == spy) {
        item->spy.conn = NULL;
        item->conn = NULL;
    } else {
        item->spy.req = NULL;
        item->req = NULL;
    }

    sbus_requests_finish(item, ERR_TERMINATED);
    sbus_requests_validate(item);

    return 0;
}

static struct sbus_request_spy *
sbus_requests_spy_create(TALLOC_CTX *mem_ctx,
                         struct sbus_request_list *item)
{
    struct sbus_request_spy *spy;

    spy = talloc_zero(mem_ctx, struct sbus_request_spy);
    if (spy == NULL) {
        return NULL;
    }

    spy->item = item;

    talloc_set_destructor(spy, sbus_requests_spy_destructor);

    return spy;
}

static errno_t
sbus_requests_attach_spies(struct sbus_request_list *item)
{
    item->spy.conn = sbus_requests_spy_create(item->conn, item);
    if (item->spy.conn == NULL) {
        return ENOMEM;
    }

    item->spy.req = sbus_requests_spy_create(item->req, item);
    if (item->spy.req == NULL) {
        return ENOMEM;
    }

    return EOK;
}

static void
sbus_requests_disable_spies(struct sbus_request_list *item)
{
    if (item->spy.req != NULL) {
        talloc_set_destructor(item->spy.req, NULL);
    }

    if (item->spy.conn != NULL) {
        talloc_set_destructor(item->spy.conn, NULL);
    }

    talloc_zfree(item->spy.req);
    talloc_zfree(item->spy.conn);
}

hash_table_t *
sbus_requests_init(TALLOC_CTX *mem_ctx)
{
    return sss_ptr_hash_create(mem_ctx, NULL, NULL);
}

errno_t
sbus_requests_add(hash_table_t *table,
                  const char *key,
                  struct sbus_connection *conn,
                  struct tevent_req *req,
                  const char *member,
                  bool is_dbus,
                  bool *_key_exists)
{
    TALLOC_CTX *tmp_ctx;
    struct sbus_request_list *list;
    struct sbus_request_list *item;
    bool key_exists = false;
    errno_t ret;

    if (key == NULL) {
        /* This is ok, since not all request are supposed to be multicasted.
         * The caller will continue as this was a new request.
         * And it simplifies the code. */
        *_key_exists = false;
        return EOK;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory!\n");
        return ENOMEM;
    }

    item = talloc_zero(tmp_ctx, struct sbus_request_list);
    if (item == NULL) {
        ret = ENOMEM;
        goto done;
    }

    item->ev = conn->ev;
    item->req = req;
    item->conn = conn;
    item->is_dbus = is_dbus;
    item->member = talloc_strdup(item, member);
    if (member != NULL && item->member == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sbus_requests_attach_spies(item);
    if (ret != EOK) {
        goto done;
    }

    /* First, check if the key already exist. If yes, check if the list
     * is valid and just append the item to the list if so. Otherwise,
     * the list is internally deleted and we can create a new one. */
    list = sss_ptr_hash_lookup(table, key, struct sbus_request_list);
    if (list != NULL) {
        key_exists = true;
        DLIST_ADD_END(list, item, struct sbus_request_list *);
        DEBUG(SSSDBG_TRACE_ALL, "Chaining request: %s\n", key);
        ret = EOK;
        goto done;
    }

    /* Otherwise create new hash entry and new list. */
    list = item;
    ret = sss_ptr_hash_add(table, key, list, struct sbus_request_list);

done:
    if (ret == EOK) {
        if (_key_exists != NULL) {
            *_key_exists = key_exists;
        }

        talloc_steal(table, item);
    }

    talloc_free(tmp_ctx);

    return ret;
}

struct sbus_request_list *
sbus_requests_lookup(hash_table_t *table,
                     const char *key)
{
    if (key == NULL) {
        /* This is ok, since not all request are supposed to be multicasted.
         * The caller will have an empty list ot send notification to.
         * And it simplifies the code. */
        return NULL;
    }

    return sss_ptr_hash_lookup(table, key, struct sbus_request_list);
}

void
sbus_requests_delete(struct sbus_request_list *list)
{
    struct sbus_request_list *current, *next;

    if (list == NULL) {
        return;
    }

    /* Find head of the list. */
    while (list->prev != NULL) {
        list = list->prev;
    }

    /* Freeing the first item will remove the list also from the table. */
    DLIST_FOR_EACH_SAFE(current, next, list) {
        sbus_requests_disable_spies(current);
        talloc_zfree(current);
    }
}

static void
sbus_requests_validate(struct sbus_request_list *list)
{
    struct sbus_request_list *current, *next;

    /* Find head of the list. */
    while (list->prev != NULL) {
        list = list->prev;
    }

    /* An item is invalid if either its request or associated connection
     * is freed before this sbus request has finished.
     *
     * The list is invalid only if all items are invalid or if the first
     * item that holds the actual request is invalid. If this is the case
     * we will remove this list and report it to the caller.
     *
     * The sbus request is always associated with the first item. If it
     * is invalid we must also terminate all other requests. */

    if (list->is_invalid) {
        DLIST_FOR_EACH_SAFE(current, next, list->next) {
            if (current->is_invalid) {
                continue;
            }

            sbus_requests_disable_spies(current);
            tevent_req_error(current->req, ERR_TERMINATED);
        }
    } else {
        DLIST_FOR_EACH_SAFE(current, next, list) {
            if (!current->is_invalid) {
                return;
            }
        }
    }

    sbus_requests_delete(list);
}

void
sbus_requests_finish(struct sbus_request_list *item,
                     errno_t error)
{
    if (item == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Bug: item is NULL\n");
        return;
    }

    if (item->is_invalid) {
        return;
    }

    /* Make sure that spies are disabled and this item is not handled
     * anymore. */
    sbus_requests_disable_spies(item);
    item->is_invalid = true;

    if (item->req == NULL) {
        return;
    }

    /* Defer callback so all requests are notified before callbacks are run. */
    tevent_req_defer_callback(item->req, item->ev);

    if (error != EOK) {
        tevent_req_error(item->req, error);
        return;
    }

    tevent_req_done(item->req);

    item->req = NULL;
}

void
sbus_requests_terminate_all(hash_table_t *table,
                            errno_t error)
{
    struct sbus_request_list *list;
    struct sbus_request_list *item;
    hash_value_t *values;
    unsigned long int num;
    unsigned long int i;
    int hret;

    hret = hash_values(table, &num, &values);
    if (hret != HASH_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get list of active requests "
              "[%d]: %s\n", hret, hash_error_string(hret));
        return;
    }

    for (i = 0; i < num; i++) {
        list = sss_ptr_get_value(&values[i], struct sbus_request_list);

        DLIST_FOR_EACH(item, list) {
            sbus_requests_finish(item, error);
        }

        sbus_requests_delete(list);
    }

    talloc_free(values);
}

void
sbus_requests_terminate_member(hash_table_t *table,
                               const char *member,
                               errno_t error)
{
    struct sbus_request_list *list;
    struct sbus_request_list *item;
    hash_value_t *values;
    unsigned long int num;
    unsigned long int i;
    int hret;

    hret = hash_values(table, &num, &values);
    if (hret != HASH_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get list of active requests "
              "[%d]: %s\n", hret, hash_error_string(hret));
        return;
    }

    for (i = 0; i < num; i++) {
        list = sss_ptr_get_value(&values[i], struct sbus_request_list);
        if ((member == NULL && list->member == NULL)
            || (member != NULL && list->member != NULL && strcmp(member, list->member) == 0)) {
            DLIST_FOR_EACH(item, list) {
                sbus_requests_finish(item, error);
            }
        }

        sbus_requests_delete(list);
    }

    talloc_free(values);
}
