/*
    SSSD

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2011 Red Hat

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


#include "src/responder/pam/pam_helpers.h"

struct pam_initgr_table_ctx {
    hash_table_t *id_table;
    char *name;
};

static void pam_initgr_cache_remove(struct tevent_context *ev,
                                    struct tevent_timer *te,
                                    struct timeval tv,
                                    void *pvt);

errno_t pam_initgr_cache_set(struct tevent_context *ev,
                             hash_table_t *id_table,
                             char *name,
                             long timeout)
{
    errno_t ret;
    hash_key_t key;
    hash_value_t val;
    int hret;
    struct tevent_timer *te;
    struct timeval tv;
    struct pam_initgr_table_ctx *table_ctx;

    ret = pam_initgr_check_timeout(id_table, name);
    if (ret == EOK) {
        /* user is already in the cache */
        goto done;
    }

    table_ctx = talloc_zero(id_table, struct pam_initgr_table_ctx);
    if (!table_ctx) return ENOMEM;

    table_ctx->id_table = id_table;
    table_ctx->name = talloc_strdup(table_ctx, name);
    if (!table_ctx->name) {
        ret = ENOMEM;
        goto done;
    }

    key.type = HASH_KEY_STRING;
    key.str = name;

    /* The value isn't relevant, since we're using
     * a timer to remove the entry.
     */
    val.type = HASH_VALUE_UNDEF;

    hret = hash_enter(id_table, &key, &val);
    if (hret != HASH_SUCCESS) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Could not update initgr cache for [%s]: [%s]\n",
               name, hash_error_string(hret));
        ret = EIO;
        goto done;
    } else {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "[%s] added to PAM initgroup cache\n",
               name);
    }

    /* Create a timer event to remove the entry from the cache */
    tv = tevent_timeval_current_ofs(timeout, 0);
    te = tevent_add_timer(ev, table_ctx, tv,
                          pam_initgr_cache_remove,
                          table_ctx);
    if (!te) {
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(table_ctx);
    }
    return ret;
}

static void pam_initgr_cache_remove(struct tevent_context *ev,
                                    struct tevent_timer *te,
                                    struct timeval tv,
                                    void *pvt)
{
    int hret;
    hash_key_t key;

    struct pam_initgr_table_ctx *table_ctx =
            talloc_get_type(pvt, struct pam_initgr_table_ctx);

    key.type = HASH_KEY_STRING;
    key.str = table_ctx->name;

    hret = hash_delete(table_ctx->id_table, &key);
    if (hret != HASH_SUCCESS
            && hret != HASH_ERROR_KEY_NOT_FOUND) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Could not clear [%s] from initgr cache: [%s]\n",
               table_ctx->name,
               hash_error_string(hret));
    } else {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "[%s] removed from PAM initgroup cache\n",
               table_ctx->name);
    }

    talloc_free(table_ctx);
}

errno_t pam_initgr_check_timeout(hash_table_t *id_table,
                                 char *name)
{
    hash_key_t key;
    hash_value_t val;
    int hret;

    key.type = HASH_KEY_STRING;
    key.str = name;

    hret = hash_lookup(id_table, &key, &val);
    if (hret != HASH_SUCCESS
            && hret != HASH_ERROR_KEY_NOT_FOUND) {
            DEBUG(SSSDBG_TRACE_ALL, "Error searching user [%s] in PAM cache.\n",
                                    name);
        return EIO;
    } else if (hret == HASH_ERROR_KEY_NOT_FOUND) {
        DEBUG(SSSDBG_TRACE_ALL, "User [%s] not found in PAM cache.\n", name);
        return ENOENT;
    }

    /* If there's a value here, then the cache
     * entry is still valid.
     */
    DEBUG(SSSDBG_TRACE_INTERNAL, "User [%s] found in PAM cache.\n", name);
    return EOK;
}

