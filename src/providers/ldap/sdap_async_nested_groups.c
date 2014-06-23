/*
    SSSD

    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2013 Red Hat

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
#include <tevent.h>
#include <talloc.h>
#include <ldb.h>
#include <dhash.h>
#include <stdint.h>
#include <time.h>

#include "util/util.h"
#include "db/sysdb.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ldap/sdap_async_private.h"

#define sdap_nested_group_sysdb_search_users(domain, filter) \
    sdap_nested_group_sysdb_search((domain), (filter), true)

#define sdap_nested_group_sysdb_search_groups(domain, filter) \
    sdap_nested_group_sysdb_search((domain), (filter), false)

enum sdap_nested_group_dn_type {
    SDAP_NESTED_GROUP_DN_USER,
    SDAP_NESTED_GROUP_DN_GROUP,
    SDAP_NESTED_GROUP_DN_UNKNOWN
};

struct sdap_nested_group_member {
    enum sdap_nested_group_dn_type type;
    const char *dn;
    const char *user_filter;
    const char *group_filter;
};

struct sdap_nested_group_ctx {
    struct sss_domain_info *domain;
    struct sdap_options *opts;
    struct sdap_search_base **user_search_bases;
    struct sdap_search_base **group_search_bases;
    struct sdap_handle *sh;
    hash_table_t *users;
    hash_table_t *groups;
    bool try_deref;
    int deref_treshold;
    int max_nesting_level;
};

static struct tevent_req *
sdap_nested_group_process_send(TALLOC_CTX *mem_ctx,
                             struct tevent_context *ev,
                             struct sdap_nested_group_ctx *group_ctx,
                             int nesting_level,
                             struct sysdb_attrs *group);

static errno_t sdap_nested_group_process_recv(struct tevent_req *req);

static struct tevent_req *
sdap_nested_group_single_send(TALLOC_CTX *mem_ctx,
                              struct tevent_context *ev,
                              struct sdap_nested_group_ctx *group_ctx,
                              struct sdap_nested_group_member *members,
                              int num_members,
                              int num_groups_max,
                              int nesting_level);

static errno_t sdap_nested_group_single_recv(struct tevent_req *req);

static struct tevent_req *
sdap_nested_group_lookup_user_send(TALLOC_CTX *mem_ctx,
                                   struct tevent_context *ev,
                                   struct sdap_nested_group_ctx *group_ctx,
                                   struct sdap_nested_group_member *member);

static errno_t sdap_nested_group_lookup_user_recv(TALLOC_CTX *mem_ctx,
                                                  struct tevent_req *req,
                                                  struct sysdb_attrs **_user);

static struct tevent_req *
sdap_nested_group_lookup_group_send(TALLOC_CTX *mem_ctx,
                                    struct tevent_context *ev,
                                    struct sdap_nested_group_ctx *group_ctx,
                                    struct sdap_nested_group_member *member);

static errno_t sdap_nested_group_lookup_group_recv(TALLOC_CTX *mem_ctx,
                                                   struct tevent_req *req,
                                                   struct sysdb_attrs **_group);

static struct tevent_req *
sdap_nested_group_lookup_unknown_send(TALLOC_CTX *mem_ctx,
                                      struct tevent_context *ev,
                                      struct sdap_nested_group_ctx *group_ctx,
                                      struct sdap_nested_group_member *member);

static errno_t
sdap_nested_group_lookup_unknown_recv(TALLOC_CTX *mem_ctx,
                                      struct tevent_req *req,
                                      struct sysdb_attrs **_entry,
                                      enum sdap_nested_group_dn_type *_type);

static struct tevent_req *
sdap_nested_group_deref_send(TALLOC_CTX *mem_ctx,
                             struct tevent_context *ev,
                             struct sdap_nested_group_ctx *group_ctx,
                             struct ldb_message_element *members,
                             const char *group_dn,
                             int nesting_level);

static errno_t sdap_nested_group_deref_recv(struct tevent_req *req);

static errno_t
sdap_nested_group_extract_hash_table(TALLOC_CTX *mem_ctx,
                                     hash_table_t *table,
                                     unsigned long *_num_entries,
                                     struct sysdb_attrs ***_entries)
{
    struct sysdb_attrs **entries = NULL;
    struct sysdb_attrs *entry = NULL;
    hash_value_t *values;
    unsigned long num_entries;
    unsigned int i;
    bool hret;
    errno_t ret;

    hret = hash_values(table, &num_entries, &values);
    if (hret != HASH_SUCCESS) {
        ret = EIO;
        goto done;
    }

    if (num_entries > 0) {
        entries = talloc_array(mem_ctx, struct sysdb_attrs *, num_entries);
        if (entries == NULL) {
            ret = ENOMEM;
            goto done;
        }

        for (i = 0; i < num_entries; i++) {
            entry = talloc_get_type(values[i].ptr, struct sysdb_attrs);
            entries[i] = talloc_steal(entries, entry);
        }
    }

    if (_num_entries != NULL) {
        *_num_entries = num_entries;
    }

    if (_entries != NULL) {
        *_entries = entries;
    }

    ret = EOK;

done:
    talloc_free(values);

    if (ret != EOK) {
        talloc_free(entries);
    }

    return ret;
}

static errno_t sdap_nested_group_hash_entry(hash_table_t *table,
                                            struct sysdb_attrs *entry,
                                            const char *table_name)
{
    hash_key_t key;
    hash_value_t value;
    const char *name = NULL;
    errno_t ret;
    int hret;

    ret = sysdb_attrs_get_string(entry, SYSDB_ORIG_DN, &name);
    if (ret != EOK) {
        return ret;
    }

    DEBUG(SSSDBG_TRACE_ALL, "Inserting [%s] into hash table [%s]\n",
                             name, table_name);

    key.type = HASH_KEY_STRING;
    key.str = talloc_strdup(NULL, name);
    if (key.str == NULL) {
        return ENOMEM;
    }

    if (hash_has_key(table, &key)) {
        talloc_free(key.str);
        return EEXIST;
    }

    value.type = HASH_VALUE_PTR;
    value.ptr = entry;

    hret = hash_enter(table, &key, &value);
    if (hret != HASH_SUCCESS) {
        talloc_free(key.str);
        return EIO;
    }

    talloc_steal(table, key.str);
    talloc_steal(table, value.ptr);

    return EOK;
}

static errno_t
sdap_nested_group_hash_user(struct sdap_nested_group_ctx *group_ctx,
                            struct sysdb_attrs *user)
{
    return sdap_nested_group_hash_entry(group_ctx->users, user, "users");
}

static errno_t
sdap_nested_group_hash_group(struct sdap_nested_group_ctx *group_ctx,
                             struct sysdb_attrs *group)
{
    struct sdap_attr_map *map = group_ctx->opts->group_map;
    gid_t gid;
    errno_t ret;
    int32_t ad_group_type;
    bool posix_group = true;

    if (group_ctx->opts->schema_type == SDAP_SCHEMA_AD) {
        ret = sysdb_attrs_get_int32_t(group, SYSDB_GROUP_TYPE, &ad_group_type);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_int32_t failed.\n");
            return ret;
        }

        DEBUG(SSSDBG_TRACE_ALL, "AD group has type flags %#x.\n",
                                 ad_group_type);
        /* Only security groups from AD are considered for POSIX groups.
         * Additionally only global and universal group are taken to account
         * for trusted domains. */
        if (!(ad_group_type & SDAP_AD_GROUP_TYPE_SECURITY)
                || (IS_SUBDOMAIN(group_ctx->domain)
                    && (!((ad_group_type & SDAP_AD_GROUP_TYPE_GLOBAL)
                        || (ad_group_type & SDAP_AD_GROUP_TYPE_UNIVERSAL))))) {
            posix_group = false;
            gid = 0;
            DEBUG(SSSDBG_TRACE_FUNC, "Filtering AD group.\n");
        }
    }

    ret = sysdb_attrs_get_uint32_t(group, map[SDAP_AT_GROUP_GID].sys_name,
                                   &gid);
    if (ret == ENOENT || (ret == EOK && gid == 0) || !posix_group) {
        DEBUG(SSSDBG_TRACE_ALL,
             "The group's gid was %s\n", ret == ENOENT ? "missing" : "zero");
        DEBUG(SSSDBG_TRACE_INTERNAL,
             "Marking group as non-posix and setting GID=0!\n");
        if (ret == ENOENT || !posix_group) {
            ret = sysdb_attrs_add_uint32(group,
                                         map[SDAP_AT_GROUP_GID].sys_name, 0);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Failed to add a GID to non-posix group!\n");
                return ret;
            }
        }

        ret = sysdb_attrs_add_bool(group, SYSDB_POSIX, false);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Error: Failed to mark group as non-posix!\n");
            return ret;
        }
    } else if (ret != EOK) {
        return ret;
    }

    return sdap_nested_group_hash_entry(group_ctx->groups, group, "groups");
}

static errno_t sdap_nested_group_sysdb_search(struct sss_domain_info *domain,
                                              const char *filter,
                                              bool user)
{
    static const char *attrs[] = {SYSDB_CACHE_EXPIRE,
                                  SYSDB_UIDNUM,
                                  NULL};
    struct ldb_message **msgs = NULL;
    size_t count;
    time_t now = time(NULL);
    uint64_t expire;
    uid_t uid;
    errno_t ret;

    if (user) {
        ret = sysdb_search_users(NULL, domain, filter, attrs,
                                 &count, &msgs);
    } else {
        ret = sysdb_search_groups(NULL, domain, filter, attrs,
                                  &count, &msgs);
    }
    if (ret != EOK) {
        goto done;
    }

    if (count != 1) {
        DEBUG(SSSDBG_OP_FAILURE, "More than one entry found?\n");
        ret = EFAULT;
        goto done;
    }

    /* we found an object with this origDN in the sysdb,
     * check if it is valid */
    if (user) {
        uid = ldb_msg_find_attr_as_uint64(msgs[0], SYSDB_UIDNUM, 0);
        if (uid == 0) {
            DEBUG(SSSDBG_OP_FAILURE, "User with no UID?\n");
            ret = EINVAL;
            goto done;
        }
    }

    expire = ldb_msg_find_attr_as_uint64(msgs[0], SYSDB_CACHE_EXPIRE, 0);
    if (expire != 0 && expire <= now) {
        /* needs refresh */
        ret = EAGAIN;
        goto done;
    }

    /* valid object */
    ret = EOK;

done:
    talloc_zfree(msgs);
    return ret;
}

static errno_t
sdap_nested_group_check_cache(struct sdap_options *opts,
                              struct sss_domain_info *domain,
                              const char *member_dn,
                              enum sdap_nested_group_dn_type *_type)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct sdap_domain *sdap_domain = NULL;
    struct sss_domain_info *member_domain = NULL;
    char *sanitized_dn = NULL;
    char *filter = NULL;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    ret = sss_filter_sanitize(tmp_ctx, member_dn, &sanitized_dn);
    if (ret != EOK) {
        goto done;
    }

    filter = talloc_asprintf(tmp_ctx, "(%s=%s)", SYSDB_ORIG_DN, sanitized_dn);
    if (filter == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* determine correct domain of this member */
    sdap_domain = sdap_domain_get_by_dn(opts, member_dn);
    member_domain = sdap_domain == NULL ? domain : sdap_domain->dom;

    /* search in users */
    ret = sdap_nested_group_sysdb_search_users(member_domain, filter);
    if (ret == EOK || ret == EAGAIN) {
        /* user found */
        *_type = SDAP_NESTED_GROUP_DN_USER;
        goto done;
    } else if (ret != ENOENT) {
        /* error */
        goto done;
    }

    /* search in groups */
    ret = sdap_nested_group_sysdb_search_groups(member_domain, filter);
    if (ret == EOK || ret == EAGAIN) {
        /* group found */
        *_type = SDAP_NESTED_GROUP_DN_GROUP;
        goto done;
    } else if (ret != ENOENT) {
        /* error */
        goto done;
    }

    /* not found in the sysdb */
    ret = ENOENT;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static bool
sdap_nested_member_is_ent(struct sdap_nested_group_ctx *group_ctx,
                          const char *dn, char **filter, bool is_user)
{
    struct sdap_domain *sditer = NULL;
    bool ret = false;
    struct sdap_search_base **search_bases;

    DLIST_FOR_EACH(sditer, group_ctx->opts->sdom) {
        search_bases = is_user ? sditer->user_search_bases : \
                                 sditer->group_search_bases;

        ret = sss_ldap_dn_in_search_bases(group_ctx, dn, search_bases,
                                          filter);
        if (ret == true) {
            break;
        }
    }

    return ret;
}

static inline bool
sdap_nested_member_is_user(struct sdap_nested_group_ctx *group_ctx,
                           const char *dn, char **filter)
{
    return sdap_nested_member_is_ent(group_ctx, dn, filter, true);
}

static inline bool
sdap_nested_member_is_group(struct sdap_nested_group_ctx *group_ctx,
                            const char *dn, char **filter)
{
    return sdap_nested_member_is_ent(group_ctx, dn, filter, false);
}

static errno_t
sdap_nested_group_split_members(TALLOC_CTX *mem_ctx,
                                struct sdap_nested_group_ctx *group_ctx,
                                int nesting_level,
                                struct ldb_message_element *members,
                                struct sdap_nested_group_member **_missing,
                                int *_num_missing,
                                int *_num_groups)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct sdap_nested_group_member *missing = NULL;
    enum sdap_nested_group_dn_type type;
    char *dn = NULL;
    char *user_filter = NULL;
    char *group_filter = NULL;
    int num_missing = 0;
    int num_groups = 0;
    hash_key_t key;
    bool bret;
    bool is_user;
    bool is_group;
    errno_t ret;
    int i;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    missing = talloc_zero_array(tmp_ctx, struct sdap_nested_group_member,
                                members->num_values);
    if (missing == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* create list of missing members
     * skip dn if:
     * - is present in user or group hash table
     * - is present in sysdb and not expired
     * - it is a group and we have reached the maximal nesting level
     * - it is not under user nor group search bases
     *
     * if dn is in sysdb but expired
     * - we know what object type it is
     *
     * if dn is not in hash table or sysdb
     * - try to determine type of object by search base that match dn
     */
    for (i = 0; i < members->num_values; i++) {
        dn = (char*)members->values[i].data;
        type = SDAP_NESTED_GROUP_DN_UNKNOWN;

        /* check hash tables */
        key.type = HASH_KEY_STRING;
        key.str = dn;

        bret = hash_has_key(group_ctx->users, &key);
        if (bret) {
            continue;
        }

        bret = hash_has_key(group_ctx->groups, &key);
        if (bret) {
            continue;
        }

        /* check sysdb */
        ret = sdap_nested_group_check_cache(group_ctx->opts, group_ctx->domain,
                                            dn, &type);
        if (ret == EOK) {
            /* found and valid */
            DEBUG(SSSDBG_TRACE_ALL, "[%s] found in cache, skipping\n", dn);
            continue;
        } else if (ret != EAGAIN && ret != ENOENT) {
            /* error */
            goto done;
        }

        /* try to determine type by dn */
        if (type == SDAP_NESTED_GROUP_DN_UNKNOWN) {
            /* user */
            is_user = sdap_nested_member_is_user(group_ctx, dn,
                                                 &user_filter);

            is_group = sdap_nested_member_is_group(group_ctx, dn,
                                                   &group_filter);

            if (is_user && is_group) {
                /* search bases overlap */
                DEBUG(SSSDBG_TRACE_ALL, "[%s] is unknown object\n", dn);
                type = SDAP_NESTED_GROUP_DN_UNKNOWN;
            } else if (is_user) {
                DEBUG(SSSDBG_TRACE_ALL, "[%s] is a user\n", dn);
                type = SDAP_NESTED_GROUP_DN_USER;
            } else if (is_group) {
                DEBUG(SSSDBG_TRACE_ALL, "[%s] is a group\n", dn);
                type = SDAP_NESTED_GROUP_DN_GROUP;
            } else {
                /* dn is outside search bases */
                DEBUG(SSSDBG_TRACE_ALL, "[%s] is out of scope of configured "
                      "search bases, skipping\n", dn);
                continue;
            }
        }

        /* check nesting level */
        if (type == SDAP_NESTED_GROUP_DN_GROUP) {
            if (nesting_level >= group_ctx->max_nesting_level) {
                DEBUG(SSSDBG_TRACE_ALL, "[%s] is outside nesting limit "
                      "(level %d), skipping\n", dn, nesting_level);
                talloc_zfree(user_filter);
                talloc_zfree(group_filter);
                continue;
            }
        }

        missing[num_missing].dn = talloc_strdup(missing, dn);
        if (missing[num_missing].dn == NULL) {
            ret = ENOMEM;
            goto done;
        }

        missing[num_missing].type = type;
        missing[num_missing].user_filter = talloc_steal(missing, user_filter);
        missing[num_missing].group_filter = talloc_steal(missing, group_filter);

        num_missing++;

        if (type != SDAP_NESTED_GROUP_DN_USER) {
            num_groups++;
        }
    }

    missing = talloc_realloc(mem_ctx, missing,
                             struct sdap_nested_group_member, num_missing);
    /* talloc_realloc behaves as talloc_free if 3rd parameter (count) is 0,
     * so it's OK to return NULL then
     */
    if (missing == NULL && num_missing > 0) {
        ret = ENOMEM;
        goto done;
    }

    if (_missing) {
        *_missing = talloc_steal(mem_ctx, missing);
    }

    if (_num_missing) {
        *_num_missing = num_missing;
    }

    if (_num_groups) {
        *_num_groups = num_groups;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}


struct sdap_nested_group_state {
    struct sdap_nested_group_ctx *group_ctx;
};

static void sdap_nested_group_done(struct tevent_req *subreq);

struct tevent_req *
sdap_nested_group_send(TALLOC_CTX *mem_ctx,
                       struct tevent_context *ev,
                       struct sdap_domain *sdom,
                       struct sdap_options *opts,
                       struct sdap_handle *sh,
                       struct sysdb_attrs *group)
{
    struct sdap_nested_group_state *state = NULL;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    errno_t ret;
    int i;

    req = tevent_req_create(mem_ctx, &state, struct sdap_nested_group_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    /* create main nested group context */
    state->group_ctx = talloc_zero(state, struct sdap_nested_group_ctx);
    if (state->group_ctx == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    ret = sss_hash_create(state->group_ctx, 32, &state->group_ctx->users);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create hash table [%d]: %s\n",
                                    ret, strerror(ret));
        goto immediately;
    }

    ret = sss_hash_create(state->group_ctx, 32, &state->group_ctx->groups);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create hash table [%d]: %s\n",
                                    ret, strerror(ret));
        goto immediately;
    }

    state->group_ctx->try_deref = true;
    state->group_ctx->deref_treshold = dp_opt_get_int(opts->basic,
                                                      SDAP_DEREF_THRESHOLD);
    state->group_ctx->max_nesting_level = dp_opt_get_int(opts->basic,
                                                         SDAP_NESTING_LEVEL);
    state->group_ctx->domain = sdom->dom;
    state->group_ctx->opts = opts;
    state->group_ctx->user_search_bases = sdom->user_search_bases;
    state->group_ctx->group_search_bases = sdom->group_search_bases;
    state->group_ctx->sh = sh;
    state->group_ctx->try_deref = sdap_has_deref_support(sh, opts);

    /* disable deref if threshold <= 0 */
    if (state->group_ctx->deref_treshold <= 0) {
        state->group_ctx->try_deref = false;
    }

    /* if any search base contains filter, disable dereference. */
    if (state->group_ctx->try_deref) {
        for (i = 0; opts->sdom->user_search_bases[i] != NULL; i++) {
            if (opts->sdom->user_search_bases[i]->filter != NULL) {
                DEBUG(SSSDBG_TRACE_FUNC, "User search base contains filter, "
                                          "dereference will be disabled\n");
                state->group_ctx->try_deref = false;
                break;
            }
        }
    }

    if (state->group_ctx->try_deref) {
        for (i = 0; opts->sdom->group_search_bases[i] != NULL; i++) {
            if (opts->sdom->group_search_bases[i]->filter != NULL) {
                DEBUG(SSSDBG_TRACE_FUNC, "Group search base contains filter, "
                                          "dereference will be disabled\n");
                state->group_ctx->try_deref = false;
                break;
            }
        }
    }

    /* insert initial group into hash table */
    ret = sdap_nested_group_hash_group(state->group_ctx, group);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to insert group into hash table "
                                    "[%d]: %s\n", ret, strerror(ret));
        goto immediately;
    }

    /* resolve group */
    subreq = sdap_nested_group_process_send(state, ev, state->group_ctx,
                                            0, group);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, sdap_nested_group_done, req);

    return req;

immediately:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);

    return req;
}

static void sdap_nested_group_done(struct tevent_req *subreq)
{
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);

    ret = sdap_nested_group_process_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t sdap_nested_group_recv(TALLOC_CTX *mem_ctx,
                               struct tevent_req *req,
                               unsigned long *_num_users,
                               struct sysdb_attrs ***_users,
                               unsigned long *_num_groups,
                               struct sysdb_attrs ***_groups)
{
    struct sdap_nested_group_state *state = NULL;
    struct sysdb_attrs **users = NULL;
    struct sysdb_attrs **groups = NULL;
    unsigned long num_users;
    unsigned long num_groups;
    errno_t ret;

    state = tevent_req_data(req, struct sdap_nested_group_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    ret = sdap_nested_group_extract_hash_table(state, state->group_ctx->users,
                                               &num_users, &users);
    if (ret != EOK) {
        return ret;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "%lu users found in the hash table\n",
                              num_users);

    ret = sdap_nested_group_extract_hash_table(state, state->group_ctx->groups,
                                               &num_groups, &groups);
    if (ret != EOK) {
        return ret;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "%lu groups found in the hash table\n",
                              num_groups);

    if (_num_users != NULL) {
        *_num_users = num_users;
    }

    if (_users != NULL) {
        *_users = talloc_steal(mem_ctx, users);
    }

    if (_num_groups!= NULL) {
        *_num_groups = num_groups;
    }

    if (_groups != NULL) {
        *_groups = talloc_steal(mem_ctx, groups);
    }

    return EOK;
}

struct sdap_nested_group_process_state {
    struct tevent_context *ev;
    struct sdap_nested_group_ctx *group_ctx;
    struct sdap_nested_group_member *missing;
    int num_missing_total;
    int num_missing_groups;
    int nesting_level;
    char *group_dn;
    bool deref;
};

static void sdap_nested_group_process_done(struct tevent_req *subreq);

static struct tevent_req *
sdap_nested_group_process_send(TALLOC_CTX *mem_ctx,
                               struct tevent_context *ev,
                               struct sdap_nested_group_ctx *group_ctx,
                               int nesting_level,
                               struct sysdb_attrs *group)
{
    struct sdap_nested_group_process_state *state = NULL;
    struct sdap_attr_map *group_map = NULL;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct ldb_message_element *members = NULL;
    const char *orig_dn = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_nested_group_process_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->ev = ev;
    state->group_ctx = group_ctx;
    state->nesting_level = nesting_level;
    group_map = state->group_ctx->opts->group_map;

    /* get original dn */
    ret = sysdb_attrs_get_string(group, SYSDB_ORIG_DN, &orig_dn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to retrieve original dn "
                                    "[%d]: %s\n", ret, strerror(ret));
        goto immediately;
    }

    state->group_dn = talloc_strdup(state, orig_dn);
    if (state->group_dn == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "About to process group [%s]\n", orig_dn);

    /* get member list */
    ret = sysdb_attrs_get_el_ext(group, group_map[SDAP_AT_GROUP_MEMBER].sys_name,
                                 false, &members);
    if (ret == ENOENT) {
        ret = EOK; /* no members */
        goto immediately;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to retrieve member list "
                                    "[%d]: %s\n", ret, strerror(ret));
        goto immediately;
    }

    /* get members that need to be refreshed */
    ret = sdap_nested_group_split_members(state, state->group_ctx,
                                          state->nesting_level, members,
                                          &state->missing,
                                          &state->num_missing_total,
                                          &state->num_missing_groups);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to split member list "
                                    "[%d]: %s\n", ret, sss_strerror(ret));
        goto immediately;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "Looking up %d/%d members of group [%s]\n",
          state->num_missing_total, members->num_values, orig_dn);

    if (state->num_missing_total == 0) {
        ret = EOK; /* we're done */
        goto immediately;
    }

    /* process members */
    if (group_ctx->try_deref
            && state->num_missing_total > group_ctx->deref_treshold) {
        DEBUG(SSSDBG_TRACE_INTERNAL, "Dereferencing members of group [%s]\n",
                                      orig_dn);
        state->deref = true;
        subreq = sdap_nested_group_deref_send(state, ev, group_ctx, members,
                                              orig_dn,
                                              state->nesting_level);
    } else {
        DEBUG(SSSDBG_TRACE_INTERNAL, "Members of group [%s] will be "
                                      "processed individually\n", orig_dn);
        state->deref = false;
        subreq = sdap_nested_group_single_send(state, ev, group_ctx,
                                               state->missing,
                                               state->num_missing_total,
                                               state->num_missing_groups,
                                               state->nesting_level);
    }
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, sdap_nested_group_process_done, req);

    return req;

immediately:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);

    return req;
}

static void sdap_nested_group_process_done(struct tevent_req *subreq)
{
    struct sdap_nested_group_process_state *state = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_nested_group_process_state);

    if (state->deref) {
        ret = sdap_nested_group_deref_recv(subreq);
        talloc_zfree(subreq);
        if (ret == ENOTSUP) {
            /* dereference is not supported, try again without dereference */
            state->group_ctx->try_deref = false;
            state->deref = false;

            DEBUG(SSSDBG_TRACE_INTERNAL, "Members of group [%s] will be "
                  "processed individually\n", state->group_dn);

            subreq = sdap_nested_group_single_send(state,
                                                   state->ev,
                                                   state->group_ctx,
                                                   state->missing,
                                                   state->num_missing_total,
                                                   state->num_missing_groups,
                                                   state->nesting_level);
            if (subreq == NULL) {
                ret = ENOMEM;
                goto done;
            }

            tevent_req_set_callback(subreq, sdap_nested_group_process_done,
                                    req);

            ret = EAGAIN;
        }
    } else {
        ret = sdap_nested_group_single_recv(subreq);
        talloc_zfree(subreq);
    }

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }
}

static errno_t sdap_nested_group_process_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct sdap_nested_group_recurse_state {
    struct tevent_context *ev;
    struct sdap_nested_group_ctx *group_ctx;
    struct sysdb_attrs **groups;
    int num_groups;
    int index;
    int nesting_level;
};

static errno_t sdap_nested_group_recurse_step(struct tevent_req *req);
static void sdap_nested_group_recurse_done(struct tevent_req *subreq);

static struct tevent_req *
sdap_nested_group_recurse_send(TALLOC_CTX *mem_ctx,
                               struct tevent_context *ev,
                               struct sdap_nested_group_ctx *group_ctx,
                               struct sysdb_attrs **nested_groups,
                               int num_groups,
                               int nesting_level)
{
    struct sdap_nested_group_recurse_state *state = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_nested_group_recurse_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->ev = ev;
    state->group_ctx = group_ctx;
    state->groups = nested_groups;
    state->num_groups = num_groups;
    state->index = 0;
    state->nesting_level = nesting_level;

    /* process each group individually */
    ret = sdap_nested_group_recurse_step(req);
    if (ret != EAGAIN) {
        goto immediately;
    }

    return req;

immediately:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);

    return req;
}

static errno_t sdap_nested_group_recurse_step(struct tevent_req *req)
{
    struct sdap_nested_group_recurse_state *state = NULL;
    struct tevent_req *subreq = NULL;

    state = tevent_req_data(req, struct sdap_nested_group_recurse_state);

    if (state->index >= state->num_groups) {
        /* we're done */
        return EOK;
    }

    subreq = sdap_nested_group_process_send(state, state->ev, state->group_ctx,
                                            state->nesting_level,
                                            state->groups[state->index]);
    if (subreq == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, sdap_nested_group_recurse_done, req);

    state->index++;

    return EAGAIN;
}

static void sdap_nested_group_recurse_done(struct tevent_req *subreq)
{
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);

    ret = sdap_nested_group_process_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

    ret = sdap_nested_group_recurse_step(req);

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }

    return;
}

static errno_t sdap_nested_group_recurse_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct sdap_nested_group_single_state {
    struct tevent_context *ev;
    struct sdap_nested_group_ctx *group_ctx;
    struct sdap_nested_group_member *members;
    int nesting_level;

    struct sdap_nested_group_member *current_member;
    int num_members;
    int member_index;

    struct sysdb_attrs **nested_groups;
    int num_groups;
};

static errno_t sdap_nested_group_single_step(struct tevent_req *req);
static void sdap_nested_group_single_step_done(struct tevent_req *subreq);
static void sdap_nested_group_single_done(struct tevent_req *subreq);

static struct tevent_req *
sdap_nested_group_single_send(TALLOC_CTX *mem_ctx,
                              struct tevent_context *ev,
                              struct sdap_nested_group_ctx *group_ctx,
                              struct sdap_nested_group_member *members,
                              int num_members,
                              int num_groups_max,
                              int nesting_level)
{
    struct sdap_nested_group_single_state *state = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_nested_group_single_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->ev = ev;
    state->group_ctx = group_ctx;
    state->members = members;
    state->nesting_level = nesting_level;
    state->current_member = NULL;
    state->num_members = num_members;
    state->member_index = 0;
    state->nested_groups = talloc_zero_array(state, struct sysdb_attrs *,
                                             num_groups_max);
    if (state->nested_groups == NULL) {
        ret = ENOMEM;
        goto immediately;
    }
    state->num_groups = 0; /* we will count exact number of the groups */

    /* process each member individually */
    ret = sdap_nested_group_single_step(req);
    if (ret != EAGAIN) {
        goto immediately;
    }

    return req;

immediately:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);

    return req;
}

static errno_t sdap_nested_group_single_step(struct tevent_req *req)
{
    struct sdap_nested_group_single_state *state = NULL;
    struct tevent_req *subreq = NULL;

    state = tevent_req_data(req, struct sdap_nested_group_single_state);

    if (state->member_index >= state->num_members) {
        /* we're done */
        return EOK;
    }

    state->current_member = &state->members[state->member_index];
    state->member_index++;

    switch (state->current_member->type) {
    case SDAP_NESTED_GROUP_DN_USER:
        subreq = sdap_nested_group_lookup_user_send(state, state->ev,
                                                    state->group_ctx,
                                                    state->current_member);
        break;
    case SDAP_NESTED_GROUP_DN_GROUP:
        subreq = sdap_nested_group_lookup_group_send(state, state->ev,
                                                     state->group_ctx,
                                                     state->current_member);
        break;
    case SDAP_NESTED_GROUP_DN_UNKNOWN:
        subreq = sdap_nested_group_lookup_unknown_send(state, state->ev,
                                                   state->group_ctx,
                                                   state->current_member);
        break;
    }

    if (subreq == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, sdap_nested_group_single_step_done, req);

    return EAGAIN;
}

static errno_t
sdap_nested_group_single_step_process(struct tevent_req *subreq)
{
    struct sdap_nested_group_single_state *state = NULL;
    struct tevent_req *req = NULL;
    struct sysdb_attrs *entry = NULL;
    enum sdap_nested_group_dn_type type = SDAP_NESTED_GROUP_DN_UNKNOWN;
    const char *orig_dn = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_nested_group_single_state);

    /* set correct type if possible */
    if (state->current_member->type == SDAP_NESTED_GROUP_DN_UNKNOWN) {
        ret = sdap_nested_group_lookup_unknown_recv(state, subreq,
                                                    &entry, &type);
        if (ret != EOK) {
            goto done;
        }

        if (entry != NULL) {
            state->current_member->type = type;
        }
    }

    switch (state->current_member->type) {
    case SDAP_NESTED_GROUP_DN_USER:
        if (entry == NULL) {
            /* type was not unknown, receive data */
            ret = sdap_nested_group_lookup_user_recv(state, subreq, &entry);
            if (ret != EOK) {
                goto done;
            }

            if (entry == NULL) {
                /* user not found, continue */
                break;
            }
        }

        /* save user in hash table */
        ret = sdap_nested_group_hash_user(state->group_ctx, entry);
        if (ret == EEXIST) {
            /* the user is already present, skip it */
            talloc_zfree(entry);
            ret = EOK;
            goto done;
        } else if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to save user in hash table "
                                        "[%d]: %s\n", ret, strerror(ret));
            goto done;
        }
        break;
    case SDAP_NESTED_GROUP_DN_GROUP:
        if (entry == NULL) {
            /* type was not unknown, receive data */
            ret = sdap_nested_group_lookup_group_recv(state, subreq, &entry);
            if (ret != EOK) {
                goto done;
            }

            if (entry == NULL) {
                /* group not found, continue */
                break;
            }
        } else {
            /* the type was unknown so we had to pull the group,
             * but we don't want to process it if we have reached
             * the nesting level */
            if (state->nesting_level >= state->group_ctx->max_nesting_level) {
                ret = sysdb_attrs_get_string(entry, SYSDB_ORIG_DN, &orig_dn);
                if (ret != EOK) {
                    DEBUG(SSSDBG_MINOR_FAILURE,
                          "The entry has no originalDN\n");
                    orig_dn = "invalid";
                }

                DEBUG(SSSDBG_TRACE_ALL, "[%s] is outside nesting limit "
                      "(level %d), skipping\n", orig_dn, state->nesting_level);
                break;
            }
        }

        /* save group in hash table */
        ret = sdap_nested_group_hash_group(state->group_ctx, entry);
        if (ret == EEXIST) {
            /* the group is already present, skip it */
            talloc_zfree(entry);
            ret = EOK;
            goto done;
        } else if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to save group in hash table "
                                        "[%d]: %s\n", ret, strerror(ret));
            goto done;
        }

        /* remember the group for later processing */
        state->nested_groups[state->num_groups] = entry;
        state->num_groups++;

        break;
    case SDAP_NESTED_GROUP_DN_UNKNOWN:
        /* not found in users nor nested_groups, continue */
        break;
    }

    ret = EOK;

done:
    return ret;
}

static void sdap_nested_group_single_step_done(struct tevent_req *subreq)
{
    struct sdap_nested_group_single_state *state = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_nested_group_single_state);

    /* process direct members */
    ret = sdap_nested_group_single_step_process(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Error processing direct membership "
                                    "[%d]: %s\n", ret, strerror(ret));
        goto done;
    }

    ret = sdap_nested_group_single_step(req);
    if (ret == EOK) {
        /* we have processed all direct members,
         * now recurse and process nested groups */
        subreq = sdap_nested_group_recurse_send(state, state->ev,
                                                state->group_ctx,
                                                state->nested_groups,
                                                state->num_groups,
                                                state->nesting_level + 1);
        if (subreq == NULL) {
            ret = ENOMEM;
            goto done;
        }

        tevent_req_set_callback(subreq, sdap_nested_group_single_done, req);
    } else if (ret != EAGAIN) {
        /* error */
        goto done;
    }

    /* we're not done yet */
    ret = EAGAIN;

done:
    if (ret == EOK) {
        /* tevent_req_error() cannot cope with EOK */
        DEBUG(SSSDBG_CRIT_FAILURE, "We should not get here with EOK\n");
        tevent_req_error(req, EINVAL);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }

    return;
}

static void sdap_nested_group_single_done(struct tevent_req *subreq)
{
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);

    /* all nested groups are completed */
    ret = sdap_nested_group_recurse_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Error processing nested groups "
                                    "[%d]: %s\n.", ret, strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);

    return;
}

static errno_t sdap_nested_group_single_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

/* This should be a function pointer set from the IPA provider */
static errno_t sdap_nested_group_get_ipa_user(TALLOC_CTX *mem_ctx,
                                              const char *user_dn,
                                              struct sysdb_ctx *sysdb,
                                              struct sysdb_attrs **_user)
{
    errno_t ret;
    struct sysdb_attrs *user = NULL;
    char *name;
    struct ldb_dn *dn = NULL;
    const char *rdn_name;
    const char *users_comp_name;
    const char *acct_comp_name;
    const struct ldb_val *rdn_val;
    const struct ldb_val *users_comp_val;
    const struct ldb_val *acct_comp_val;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    /* return username if dn is in form:
     * uid=username,cn=users,cn=accounts,dc=example,dc=com */

    dn = ldb_dn_new(tmp_ctx, sysdb_ctx_get_ldb(sysdb), user_dn);
    if (dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* rdn, users, accounts and least one domain component */
    if (ldb_dn_get_comp_num(dn) < 4) {
        ret = ENOENT;
        goto done;
    }

    rdn_name = ldb_dn_get_rdn_name(dn);
    if (rdn_name == NULL) {
        ret = EINVAL;
        goto done;
    }

    /* rdn must be 'uid' */
    if (strcasecmp("uid", rdn_name) != 0) {
        ret = ENOENT;
        goto done;
    }

    /* second component must be 'cn=users' */
    users_comp_name = ldb_dn_get_component_name(dn, 1);
    if (strcasecmp("cn", users_comp_name) != 0) {
        ret = ENOENT;
        goto done;
    }

    users_comp_val = ldb_dn_get_component_val(dn, 1);
    if (strncasecmp("users", (const char *) users_comp_val->data,
                    users_comp_val->length) != 0) {
        ret = ENOENT;
        goto done;
    }

    /* third component must be 'cn=accounts' */
    acct_comp_name = ldb_dn_get_component_name(dn, 2);
    if (strcasecmp("cn", acct_comp_name) != 0) {
        ret = ENOENT;
        goto done;
    }

    acct_comp_val = ldb_dn_get_component_val(dn, 2);
    if (strncasecmp("accounts", (const char *) acct_comp_val->data,
                    acct_comp_val->length) != 0) {
        ret = ENOENT;
        goto done;
    }

    /* value of rdn is username */
    user = sysdb_new_attrs(tmp_ctx);
    if (user == NULL) {
        ret = ENOMEM;
        goto done;
    }

    rdn_val = ldb_dn_get_rdn_val(dn);
    name = talloc_strndup(user, (const char *)rdn_val->data, rdn_val->length);
    if (name == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_attrs_add_string(user, SYSDB_NAME, name);
    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_attrs_add_string(user, SYSDB_ORIG_DN, user_dn);
    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_attrs_add_string(user, SYSDB_OBJECTCLASS, SYSDB_USER_CLASS);
    if (ret != EOK) {
        goto done;
    }

    *_user = talloc_steal(mem_ctx, user);

done:
    talloc_free(tmp_ctx);
    return ret;
}

struct sdap_nested_group_lookup_user_state {
    struct sysdb_attrs *user;
};

static void sdap_nested_group_lookup_user_done(struct tevent_req *subreq);

static struct tevent_req *
sdap_nested_group_lookup_user_send(TALLOC_CTX *mem_ctx,
                                   struct tevent_context *ev,
                                   struct sdap_nested_group_ctx *group_ctx,
                                   struct sdap_nested_group_member *member)
{
    struct sdap_nested_group_lookup_user_state *state = NULL;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    const char **attrs = NULL;
    const char *base_filter = NULL;
    const char *filter = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_nested_group_lookup_user_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    if (group_ctx->opts->schema_type == SDAP_SCHEMA_IPA_V1) {
        /* if the schema is IPA, then just shortcut and guess the name */
        ret = sdap_nested_group_get_ipa_user(state, member->dn,
                                             group_ctx->domain->sysdb,
                                             &state->user);
        if (ret == EOK) {
            goto immediately;
        }

        DEBUG(SSSDBG_MINOR_FAILURE, "Couldn't parse out user information "
              "based on DN %s, falling back to an LDAP lookup\n", member->dn);
    }

    /* only pull down username and originalDN */
    attrs = talloc_array(state, const char *, 3);
    if (attrs == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    attrs[0] = "objectClass";
    attrs[1] = group_ctx->opts->user_map[SDAP_AT_USER_NAME].name;
    attrs[2] = NULL;

    /* create filter */
    base_filter = talloc_asprintf(state, "(objectclass=%s)",
                                  group_ctx->opts->user_map[SDAP_OC_USER].name);
    if (base_filter == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    /* use search base filter if needed */
    filter = sdap_get_id_specific_filter(state, base_filter,
                                         member->user_filter);
    if (filter == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    /* search */
    subreq = sdap_get_generic_send(state, ev, group_ctx->opts, group_ctx->sh,
                                   member->dn, LDAP_SCOPE_BASE, filter, attrs,
                                   group_ctx->opts->user_map,
                                   group_ctx->opts->user_map_cnt,
                                   dp_opt_get_int(group_ctx->opts->basic,
                                                  SDAP_SEARCH_TIMEOUT),
                                   false);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, sdap_nested_group_lookup_user_done, req);

    return req;

immediately:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);

    return req;
}

static void sdap_nested_group_lookup_user_done(struct tevent_req *subreq)
{
    struct sdap_nested_group_lookup_user_state *state = NULL;
    struct tevent_req *req = NULL;
    struct sysdb_attrs **user = NULL;
    size_t count = 0;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_nested_group_lookup_user_state);

    ret = sdap_get_generic_recv(subreq, state, &count, &user);
    talloc_zfree(subreq);
    if (ret == ENOENT) {
        count = 0;
    } else if (ret != EOK) {
        goto done;
    }

    if (count == 1) {
        state->user = user[0];
    } else if (count == 0) {
        /* group not found */
        state->user = NULL;
    } else {
        DEBUG(SSSDBG_OP_FAILURE,
              "BASE search returned more than one records\n");
        ret = EIO;
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static errno_t sdap_nested_group_lookup_user_recv(TALLOC_CTX *mem_ctx,
                                                  struct tevent_req *req,
                                                  struct sysdb_attrs **_user)
{
    struct sdap_nested_group_lookup_user_state *state = NULL;
    state = tevent_req_data(req, struct sdap_nested_group_lookup_user_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (_user != NULL) {
        *_user = talloc_steal(mem_ctx, state->user);
    }

    return EOK;
}

struct sdap_nested_group_lookup_group_state {
    struct sysdb_attrs *group;
};

static void sdap_nested_group_lookup_group_done(struct tevent_req *subreq);

static struct tevent_req *
sdap_nested_group_lookup_group_send(TALLOC_CTX *mem_ctx,
                                    struct tevent_context *ev,
                                    struct sdap_nested_group_ctx *group_ctx,
                                    struct sdap_nested_group_member *member)
{
     struct sdap_nested_group_lookup_group_state *state = NULL;
     struct tevent_req *req = NULL;
     struct tevent_req *subreq = NULL;
     struct sdap_attr_map *map = group_ctx->opts->group_map;
     const char **attrs = NULL;
     const char *base_filter = NULL;
     const char *filter = NULL;
     errno_t ret;

     req = tevent_req_create(mem_ctx, &state,
                             struct sdap_nested_group_lookup_group_state);
     if (req == NULL) {
         DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
         return NULL;
     }

     ret = build_attrs_from_map(state, group_ctx->opts->group_map,
                                SDAP_OPTS_GROUP, NULL, &attrs, NULL);
     if (ret != EOK) {
         goto immediately;
     }

     /* create filter */
     base_filter = talloc_asprintf(attrs, "(&(objectclass=%s)(%s=*))",
                                   map[SDAP_OC_GROUP].name,
                                   map[SDAP_AT_GROUP_NAME].name);
     if (base_filter == NULL) {
         ret = ENOMEM;
         goto immediately;
     }

     /* use search base filter if needed */
     filter = sdap_get_id_specific_filter(state, base_filter,
                                          member->group_filter);
     if (filter == NULL) {
         ret = ENOMEM;
         goto immediately;
     }

     /* search */
     subreq = sdap_get_generic_send(state, ev, group_ctx->opts, group_ctx->sh,
                                    member->dn, LDAP_SCOPE_BASE, filter, attrs,
                                    map, SDAP_OPTS_GROUP,
                                    dp_opt_get_int(group_ctx->opts->basic,
                                                   SDAP_SEARCH_TIMEOUT),
                                    false);
     if (subreq == NULL) {
         ret = ENOMEM;
         goto immediately;
     }

     tevent_req_set_callback(subreq, sdap_nested_group_lookup_group_done, req);

     return req;

immediately:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);

    return req;
}

static void sdap_nested_group_lookup_group_done(struct tevent_req *subreq)
{
    struct sdap_nested_group_lookup_group_state *state = NULL;
    struct tevent_req *req = NULL;
    struct sysdb_attrs **group = NULL;
    size_t count = 0;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_nested_group_lookup_group_state);

    ret = sdap_get_generic_recv(subreq, state, &count, &group);
    talloc_zfree(subreq);
    if (ret == ENOENT) {
        count = 0;
    } else if (ret != EOK) {
        goto done;
    }

    if (count == 1) {
        state->group = group[0];
    } else if (count == 0) {
        /* group not found */
        state->group = NULL;
    } else {
        DEBUG(SSSDBG_OP_FAILURE,
              "BASE search returned more than one records\n");
        ret = EIO;
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static errno_t sdap_nested_group_lookup_group_recv(TALLOC_CTX *mem_ctx,
                                                   struct tevent_req *req,
                                                   struct sysdb_attrs **_group)
{
     struct sdap_nested_group_lookup_group_state *state = NULL;
     state = tevent_req_data(req, struct sdap_nested_group_lookup_group_state);

     TEVENT_REQ_RETURN_ON_ERROR(req);

     if (_group != NULL) {
         *_group = talloc_steal(mem_ctx, state->group);
     }

     return EOK;
}

struct sdap_nested_group_lookup_unknown_state {
    struct tevent_context *ev;
    struct sdap_nested_group_ctx *group_ctx;
    struct sdap_nested_group_member *member;
    enum sdap_nested_group_dn_type type;
    struct sysdb_attrs *entry;
};

static void
sdap_nested_group_lookup_unknown_user_done(struct tevent_req *subreq);

static void
sdap_nested_group_lookup_unknown_group_done(struct tevent_req *subreq);

static struct tevent_req *
sdap_nested_group_lookup_unknown_send(TALLOC_CTX *mem_ctx,
                                      struct tevent_context *ev,
                                      struct sdap_nested_group_ctx *group_ctx,
                                      struct sdap_nested_group_member *member)
{
    struct sdap_nested_group_lookup_unknown_state *state = NULL;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_nested_group_lookup_unknown_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->ev = ev;
    state->group_ctx = group_ctx;
    state->member = member;

    /* try users first */
    subreq = sdap_nested_group_lookup_user_send(state,
                                                state->ev,
                                                state->group_ctx,
                                                state->member);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, sdap_nested_group_lookup_unknown_user_done,
                            req);

    return req;

immediately:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);

    return req;
}

static void
sdap_nested_group_lookup_unknown_user_done(struct tevent_req *subreq)
{
    struct sdap_nested_group_lookup_unknown_state *state = NULL;
    struct tevent_req *req = NULL;
    struct sysdb_attrs *entry = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_nested_group_lookup_unknown_state);

    ret = sdap_nested_group_lookup_user_recv(state, subreq, &entry);
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

    if (entry != NULL) {
        /* found in users */
        state->entry = entry;
        state->type = SDAP_NESTED_GROUP_DN_USER;
        ret = EOK;
        goto done;
    }

    /* not found in users, try group */
    subreq = sdap_nested_group_lookup_group_send(state,
                                                 state->ev,
                                                 state->group_ctx,
                                                 state->member);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, sdap_nested_group_lookup_unknown_group_done,
                            req);

    ret = EAGAIN;

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }

    return;
}

static void
sdap_nested_group_lookup_unknown_group_done(struct tevent_req *subreq)
{
    struct sdap_nested_group_lookup_unknown_state *state = NULL;
    struct tevent_req *req = NULL;
    struct sysdb_attrs *entry = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_nested_group_lookup_unknown_state);

    ret = sdap_nested_group_lookup_group_recv(state, subreq, &entry);
    talloc_zfree(subreq);
    if (ret != EOK) {
        goto done;
    }

    if (entry == NULL) {
        /* not found, end request */
        state->entry = NULL;
        state->type = SDAP_NESTED_GROUP_DN_UNKNOWN;
    } else {
        /* found in groups */
        state->entry = entry;
        state->type = SDAP_NESTED_GROUP_DN_GROUP;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static errno_t
sdap_nested_group_lookup_unknown_recv(TALLOC_CTX *mem_ctx,
                                      struct tevent_req *req,
                                      struct sysdb_attrs **_entry,
                                      enum sdap_nested_group_dn_type *_type)
{
    struct sdap_nested_group_lookup_unknown_state *state = NULL;
    state = tevent_req_data(req, struct sdap_nested_group_lookup_unknown_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (_entry != NULL) {
        *_entry = talloc_steal(mem_ctx, state->entry);
    }

    if (_type != NULL) {
        *_type = state->type;
    }


    return EOK;
}

struct sdap_nested_group_deref_state {
    struct tevent_context *ev;
    struct sdap_nested_group_ctx *group_ctx;
    struct ldb_message_element *members;
    int nesting_level;

    struct sysdb_attrs **nested_groups;
    int num_groups;
};

static void sdap_nested_group_deref_direct_done(struct tevent_req *subreq);
static void sdap_nested_group_deref_done(struct tevent_req *subreq);

static struct tevent_req *
sdap_nested_group_deref_send(TALLOC_CTX *mem_ctx,
                             struct tevent_context *ev,
                             struct sdap_nested_group_ctx *group_ctx,
                             struct ldb_message_element *members,
                             const char *group_dn,
                             int nesting_level)
{
    struct sdap_nested_group_deref_state *state = NULL;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct sdap_attr_map_info *maps = NULL;
    static const int num_maps = 2;
    struct sdap_options *opts = group_ctx->opts;
    const char **attrs = NULL;
    size_t num_attrs = 0;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_nested_group_deref_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->ev = ev;
    state->group_ctx = group_ctx;
    state->members = members;
    state->nesting_level = nesting_level;
    state->num_groups = 0; /* we will count exact number of the groups */

    maps = talloc_array(state, struct sdap_attr_map_info, num_maps);
    if (maps == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    maps[0].map = opts->user_map;
    maps[0].num_attrs = opts->user_map_cnt;
    maps[1].map = opts->group_map;
    maps[1].num_attrs = SDAP_OPTS_GROUP;

    /* pull down the whole group map,
     * but only pull down username and originalDN for users */
    ret = build_attrs_from_map(state, opts->group_map, SDAP_OPTS_GROUP,
                               NULL, &attrs, &num_attrs);
    if (ret != EOK) {
        goto immediately;
    }

    attrs = talloc_realloc(state, attrs, const char *, num_attrs + 2);
    if (attrs == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    attrs[num_attrs] = group_ctx->opts->user_map[SDAP_AT_USER_NAME].name;
    attrs[num_attrs + 1] = NULL;

    /* send request */
    subreq = sdap_deref_search_send(state, ev, opts, group_ctx->sh, group_dn,
                                    opts->group_map[SDAP_AT_GROUP_MEMBER].name,
                                    attrs, num_maps, maps,
                                    dp_opt_get_int(opts->basic,
                                                   SDAP_SEARCH_TIMEOUT));
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, sdap_nested_group_deref_direct_done, req);

    return req;

immediately:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);

    return req;
}

static errno_t
sdap_nested_group_deref_direct_process(struct tevent_req *subreq)
{
    struct sdap_nested_group_deref_state *state = NULL;
    struct tevent_req *req = NULL;
    struct sdap_options *opts = NULL;
    struct sdap_deref_attrs **entries = NULL;
    struct ldb_message_element *members = NULL;
    const char *orig_dn = NULL;
    const char *member_dn = NULL;
    size_t num_entries = 0;
    size_t i, j;
    bool member_found;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_nested_group_deref_state);

    opts = state->group_ctx->opts;
    members = state->members;

    ret = sdap_deref_search_recv(subreq, state, &num_entries, &entries);
    if (ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "Received %zu dereference results, "
          "about to process them\n", num_entries);

    /*
     * We don't have any knowledge about possible number of groups when
     * dereferencing. We expect that every member is a group and we will
     * allocate enough space to hold it. We will shrink the memory later.
     */
    state->nested_groups = talloc_zero_array(state, struct sysdb_attrs *,
                                             num_entries);
    if (state->nested_groups == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < num_entries; i++) {
        ret = sysdb_attrs_get_string(entries[i]->attrs,
                                     SYSDB_ORIG_DN, &orig_dn);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "The entry has no originalDN\n");
            goto done;
        }

        /* Ensure that all members returned from the deref request are included
         * in the member processing. Sometimes we will get more results back
         * from deref/asq than we got from the initial lookup, as is the case
         * with Active Directory and its range retrieval mechanism.
         */
        member_found = false;
        for (j = 0; j < members->num_values; j++) {
            /* FIXME: This is inefficient for very large sets of groups */
            member_dn = (const char *)members->values[j].data;
            if (strcasecmp(orig_dn, member_dn) == 0) {
                member_found = true;
                break;
            }
        }

        if (!member_found) {
            /* Append newly found member to member list.
             * Changes in state->members will propagate into sysdb_attrs of
             * the group. */
            state->members->values = talloc_realloc(members, members->values,
                                                    struct ldb_val,
                                                    members->num_values + 1);
            if (members->values == NULL) {
                ret = ENOMEM;
                goto done;
            }

            members->values[members->num_values].data =
                    (uint8_t *)talloc_strdup(members->values, orig_dn);
            if (members->values[members->num_values].data == NULL) {
                ret = ENOMEM;
                goto done;
            }

            members->values[members->num_values].length = strlen(orig_dn);
            members->num_values++;
        }

        if (entries[i]->map == opts->user_map) {
            /* we found a user */

            /* skip the user if it is not amongst configured search bases */
            if (!sdap_nested_member_is_user(state->group_ctx, orig_dn, NULL)) {
                continue;
            }

            /* save user in hash table */
            ret = sdap_nested_group_hash_user(state->group_ctx,
                                              entries[i]->attrs);
            if (ret != EOK && ret != EEXIST) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Unable to save user in hash table "
                       "[%d]: %s\n", ret, strerror(ret));
                goto done;
            }

        } else if (entries[i]->map == opts->group_map) {
            /* we found a group */

            /* skip the group if we have reached the nesting limit */
            if (state->nesting_level >= state->group_ctx->max_nesting_level) {
                DEBUG(SSSDBG_TRACE_ALL, "[%s] is outside nesting limit "
                      "(level %d), skipping\n", orig_dn, state->nesting_level);
                continue;
            }

            /* skip the group if it is not amongst configured search bases */
            if (!sdap_nested_member_is_group(state->group_ctx, orig_dn, NULL)) {
                continue;
            }

            /* save group in hash table */
            ret = sdap_nested_group_hash_group(state->group_ctx,
                                               entries[i]->attrs);
            if (ret == EEXIST) {
                continue;
            } else if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Unable to save group in hash table "
                       "[%d]: %s\n", ret, strerror(ret));
                goto done;
            }

            /* remember the group for later processing */
            state->nested_groups[state->num_groups] = entries[i]->attrs;
            state->num_groups++;

        } else {
            /* this should never happen, but if it does, do not loop forever */
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Entry does not match any known map, skipping\n");
            continue;
        }
    }

    /* adjust size of nested groups array */
    if (state->num_groups > 0) {
        state->nested_groups = talloc_realloc(state, state->nested_groups,
                                              struct sysdb_attrs *,
                                              state->num_groups);
        if (state->nested_groups == NULL) {
            ret = ENOMEM;
            goto done;
        }
    } else {
        talloc_zfree(state->nested_groups);
    }

    ret = EOK;

done:
    return ret;
}

static void sdap_nested_group_deref_direct_done(struct tevent_req *subreq)
{
    struct sdap_nested_group_deref_state *state = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_nested_group_deref_state);

    /* process direct members */
    ret = sdap_nested_group_deref_direct_process(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Error processing direct membership "
                                    "[%d]: %s\n", ret, strerror(ret));
        goto done;
    }

    /* we have processed all direct members,
     * now recurse and process nested groups */
    subreq = sdap_nested_group_recurse_send(state, state->ev,
                                            state->group_ctx,
                                            state->nested_groups,
                                            state->num_groups,
                                            state->nesting_level + 1);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, sdap_nested_group_deref_done, req);

    ret = EAGAIN;

done:
    if (ret == EOK) {
        /* tevent_req_error() cannot cope with EOK */
        DEBUG(SSSDBG_CRIT_FAILURE, "We should not get here with EOK\n");
        tevent_req_error(req, EINVAL);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }

    return;

}

static void sdap_nested_group_deref_done(struct tevent_req *subreq)
{
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);

    /* process nested groups */
    ret = sdap_nested_group_recurse_recv(subreq);
    talloc_zfree(subreq);

    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }

    return;
}

static errno_t sdap_nested_group_deref_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}
