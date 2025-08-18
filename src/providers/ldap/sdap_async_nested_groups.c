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
#include "util/probes.h"
#include "db/sysdb.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ldap/sdap_async_private.h"
#include "providers/ldap/sdap_idmap.h"
#include "providers/ipa/ipa_dn.h"

#define sdap_nested_group_sysdb_search_users(domain, dn) \
    sdap_nested_group_sysdb_search((domain), (dn), true)

#define sdap_nested_group_sysdb_search_groups(domain, dn) \
    sdap_nested_group_sysdb_search((domain), (dn), false)

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

#ifndef EXTERNAL_MEMBERS_CHUNK
#define EXTERNAL_MEMBERS_CHUNK  16
#endif /* EXTERNAL_MEMBERS_CHUNK */

struct sdap_external_missing_member {
    const char **parent_group_dns;
    size_t parent_dn_idx;
};

struct sdap_nested_group_ctx {
    struct sss_domain_info *domain;
    struct sdap_options *opts;
    struct sdap_search_base **user_search_bases;
    struct sdap_search_base **group_search_bases;
    struct sdap_search_base **ignore_user_search_bases;
    struct sdap_handle *sh;
    hash_table_t *users;
    hash_table_t *groups;
    hash_table_t *missing_external;
    bool try_deref;
    int deref_threshold;
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

static errno_t sdap_nested_group_hash_insert(hash_table_t *table,
                                             const char *entry_key,
                                             void *entry_value,
                                             bool overwrite,
                                             const char *table_name)
{
    hash_key_t key;
    hash_value_t value;
    int hret;

    DEBUG(SSSDBG_TRACE_ALL, "Inserting [%s] into hash table [%s]\n",
                             entry_key, table_name);

    key.type = HASH_KEY_STRING;
    key.c_str = discard_const(entry_key); /* hash_enter() will make a copy */

    if (overwrite == false && hash_has_key(table, &key)) {
        return EEXIST;
    }

    value.type = HASH_VALUE_PTR;
    value.ptr = entry_value;

    hret = hash_enter(table, &key, &value);
    if (hret != HASH_SUCCESS) {
        return EIO;
    }

    talloc_steal(table, value.ptr);

    return EOK;
}

static errno_t sdap_nested_group_hash_entry(hash_table_t *table,
                                            struct sysdb_attrs *entry,
                                            const char *table_name)
{
    const char *name = NULL;
    errno_t ret;

    ret = sysdb_attrs_get_string(entry, SYSDB_DN_FOR_MEMBER_HASH_TABLE, &name);
    if (ret != EOK) {
        ret = sysdb_attrs_get_string(entry, SYSDB_ORIG_DN, &name);
        if (ret != EOK) {
            return ret;
        }
    }

    return sdap_nested_group_hash_insert(table, name, entry, false, table_name);
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
    gid_t gid = 0;
    errno_t ret;
    bool posix_group = true;
    bool use_id_mapping;
    bool can_find_gid;
    bool need_filter;

    ret = sdap_check_ad_group_type(group_ctx->domain, group_ctx->opts,
                                   group, "", &need_filter);
    if (ret != EOK) {
        return ret;
    }

    if (need_filter) {
        posix_group = false;
        gid = 0;
    }

    use_id_mapping = sdap_idmap_domain_has_algorithmic_mapping(
                                                          group_ctx->opts->idmap_ctx,
                                                          group_ctx->domain->name,
                                                          group_ctx->domain->domain_id);

    can_find_gid = posix_group && !use_id_mapping;
    if (can_find_gid) {
        ret = sysdb_attrs_get_uint32_t(group, map[SDAP_AT_GROUP_GID].sys_name,
                                       &gid);
    }
    if (!can_find_gid || ret == ENOENT || (ret == EOK && gid == 0)) {
        DEBUG(SSSDBG_TRACE_ALL,
             "The group's gid was %s\n", ret == ENOENT ? "missing" : "zero");
        DEBUG(SSSDBG_TRACE_INTERNAL,
             "Marking group as non-POSIX!\n");

        ret = sysdb_attrs_add_bool(group, SYSDB_POSIX, false);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Error: Failed to mark group as non-POSIX!\n");
            return ret;
        }
    } else if (ret != EOK) {
        return ret;
    }

    return sdap_nested_group_hash_entry(group_ctx->groups, group, "groups");
}

static errno_t sdap_nested_group_external_add(hash_table_t *table,
                                              const char *ext_member,
                                              const char *parent_group_dn)
{
    hash_key_t key;
    hash_value_t value;
    int hret;
    int ret;
    struct sdap_external_missing_member *ext_mem;

    key.type = HASH_KEY_STRING;
    key.str = discard_const(ext_member);

    DEBUG(SSSDBG_TRACE_ALL,
          "Inserting external member [%s] into external members hash table\n",
          ext_member);

    hret = hash_lookup(table, &key, &value);
    switch (hret) {
    case HASH_ERROR_KEY_NOT_FOUND:
        ext_mem = talloc_zero(table, struct sdap_external_missing_member);
        if (ext_mem == NULL) {
            return ENOMEM;
        }
        ext_mem->parent_group_dns = talloc_zero_array(ext_mem,
                                                      const char *,
                                                      EXTERNAL_MEMBERS_CHUNK);
        if (ext_mem->parent_group_dns == NULL) {
            talloc_free(ext_mem);
            return ENOMEM;
        }

        ret = sdap_nested_group_hash_insert(table, ext_member, ext_mem,
                                            true, "missing external users");
        if (ret != EOK) {
            return ret;
        }
        break;

    case HASH_SUCCESS:
        ext_mem = talloc_get_type(value.ptr,
                                  struct sdap_external_missing_member);
        if (ext_mem->parent_dn_idx == \
                talloc_array_length(ext_mem->parent_group_dns)) {
            ext_mem->parent_group_dns = talloc_realloc(ext_mem,
                                                ext_mem->parent_group_dns,
                                                const char *,
                                                ext_mem->parent_dn_idx + \
                                                    EXTERNAL_MEMBERS_CHUNK);
            if (ext_mem->parent_group_dns == NULL) {
                talloc_free(ext_mem);
                return ENOMEM;
            }
        }
        break;
    default:
        return EIO;
    }

    ext_mem->parent_group_dns[ext_mem->parent_dn_idx] = \
                                        talloc_strdup(ext_mem->parent_group_dns,
                                                      parent_group_dn);
    if (ext_mem->parent_group_dns[ext_mem->parent_dn_idx] == NULL) {
        return ENOMEM;
    }
    ext_mem->parent_dn_idx++;

    return EOK;
}

static errno_t sdap_nested_group_sysdb_search(struct sss_domain_info *domain,
                                              const char *dn,
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
        ret = sysdb_search_users_by_orig_dn(NULL, domain, dn, attrs,
                                            &count, &msgs);
    } else {
        ret = sysdb_search_groups_by_orig_dn(NULL, domain, dn, attrs,
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
    struct sdap_domain *sdap_domain = NULL;
    struct sss_domain_info *member_domain = NULL;
    errno_t ret;

    /* determine correct domain of this member */
    sdap_domain = sdap_domain_get_by_dn(opts, member_dn);
    member_domain = sdap_domain == NULL ? domain : sdap_domain->dom;

    /* search in users */
    PROBE(SDAP_NESTED_GROUP_SYSDB_SEARCH_USERS_PRE);
    ret = sdap_nested_group_sysdb_search_users(member_domain, member_dn);
    PROBE(SDAP_NESTED_GROUP_SYSDB_SEARCH_USERS_POST);
    if (ret == EOK || ret == EAGAIN) {
        /* user found */
        *_type = SDAP_NESTED_GROUP_DN_USER;
        goto done;
    } else if (ret != ENOENT) {
        /* error */
        goto done;
    }

    /* search in groups */
    PROBE(SDAP_NESTED_GROUP_SYSDB_SEARCH_GROUPS_PRE);
    ret = sdap_nested_group_sysdb_search_groups(member_domain, member_dn);
    PROBE(SDAP_NESTED_GROUP_SYSDB_SEARCH_GROUPS_POST);
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
                                int threshold,
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

    if (members == NULL) {
        *_missing = NULL;
        *_num_missing = 0;
        *_num_groups = 0;
        return EOK;
    }

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
        PROBE(SDAP_NESTED_GROUP_CHECK_CACHE_PRE);
        ret = sdap_nested_group_check_cache(group_ctx->opts, group_ctx->domain,
                                            dn, &type);
        PROBE(SDAP_NESTED_GROUP_CHECK_CACHE_POST);
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
        if (threshold > 0 && num_missing > threshold) {
            if (_num_missing) {
                *_num_missing = num_missing;
            }

            ret = ERR_DEREF_THRESHOLD;
            goto done;
        }

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

static errno_t
sdap_nested_group_add_ext_members(struct sdap_nested_group_ctx *group_ctx,
                                  struct sysdb_attrs *group,
                                  struct ldb_message_element *ext_members)
{
    errno_t ret;
    const char *ext_member_attr;
    const char *orig_dn;

    if (ext_members == NULL) {
        return EOK;
    }

    ret = sysdb_attrs_get_string(group, SYSDB_ORIG_DN, &orig_dn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "A group with no originalDN!?!\n");
        return ret;
    }

    for (size_t i = 0; i < ext_members->num_values; i++) {
        ext_member_attr = (const char *) ext_members->values[i].data;

        ret = sdap_nested_group_external_add(group_ctx->missing_external,
                                             ext_member_attr,
                                             orig_dn);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                    "Cannot add %s into external members [%d]: %s\n",
                    ext_member_attr, ret, sss_strerror(ret));
            return ret;
        }
    }

    return EOK;
}

static struct ldb_message_element *
sdap_nested_group_ext_members(struct sdap_options *opts,
                              struct sysdb_attrs *group)
{
    errno_t ret;
    struct ldb_message_element *ext_members = NULL;

    if (opts->ext_ctx == NULL) {
        return NULL;
    }

    ret = sysdb_attrs_get_el_ext(group,
                 opts->group_map[SDAP_AT_GROUP_EXT_MEMBER].sys_name,
                 false, &ext_members);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to retrieve external member list "
                                   "[%d]: %s\n", ret, sss_strerror(ret));
    }

    return ext_members;
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

    PROBE(SDAP_NESTED_GROUP_SEND);

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

    ret = sss_hash_create(state->group_ctx, 0, &state->group_ctx->users);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create hash table [%d]: %s\n",
                                    ret, strerror(ret));
        goto immediately;
    }

    ret = sss_hash_create(state->group_ctx, 0, &state->group_ctx->groups);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create hash table [%d]: %s\n",
                                    ret, strerror(ret));
        goto immediately;
    }

    ret = sss_hash_create(state->group_ctx, 0,
                          &state->group_ctx->missing_external);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create hash table [%d]: %s\n",
                                    ret, strerror(ret));
        goto immediately;
    }

    state->group_ctx->try_deref = true;
    state->group_ctx->deref_threshold = dp_opt_get_int(opts->basic,
                                                      SDAP_DEREF_THRESHOLD);
    state->group_ctx->max_nesting_level = dp_opt_get_int(opts->basic,
                                                         SDAP_NESTING_LEVEL);
    state->group_ctx->domain = sdom->dom;
    state->group_ctx->opts = opts;
    state->group_ctx->user_search_bases = sdom->user_search_bases;
    state->group_ctx->group_search_bases = sdom->group_search_bases;
    state->group_ctx->ignore_user_search_bases = sdom->ignore_user_search_bases;
    state->group_ctx->sh = sh;
    state->group_ctx->try_deref = sdap_has_deref_support(sh, opts);

    /* disable deref if threshold <= 0 */
    if (state->group_ctx->deref_threshold <= 0) {
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
                               struct sysdb_attrs ***_groups,
                               hash_table_t **_missing_external)
{
    struct sdap_nested_group_state *state = NULL;
    struct sysdb_attrs **users = NULL;
    struct sysdb_attrs **groups = NULL;
    unsigned long num_users;
    unsigned long num_groups;
    errno_t ret;

    state = tevent_req_data(req, struct sdap_nested_group_state);

    PROBE(SDAP_NESTED_GROUP_RECV);
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

    if (_missing_external) {
        *_missing_external = talloc_steal(mem_ctx,
                                          state->group_ctx->missing_external);
    }

    return EOK;
}

struct sdap_nested_group_process_state {
    struct tevent_context *ev;
    struct sdap_nested_group_ctx *group_ctx;
    struct sdap_nested_group_member *missing;
    int num_missing_total;
    int num_missing_groups;
    struct ldb_message_element *ext_members;
    struct ldb_message_element *members;
    int nesting_level;
    char *group_dn;
    bool deref;
    bool deref_shortcut;
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
    const char *orig_dn = NULL;
    errno_t ret;
    int split_threshold;

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
    PROBE(SDAP_NESTED_GROUP_PROCESS_SEND, state->group_dn);

    /* get member list, both direct and external */
    state->ext_members = sdap_nested_group_ext_members(state->group_ctx->opts,
                                                       group);

    ret = sysdb_attrs_get_el_ext(group, group_map[SDAP_AT_GROUP_MEMBER].sys_name,
                                 false, &state->members);
    if (ret == ENOENT && state->ext_members == NULL) {
        ret = EOK; /* no members, direct or external */
        goto immediately;
    } else if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to retrieve member list "
                                    "[%d]: %s\n", ret, strerror(ret));
        goto immediately;
    }

    split_threshold = state->group_ctx->try_deref ? \
                            state->group_ctx->deref_threshold : \
                            -1;

    /* get members that need to be refreshed */
    PROBE(SDAP_NESTED_GROUP_PROCESS_SPLIT_PRE);
    ret = sdap_nested_group_split_members(state, state->group_ctx,
                                          split_threshold,
                                          state->nesting_level,
                                          state->members,
                                          &state->missing,
                                          &state->num_missing_total,
                                          &state->num_missing_groups);
    PROBE(SDAP_NESTED_GROUP_PROCESS_SPLIT_POST);
    if (ret == ERR_DEREF_THRESHOLD) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "More members were missing than the deref threshold\n");
        state->deref_shortcut = true;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to split member list "
                                    "[%d]: %s\n", ret, sss_strerror(ret));
        goto immediately;
    }

    ret = sdap_nested_group_add_ext_members(state->group_ctx,
                                            group,
                                            state->ext_members);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to split external member list "
                                    "[%d]: %s\n", ret, sss_strerror(ret));
        goto immediately;
    }

    if (state->num_missing_total == 0
            && hash_count(state->group_ctx->missing_external) == 0) {
        ret = EOK; /* we're done */
        goto immediately;
    }

    /* If there are only indirect members of the group, it's still safe to
     * proceed and let the direct lookup code just fall through.
     */

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Looking up %d/%d members of group [%s]\n",
          state->num_missing_total,
          state->members ? state->members->num_values : 0,
          orig_dn);

    /* process members */
    if (group_ctx->try_deref
            && state->num_missing_total > group_ctx->deref_threshold) {
        DEBUG(SSSDBG_TRACE_INTERNAL, "Dereferencing members of group [%s]\n",
                                      orig_dn);
        state->deref = true;
        subreq = sdap_nested_group_deref_send(state, ev, group_ctx,
                                              state->members, orig_dn,
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

            if (state->deref_shortcut == true) {
                /* If we previously short-cut dereference, we need to split the
                 * members again to get full list of missing member types
                 */
                PROBE(SDAP_NESTED_GROUP_PROCESS_SPLIT_PRE);
                ret = sdap_nested_group_split_members(state, state->group_ctx,
                                                      -1,
                                                      state->nesting_level,
                                                      state->members,
                                                      &state->missing,
                                                      &state->num_missing_total,
                                                      &state->num_missing_groups);
                PROBE(SDAP_NESTED_GROUP_PROCESS_SPLIT_POST);
                if (ret != EOK) {
                    DEBUG(SSSDBG_CRIT_FAILURE, "Unable to split member list "
                                                "[%d]: %s\n",
                                                ret, sss_strerror(ret));
                    goto done;
                }
            }

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
#ifdef HAVE_SYSTEMTAP
    struct sdap_nested_group_process_state *state = NULL;
    state = tevent_req_data(req, struct sdap_nested_group_process_state);

    PROBE(SDAP_NESTED_GROUP_PROCESS_RECV, state->group_dn);
#endif

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
    bool ignore_unreadable_references;
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
    state->ignore_unreadable_references = dp_opt_get_bool(
            group_ctx->opts->basic, SDAP_IGNORE_UNREADABLE_REFERENCES);

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

static errno_t must_ignore(struct sdap_search_base **ignore_user_search_bases,
                           struct ldb_context *ldb_ctx,
                           const char *dn_str,
                           bool *_ignore)
{
    bool ignore;
    struct ldb_dn *ldn;
    struct sdap_search_base **base;

    if (ldb_ctx == NULL || dn_str == NULL) {
        return EINVAL;
    }

    if (ignore_user_search_bases == NULL) {
        *_ignore = false;
        return EOK;
    }

    ldn = ldb_dn_new(NULL, ldb_ctx, dn_str);
    if (ldn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to allocate memory for the DN\n");
        return ENOMEM;
    }

    ignore = false;
    for (base = ignore_user_search_bases; *base != NULL; base++) {
        if ((*base)->ldb_basedn != NULL) {
            if (ldb_dn_compare_base((*base)->ldb_basedn, ldn) == 0) {
                ignore = true;
                DEBUG(SSSDBG_TRACE_INTERNAL, "Ignoring entry [%s]\n", dn_str);
                break;
            }
        } else {
            DEBUG(SSSDBG_TRACE_INTERNAL,
                  "Not checking ignore user search base %s \n",
                  (*base)->basedn);
        }
    }
    *_ignore = ignore;

    talloc_free(ldn);
    return EOK;
}

static errno_t sdap_nested_group_single_step(struct tevent_req *req)
{
    struct sdap_nested_group_single_state *state = NULL;
    struct tevent_req *subreq = NULL;
    errno_t ret;
    bool ignore;

    state = tevent_req_data(req, struct sdap_nested_group_single_state);

    do {
        if (state->member_index >= state->num_members) {
            /* we're done */
            return EOK;
        }

        state->current_member = &state->members[state->member_index];
        state->member_index++;

        ret = must_ignore(state->group_ctx->ignore_user_search_bases,
                          sysdb_ctx_get_ldb(state->group_ctx->domain->sysdb),
                          state->current_member->dn, &ignore);
        if (ret != EOK) {
            return ret;
        }
    } while (ignore);

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

        /* The original DN of the user object itself might differ from the one
         * used in the member attribute, e.g. different case. To make sure if
         * can be found in a hash table when iterating over group members the
         * DN from the member attribute used for the search as saved as well.
         */
        ret = sysdb_attrs_add_string(entry,
                                     SYSDB_DN_FOR_MEMBER_HASH_TABLE,
                                     state->current_member->dn);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_add_string failed.\n");
            goto done;
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
        if (state->ignore_unreadable_references) {
            DEBUG(SSSDBG_TRACE_FUNC, "Ignoring unreadable reference [%s]\n",
                  state->current_member->dn);
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "Unknown entry type [%s]!\n",
                  state->current_member->dn);
            DEBUG(SSSDBG_OP_FAILURE, "Consider enabling sssd-ldap option "
                                     "ldap_ignore_unreadable_references\n");
            ret = EINVAL;
            goto done;
        }
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
                                    "[%d]: %s.\n", ret, strerror(ret));
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

static errno_t sdap_nested_group_get_ipa_user(TALLOC_CTX *mem_ctx,
                                              const char *user_dn,
                                              struct sysdb_ctx *sysdb,
                                              struct sysdb_attrs **_user)
{
    TALLOC_CTX *tmp_ctx;
    struct sysdb_attrs *user;
    char *name;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = ipa_get_rdn(tmp_ctx, sysdb, user_dn, &name, "uid",
                      "cn", "users", "cn", "accounts");
    if (ret != EOK) {
        goto done;
    }

    user = sysdb_new_attrs(tmp_ctx);
    if (user == NULL) {
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

    ret = sysdb_attrs_add_string(user, SYSDB_OBJECTCATEGORY, SYSDB_USER_CLASS);
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

    PROBE(SDAP_NESTED_GROUP_LOOKUP_USER_SEND);

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
    filter = sdap_combine_filters(state, base_filter, member->user_filter);
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

    PROBE(SDAP_NESTED_GROUP_LOOKUP_USER_RECV);

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
     char *oc_list;
     errno_t ret;

     PROBE(SDAP_NESTED_GROUP_LOOKUP_GROUP_SEND);

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
     oc_list = sdap_make_oc_list(state, map);
     if (oc_list == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to create objectClass list.\n");
        ret = ENOMEM;
        goto immediately;
     }

     base_filter = talloc_asprintf(attrs, "(&(%s)(%s=*))", oc_list,
                                   map[SDAP_AT_GROUP_NAME].name);
     if (base_filter == NULL) {
         ret = ENOMEM;
         goto immediately;
     }

     /* use search base filter if needed */
     filter = sdap_combine_filters(state, base_filter, member->group_filter);
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

     PROBE(SDAP_NESTED_GROUP_LOOKUP_GROUP_RECV);

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

    PROBE(SDAP_NESTED_GROUP_LOOKUP_UNKNOWN_SEND);

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
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    } else {
        tevent_req_set_callback(subreq,
                                sdap_nested_group_lookup_unknown_user_done,
                                req);
    }

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

    PROBE(SDAP_NESTED_GROUP_LOOKUP_UNKNOWN_RECV);

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

    PROBE(SDAP_NESTED_GROUP_DEREF_SEND);

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

static hash_table_t *
convert_ldb_element_to_set(const struct ldb_message_element *members)
{
    errno_t ret;
    hash_table_t *set = NULL;
    hash_key_t key;
    hash_value_t value;
    size_t j;

    ret = sss_hash_create(NULL, members->num_values, &set);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create hash table [%d]: %s\n",
                                    ret, strerror(ret));
        return NULL;
    }

    key.type = HASH_KEY_CONST_STRING;
    value.type = HASH_VALUE_UNDEF;

    for (j = 0; j < members->num_values; ++j) {
        key.c_str = (const char*)members->values[j].data;
        /* since hash table is used as a set, we don't care about value */
        ret = hash_enter(set, &key, &value);
        if (ret != HASH_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to add '%s'\n", key.c_str);
            hash_destroy(set);
            return NULL;
        }
    }

    return set;
}

static bool set_has_key(hash_table_t *set, const char *key)
{
    hash_key_t hkey;

    hkey.type = HASH_KEY_CONST_STRING;
    hkey.c_str = key;

    return hash_has_key(set, &hkey);
}

static errno_t
sdap_nested_group_deref_direct_process(struct tevent_req *subreq)
{
    struct sdap_nested_group_deref_state *state = NULL;
    struct tevent_req *req = NULL;
    struct sdap_options *opts = NULL;
    struct sdap_deref_attrs **entries = NULL;
    struct ldb_message_element *members = NULL;
    hash_table_t *members_set = NULL; /* will be used as a `set` */
    const char *orig_dn = NULL;
    size_t num_entries = 0;
    size_t i;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_nested_group_deref_state);

    opts = state->group_ctx->opts;
    members = state->members;
    members_set = convert_ldb_element_to_set(state->members);
    if (members_set == NULL) {
        ret = ENOMEM;
        goto done;
    }

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

    PROBE(SDAP_NESTED_GROUP_DEREF_PROCESS_PRE);
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
        if (!set_has_key(members_set, orig_dn)) {
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
    PROBE(SDAP_NESTED_GROUP_DEREF_PROCESS_POST);

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
    if (members_set != NULL) {
        hash_destroy(members_set);
    }
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
    PROBE(SDAP_NESTED_GROUP_DEREF_RECV);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct sdap_ext_member {
    struct sdap_external_missing_member *missing_mem;
    const char *ext_member_attr;

    enum sysdb_member_type member_type;
    struct sss_domain_info *dom;
    struct sysdb_attrs *attrs;
};

struct sdap_nested_group_lookup_external_state {
    struct tevent_context *ev;
    struct sdap_ext_member_ctx *ext_ctx;
    struct sss_domain_info *group_dom;
    hash_table_t *missing_external;

    hash_entry_t *entries;
    unsigned long n_entries;
    unsigned long eniter;

    struct sdap_ext_member *ext_members;

    ext_member_send_fn_t ext_member_resolve_send;
    ext_member_recv_fn_t ext_member_resolve_recv;
};

static errno_t
sdap_nested_group_lookup_external_step(struct tevent_req *req);
static void
sdap_nested_group_lookup_external_done(struct tevent_req *subreq);
static errno_t
sdap_nested_group_lookup_external_link(struct tevent_req *req);
static errno_t
sdap_nested_group_lookup_external_link_member(
                        struct sdap_nested_group_lookup_external_state *state,
                        struct sdap_ext_member *member);
static errno_t
sdap_nested_group_memberof_dn_by_original_dn(
                            TALLOC_CTX *mem_ctx,
                            struct sss_domain_info *group_dom,
                            const char *original_dn,
                            const char ***_parents);

struct tevent_req *
sdap_nested_group_lookup_external_send(TALLOC_CTX *mem_ctx,
                                       struct tevent_context *ev,
                                       struct sss_domain_info *group_dom,
                                       struct sdap_ext_member_ctx *ext_ctx,
                                       hash_table_t *missing_external)
{
    struct sdap_nested_group_lookup_external_state *state = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_nested_group_lookup_external_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->ev = ev;
    state->group_dom = group_dom;
    state->ext_ctx = ext_ctx;
    state->missing_external = missing_external;

    if (state->ext_ctx->ext_member_resolve_send == NULL
            || state->ext_ctx->ext_member_resolve_recv == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Wrong private context\n");
        ret = EINVAL;
        goto immediately;
    }

    ret = hash_entries(state->missing_external,
                       &state->n_entries, &state->entries);
    if (ret != HASH_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "hash_entries returned %d\n", ret);
        ret = EIO;
        goto immediately;
    }
    state->eniter = 0;

    state->ext_members = talloc_zero_array(state,
                                           struct sdap_ext_member,
                                           state->n_entries);
    if (state->ext_members == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    ret = sdap_nested_group_lookup_external_step(req);
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

static errno_t
sdap_nested_group_lookup_external_step(struct tevent_req *req)
{
    struct tevent_req *subreq = NULL;
    struct sdap_nested_group_lookup_external_state *state = NULL;
    state = tevent_req_data(req,
                            struct sdap_nested_group_lookup_external_state);

    subreq = state->ext_ctx->ext_member_resolve_send(state,
                                        state->ev,
                                        state->entries[state->eniter].key.str,
                                        state->ext_ctx->pvt);
    if (subreq == NULL) {
        return ENOMEM;
    }
    DEBUG(SSSDBG_TRACE_FUNC, "Refreshing member %lu/%lu\n",
                             state->eniter, state->n_entries);
    tevent_req_set_callback(subreq,
                            sdap_nested_group_lookup_external_done,
                            req);

    return EAGAIN;
}

static void
sdap_nested_group_lookup_external_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = NULL;
    struct sdap_nested_group_lookup_external_state *state = NULL;
    enum sysdb_member_type member_type;
    struct sysdb_attrs *member;
    struct sss_domain_info *member_dom;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req,
                            struct sdap_nested_group_lookup_external_state);

    ret = state->ext_ctx->ext_member_resolve_recv(state, subreq,
                                                  &member_type,
                                                  &member_dom,
                                                  &member);
    talloc_free(subreq);
    if (ret == EOK) {
        DEBUG(SSSDBG_TRACE_FUNC, "Refreshed member %lu\n", state->eniter);
        state->ext_members[state->eniter].missing_mem = \
                                    state->entries[state->eniter].value.ptr;
        state->ext_members[state->eniter].dom = member_dom;

        state->ext_members[state->eniter].ext_member_attr = \
                        talloc_steal(state->ext_members,
                                     state->entries[state->eniter].key.str);
        state->ext_members[state->eniter].member_type = member_type;
        state->ext_members[state->eniter].attrs = \
                            talloc_steal(state->ext_members, member);
    }

    state->eniter++;
    if (state->eniter >= state->n_entries) {
        DEBUG(SSSDBG_TRACE_FUNC, "All external members processed\n");
        ret = sdap_nested_group_lookup_external_link(req);
        if (ret != EOK) {
            tevent_req_error(req, ret);
            return;
        }
        tevent_req_done(req);
        return;
    }

    ret = sdap_nested_group_lookup_external_step(req);
    if (ret != EOK && ret != EAGAIN) {
        tevent_req_error(req, ret);
        return;
    }

    return;
}

static errno_t
sdap_nested_group_lookup_external_link(struct tevent_req *req)
{
    errno_t ret, tret;
    bool in_transaction = false;
    struct sdap_nested_group_lookup_external_state *state = NULL;
    state = tevent_req_data(req,
                            struct sdap_nested_group_lookup_external_state);

    ret = sysdb_transaction_start(state->group_dom->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
        goto fail;
    }
    in_transaction = true;


    for (size_t i = 0; i < state->eniter; i++) {
        if (state->ext_members[i].attrs == NULL) {
            DEBUG(SSSDBG_MINOR_FAILURE, "The member %s could not be resolved\n",
                                        state->ext_members[i].ext_member_attr);
            continue;
        }

        ret = sdap_nested_group_lookup_external_link_member(state,
                                                    &state->ext_members[i]);
        if (ret != EOK) {
            goto fail;
        }
    }

    ret = sysdb_transaction_commit(state->group_dom->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to commit transaction\n");
        goto fail;
    }
    in_transaction = false;

    return EOK;

fail:
    if (in_transaction) {
        tret = sysdb_transaction_cancel(state->group_dom->sysdb);
        if (tret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to cancel transaction\n");
        }
    }
    return EFAULT;
}

static errno_t
sdap_nested_group_lookup_external_link_member(
                        struct sdap_nested_group_lookup_external_state *state,
                        struct sdap_ext_member *member)
{
    const char *name;
    int ret;
    const char **parents = NULL;
    size_t i;
    TALLOC_CTX *tmp_ctx;
    const char *orig_dn;

    tmp_ctx = talloc_new(state);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sysdb_attrs_get_string(member->attrs, SYSDB_NAME, &name);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No name for a user\n");
        goto done;
    }

    /* This only works because the groups were saved in a previous
     * transaction */
    for (i=0; i < member->missing_mem->parent_dn_idx; i++) {
        orig_dn = member->missing_mem->parent_group_dns[i];
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Linking external members %s from domain %s to parents of %s\n",
              name, member->dom->name, orig_dn);
        ret = sdap_nested_group_memberof_dn_by_original_dn(tmp_ctx,
                                                           state->group_dom,
                                                           orig_dn,
                                                           &parents);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Cannot find parents of %s\n", orig_dn);
            continue;
        }

        /* We don't have to remove the members here, since all members attributes
         * are always written anew
         */
        ret = sysdb_update_members_dn(member->dom, name, member->member_type,
                                      parents, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Cannot link %s@%s to its parents\n",
                                       name, member->dom->name);
            goto done;
        }

    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
sdap_nested_group_memberof_dn_by_original_dn(
                            TALLOC_CTX *mem_ctx,
                            struct sss_domain_info *group_dom,
                            const char *original_dn,
                            const char ***_parents)
{
    errno_t ret;
    const char *attrs[] = { SYSDB_NAME,
                            SYSDB_MEMBEROF,
                            NULL };
    struct ldb_message **msgs = NULL;
    size_t count;
    TALLOC_CTX *tmp_ctx;
    struct ldb_message_element *memberof;
    const char **parents;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sysdb_search_groups_by_orig_dn(tmp_ctx, group_dom, original_dn,
                                         attrs, &count, &msgs);
    if (ret != EOK) {
        goto done;
    }

    if (count != 1) {
        DEBUG(SSSDBG_OP_FAILURE,
              "More than one entry found by originalDN?\n");
        goto done;
    }

    memberof = ldb_msg_find_element(msgs[0], SYSDB_MEMBEROF);
    if (memberof == NULL || memberof->num_values == 0) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "The external group is not a member of any groups\n");
        ret = ENOENT;
        goto done;
    }

    parents = talloc_zero_array(tmp_ctx,
                                const char *,
                                memberof->num_values + 1);
    if (parents == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (size_t i = 0; i < memberof->num_values; i++) {
        parents[i] = talloc_strdup(parents,
                                   (const char *) memberof->values[i].data);
        if (parents[i] == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    *_parents = talloc_steal(mem_ctx, parents);
    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sdap_nested_group_lookup_external_recv(TALLOC_CTX *mem_ctx,
                                       struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}
