/*
    SSSD

    Async LDAP Helper routines - retrieving groups

    Copyright (C) Simo Sorce <ssorce@redhat.com> - 2009
    Copyright (C) 2010, Ralf Haferkamp <rhafer@suse.de>, Novell Inc.
    Copyright (C) Jan Zeleny <jzeleny@redhat.com> - 2011

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

#include "util/util.h"
#include "db/sysdb.h"
#include "providers/ldap/sdap_async_private.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_idmap.h"

/* ==Group-Parsing Routines=============================================== */

static int sdap_find_entry_by_origDN(TALLOC_CTX *memctx,
                                     struct sysdb_ctx *ctx,
                                     struct sss_domain_info *domain,
                                     const char *orig_dn,
                                     char **localdn)
{
    TALLOC_CTX *tmpctx;
    const char *no_attrs[] = { NULL };
    struct ldb_dn *base_dn;
    char *filter;
    struct ldb_message **msgs;
    size_t num_msgs;
    int ret;
    char *sanitized_dn;

    tmpctx = talloc_new(NULL);
    if (!tmpctx) {
        return ENOMEM;
    }

    ret = sss_filter_sanitize(tmpctx, orig_dn, &sanitized_dn);
    if (ret != EOK) {
        ret = ENOMEM;
        goto done;
    }

    filter = talloc_asprintf(tmpctx, "%s=%s", SYSDB_ORIG_DN, sanitized_dn);
    if (!filter) {
        ret = ENOMEM;
        goto done;
    }

    base_dn = sysdb_domain_dn(ctx, tmpctx);
    if (!base_dn) {
        ret = ENOMEM;
        goto done;
    }

    DEBUG(9, ("Searching cache for [%s].\n", sanitized_dn));
    ret = sysdb_search_entry(tmpctx, ctx,
                             base_dn, LDB_SCOPE_SUBTREE, filter, no_attrs,
                             &num_msgs, &msgs);
    if (ret) {
        goto done;
    }
    if (num_msgs != 1) {
        ret = ENOENT;
        goto done;
    }

    *localdn = talloc_strdup(memctx, ldb_dn_get_linearized(msgs[0]->dn));
    if (!*localdn) {
        ret = ENOENT;
        goto done;
    }

    ret = EOK;

done:
    talloc_zfree(tmpctx);
    return ret;
}

static errno_t
sdap_get_members_with_primary_gid(TALLOC_CTX *mem_ctx, struct sysdb_ctx *sysdb,
                                  gid_t gid, char ***_localdn, size_t *_ndn)
{
    static const char *search_attrs[] = { SYSDB_NAME, NULL };
    char *filter;
    struct ldb_message **msgs;
    size_t count;
    size_t i;
    errno_t ret;
    char **localdn;

    /* Don't search if the group is non-posix */
    if (!gid) return EOK;

    filter = talloc_asprintf(mem_ctx, "(%s=%llu)", SYSDB_GIDNUM,
                             (unsigned long long) gid);
    if (!filter) {
        return ENOMEM;
    }

    ret = sysdb_search_users(mem_ctx, sysdb, filter,
                             search_attrs, &count, &msgs);
    talloc_free(filter);
    if (ret == ENOENT) {
        *_localdn = NULL;
        *_ndn = 0;
        return EOK;
    } else if (ret != EOK) {
        return ret;
    }

    localdn = talloc_array(mem_ctx, char *, count);
    if (!localdn) {
        talloc_free(msgs);
        return ENOMEM;
    }

    for (i=0; i < count; i++) {
        localdn[i] = talloc_strdup(localdn,
                                   ldb_dn_get_linearized(msgs[i]->dn));
        if (!localdn[i]) {
            talloc_free(localdn);
            talloc_free(msgs);
            return ENOMEM;
        }
    }

    talloc_free(msgs);
    *_localdn = localdn;
    *_ndn = count;
    return EOK;
}

static errno_t
sdap_dn_by_primary_gid(TALLOC_CTX *mem_ctx, struct sysdb_attrs *ldap_attrs,
                       struct sysdb_ctx *sysdb, struct sdap_options *opts,
                       char ***_dn_list, size_t *_count)
{
    gid_t gid;
    errno_t ret;

    ret = sysdb_attrs_get_uint32_t(ldap_attrs,
                                   opts->group_map[SDAP_AT_GROUP_GID].sys_name,
                                   &gid);
    if (ret == ENOENT) {
        /* Non-posix AD group. Skip. */
        *_dn_list = NULL;
        *_count = 0;
        return EOK;
    } else if (ret && ret != ENOENT) {
        return ret;
    }

    ret = sdap_get_members_with_primary_gid(mem_ctx, sysdb, gid,
                                            _dn_list, _count);
    if (ret) return ret;

    return EOK;
}

static int sdap_fill_memberships(struct sysdb_attrs *group_attrs,
                                 struct sysdb_ctx *ctx,
                                 struct sss_domain_info *domain,
                                 hash_table_t *ghosts,
                                 struct ldb_val *values,
                                 int num_values,
                                 char **userdns,
                                 size_t nuserdns)
{
    struct ldb_message_element *el;
    int i, j;
    int ret;
    errno_t hret;
    hash_key_t key;
    hash_value_t value;

    ret = sysdb_attrs_get_el(group_attrs, SYSDB_MEMBER, &el);
    if (ret) {
        goto done;
    }

    /* Just allocate both big enough to contain all members for now */
    el->values = talloc_realloc(group_attrs, el->values, struct ldb_val,
                                el->num_values + num_values + nuserdns);
    if (!el->values) {
        ret = ENOMEM;
        goto done;
    }

    j = el->num_values;
    for (i = 0; i < num_values; i++) {
        if (ghosts == NULL) {
            hret = HASH_ERROR_KEY_NOT_FOUND;
        } else {
            key.type = HASH_KEY_STRING;
            key.str = (char *)values[i].data;
            hret = hash_lookup(ghosts, &key, &value);
        }

        if (hret == HASH_ERROR_KEY_NOT_FOUND) {
            /* sync search entry with this as origDN */
            ret = sdap_find_entry_by_origDN(el->values, ctx, domain,
                                            (char *)values[i].data,
                                            (char **)&el->values[j].data);
            if (ret == ENOENT) {
                /* member may be outside of the configured search bases
                 * or out of scope of nesting limit */
                DEBUG(SSSDBG_MINOR_FAILURE, ("Member [%s] was not found in "
                      "cache. Is it out of scope?\n", (char *)values[i].data));
                continue;
            }
            if (ret != EOK) {
                goto done;
            }

            DEBUG(7, ("    member #%d (%s): [%s]\n",
                      i, (char *)values[i].data,
                      (char *)el->values[j].data));

            el->values[j].length = strlen((char *)el->values[j].data);
            j++;
        } else if (hret != HASH_SUCCESS) {
            ret = EFAULT;
            goto done;
        }

        /* If the member is in ghost table, it has
         * already been processed - just skip it */
    }
    el->num_values = j;

    for (i=0; i < nuserdns; i++) {
        el->values[el->num_values + i].data = (uint8_t *) \
                                          talloc_steal(group_attrs, userdns[i]);
        el->values[el->num_values + i].length = strlen(userdns[i]);
    }
    el->num_values += nuserdns;

    ret = EOK;

done:
    return ret;
}

/* ==Save-Group-Entry===================================================== */

    /* FIXME: support non legacy */
    /* FIXME: support storing additional attributes */

static errno_t
sdap_store_group_with_gid(struct sysdb_ctx *ctx,
                          const char *name,
                          gid_t gid,
                          struct sysdb_attrs *group_attrs,
                          uint64_t cache_timeout,
                          bool posix_group,
                          time_t now)
{
    errno_t ret;

    /* make sure that non-posix (empty or explicit gid=0) groups have the
     * gidNumber set to zero even if updating existing group */
    if (!posix_group) {
        ret = sysdb_attrs_add_uint32(group_attrs, SYSDB_GIDNUM, 0);
        if (ret) {
            DEBUG(2, ("Could not set explicit GID 0 for %s\n", name));
            return ret;
        }
    }

    ret = sysdb_store_group(ctx, name, gid, group_attrs, cache_timeout, now);
    if (ret) {
        DEBUG(2, ("Could not store group %s\n", name));
        return ret;
    }

    return ret;
}

static errno_t
sdap_process_ghost_members(struct sysdb_attrs *attrs,
                           struct sdap_options *opts,
                           hash_table_t *ghosts,
                           bool populate_members,
                           bool store_original_member,
                           struct sysdb_attrs *sysdb_attrs)
{
    errno_t ret;
    struct ldb_message_element *gh;
    struct ldb_message_element *memberel;
    struct ldb_message_element *sysdb_memberel;
    struct ldb_message_element *ghostel;
    size_t cnt;
    int i;
    int hret;
    hash_key_t key;
    hash_value_t value;

    ret = sysdb_attrs_get_el(attrs, SYSDB_GHOST, &gh);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Error reading ghost attributes: [%s]\n",
               strerror(ret)));
        return ret;
    }

    ret = sysdb_attrs_get_el_ext(attrs,
                             opts->group_map[SDAP_AT_GROUP_MEMBER].sys_name,
                             false, &memberel);
    if (ret == ENOENT) {
        /* Create a dummy element with no values in order for the loop to just
         * fall through and make sure the attrs array is not reallocated.
         */
        memberel = talloc(attrs, struct ldb_message_element);
        if (memberel == NULL) {
            return ENOMEM;
        }
        memberel->num_values = 0;
        memberel->values = NULL;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
                ("Error reading members: [%s]\n", strerror(ret)));
        return ret;
    }

    if (store_original_member) {
        DEBUG(SSSDBG_TRACE_FUNC, ("The group has %d members\n", memberel->num_values));
        for (i = 0; i < memberel->num_values; i++) {
            ret = sysdb_attrs_add_string(sysdb_attrs, SYSDB_ORIG_MEMBER,
                                        (const char *) memberel->values[i].data);
            if (ret) {
                DEBUG(SSSDBG_OP_FAILURE, ("Could not add member [%s]\n",
                      (const char *) memberel->values[i].data));
                return ret;
            }
        }
    }

    if (populate_members) {
        ret = sysdb_attrs_get_el(sysdb_attrs, SYSDB_MEMBER, &sysdb_memberel);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("Error reading group members from group_attrs: [%s]\n",
                   strerror(ret)));
            return ret;
        }
        sysdb_memberel->values = memberel->values;
        sysdb_memberel->num_values = memberel->num_values;
    }

    ret = sysdb_attrs_get_el(sysdb_attrs, SYSDB_GHOST, &ghostel);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Error getting ghost element: [%s]\n", strerror(ret)));
        return ret;
    }
    ghostel->values = gh->values;
    ghostel->num_values = gh->num_values;

    cnt = ghostel->num_values + memberel->num_values;
    DEBUG(SSSDBG_TRACE_FUNC, ("Group has %d members\n", cnt));

    /* Now process RFC2307bis ghost hash table */
    if (ghosts && cnt > 0) {
        ghostel->values = talloc_realloc(sysdb_attrs, ghostel->values,
                                         struct ldb_val, cnt);
        if (ghostel->values == NULL) {
            return ENOMEM;
        }

        for (i = 0; i < memberel->num_values; i++) {
            key.type = HASH_KEY_STRING;
            key.str = (char *) memberel->values[i].data;
            hret = hash_lookup(ghosts, &key, &value);
            if (hret == HASH_ERROR_KEY_NOT_FOUND) {
                continue;
            } else if (hret != HASH_SUCCESS) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      ("Error checking hash table: [%s]\n",
                       hash_error_string(hret)));
                return EFAULT;
            }

            DEBUG(SSSDBG_TRACE_FUNC,
                  ("Adding ghost member for group [%s]\n", (char *) value.ptr));
            ghostel->values[ghostel->num_values].data = \
                        (uint8_t *) talloc_strdup(ghostel->values, value.ptr);
            if (ghostel->values[ghostel->num_values].data == NULL) {
                return ENOMEM;
            }
            ghostel->values[ghostel->num_values].length = strlen(value.ptr);
            ghostel->num_values++;
        }
    }

    return EOK;
}

static int sdap_save_group(TALLOC_CTX *memctx,
                           struct sysdb_ctx *ctx,
                           struct sdap_options *opts,
                           struct sss_domain_info *dom,
                           struct sysdb_attrs *attrs,
                           bool populate_members,
                           bool store_original_member,
                           hash_table_t *ghosts,
                           char **_usn_value,
                           time_t now)
{
    struct ldb_message_element *el;
    struct sysdb_attrs *group_attrs;
    const char *name = NULL;
    gid_t gid;
    errno_t ret;
    char *usn_value = NULL;
    TALLOC_CTX *tmpctx = NULL;
    bool posix_group;
    bool use_id_mapping = dp_opt_get_bool(opts->basic, SDAP_ID_MAPPING);
    char *sid_str;

    tmpctx = talloc_new(NULL);
    if (!tmpctx) {
        ret = ENOMEM;
        goto done;
    }

    group_attrs = sysdb_new_attrs(tmpctx);
    if (group_attrs == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_attrs_primary_name(ctx, attrs,
                                   opts->group_map[SDAP_AT_GROUP_NAME].name,
                                   &name);
    if (ret != EOK) {
        DEBUG(1, ("Failed to save the group - entry has no name attribute\n"));
        goto done;
    }
    DEBUG(SSSDBG_TRACE_FUNC, ("Processing group %s\n", name));

    if (use_id_mapping) {
        posix_group = true;

        DEBUG(SSSDBG_TRACE_LIBS,
              ("Mapping group [%s] objectSID to unix ID\n", name));

        ret = sdap_attrs_get_sid_str(
                tmpctx, opts->idmap_ctx, attrs,
                opts->group_map[SDAP_AT_GROUP_OBJECTSID].sys_name,
                &sid_str);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("Could not identify objectSID: [%s]\n",
                   strerror(ret)));
            goto done;
        }

        /* Add string representation to the cache for easier
         * debugging
         */
        ret = sysdb_attrs_add_string(group_attrs, SYSDB_SID_STR, sid_str);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("Could not add SID string: [%s]\n",
                   strerror(ret)));
            goto done;
        }

        /* Convert the SID into a UNIX group ID */
        ret = sdap_idmap_sid_to_unix(opts->idmap_ctx, sid_str, &gid);
        if (ret == ENOTSUP) {
            /* ENOTSUP is returned if built-in SID was provided
             * => do not store the group, but return EOK */
            DEBUG(SSSDBG_TRACE_FUNC, ("Skipping built-in object.\n"));
            ret = EOK;
            goto done;
        } else if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("Could not convert SID string: [%s]\n",
                   strerror(ret)));
            goto done;
        }

        /* Store the GID in the ldap_attrs so it doesn't get
         * treated as a missing attribute from LDAP and removed.
         */
        ret = sdap_replace_id(attrs, SYSDB_GIDNUM, gid);
        if (ret) {
            DEBUG(SSSDBG_OP_FAILURE, ("Cannot set the id-mapped GID\n"));
            goto done;
        }
    } else {
        ret = sysdb_attrs_get_bool(attrs, SYSDB_POSIX, &posix_group);
        if (ret == ENOENT) {
            posix_group = true;
        } else if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("Error reading posix attribute: [%s]\n",
                   strerror(ret)));
            goto done;
        }

        DEBUG(8, ("This is%s a posix group\n", (posix_group)?"":" not"));
        ret = sysdb_attrs_add_bool(group_attrs, SYSDB_POSIX, posix_group);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("Error setting posix attribute: [%s]\n",
                   strerror(ret)));
            goto done;
        }

        ret = sysdb_attrs_get_uint32_t(attrs,
                                       opts->group_map[SDAP_AT_GROUP_GID].sys_name,
                                       &gid);
        if (ret != EOK) {
            DEBUG(1, ("no gid provided for [%s] in domain [%s].\n",
                      name, dom->name));
            ret = EINVAL;
            goto done;
        }
    }

    /* check that the gid is valid for this domain */
    if (posix_group) {
        if (OUT_OF_ID_RANGE(gid, dom->id_min, dom->id_max)) {
            DEBUG(2, ("Group [%s] filtered out! (id out of range)\n",
                      name));
            ret = EINVAL;
            goto done;
        }
        /* Group ID OK */
    }

    ret = sdap_attrs_add_string(attrs, SYSDB_ORIG_DN, "original DN",
                                name, group_attrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Error setting original DN: [%s]\n",
               strerror(ret)));
        goto done;
    }

    ret = sdap_attrs_add_string(attrs,
                            opts->group_map[SDAP_AT_GROUP_MODSTAMP].sys_name,
                            "original mod-Timestamp",
                            name, group_attrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Error setting mod timestamp: [%s]\n",
               strerror(ret)));
        goto done;
    }

    ret = sysdb_attrs_get_el(attrs,
                      opts->group_map[SDAP_AT_GROUP_USN].sys_name, &el);
    if (ret) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Error looking up group USN: [%s]\n",
               strerror(ret)));
        goto done;
    }
    if (el->num_values == 0) {
        DEBUG(7, ("Original USN value is not available for [%s].\n",
                  name));
    } else {
        ret = sysdb_attrs_add_string(group_attrs,
                          opts->group_map[SDAP_AT_GROUP_USN].sys_name,
                          (const char*)el->values[0].data);
        if (ret) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("Error setting group USN: [%s]\n",
                   strerror(ret)));
            goto done;
        }
        usn_value = talloc_strdup(tmpctx, (const char*)el->values[0].data);
        if (!usn_value) {
            ret = ENOMEM;
            goto done;
        }
    }

    ret = sdap_process_ghost_members(attrs, opts, ghosts,
                                     populate_members, store_original_member,
                                     group_attrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Failed to save ghost members\n"));
        goto done;
    }

    ret = sdap_save_all_names(name, attrs, !dom->case_sensitive, group_attrs);
    if (ret != EOK) {
        DEBUG(1, ("Failed to save group names\n"));
        goto done;
    }

    DEBUG(6, ("Storing info for group %s\n", name));

    ret = sdap_store_group_with_gid(ctx,
                                    name, gid, group_attrs,
                                    dom->group_timeout,
                                    posix_group, now);
    if (ret) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Could not store group with GID: [%s]\n",
               strerror(ret)));
        goto done;
    }

    if (_usn_value) {
        *_usn_value = talloc_steal(memctx, usn_value);
    }

    talloc_steal(memctx, group_attrs);
    ret = EOK;

done:
    if (ret) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Failed to save group [%s]: [%s]\n",
               name ? name : "Unknown",
               strerror(ret)));
    }
    talloc_free(tmpctx);
    return ret;
}


/* ==Save-Group-Memebrs=================================================== */

    /* FIXME: support non legacy */
    /* FIXME: support storing additional attributes */

static int sdap_save_grpmem(TALLOC_CTX *memctx,
                            struct sysdb_ctx *ctx,
                            struct sdap_options *opts,
                            struct sss_domain_info *dom,
                            struct sysdb_attrs *attrs,
                            hash_table_t *ghosts,
                            time_t now)
{
    struct ldb_message_element *el;
    struct sysdb_attrs *group_attrs = NULL;
    const char *name;
    char **userdns = NULL;
    size_t nuserdns = 0;
    int ret;

    ret = sysdb_attrs_primary_name(ctx, attrs,
                                   opts->group_map[SDAP_AT_GROUP_NAME].name,
                                   &name);
    if (ret != EOK) {
        goto fail;
    }

    /* With AD we also want to merge in parent groups of primary GID as they
     * are reported with tokenGroups, too
     */
    if (opts->schema_type == SDAP_SCHEMA_AD) {
        ret = sdap_dn_by_primary_gid(memctx, attrs, ctx, opts,
                                     &userdns, &nuserdns);
        if (ret != EOK) {
            goto fail;
        }
    }

    ret = sysdb_attrs_get_el(attrs,
                    opts->group_map[SDAP_AT_GROUP_MEMBER].sys_name, &el);
    if (ret != EOK) {
        goto fail;
    }
    if (el->num_values == 0 && nuserdns == 0) {
        DEBUG(7, ("No members for group [%s]\n", name));

    } else {
        DEBUG(7, ("Adding member users to group [%s]\n", name));

        group_attrs = sysdb_new_attrs(memctx);
        if (!group_attrs) {
            ret = ENOMEM;
            goto fail;
        }

        ret = sdap_fill_memberships(group_attrs, ctx, dom, ghosts,
                                    el->values, el->num_values,
                                    userdns, nuserdns);
        if (ret) {
            goto fail;
        }
    }

    DEBUG(6, ("Storing members for group %s\n", name));

    ret = sysdb_store_group(ctx, name, 0, group_attrs,
                            dom->group_timeout, now);
    if (ret) goto fail;

    return EOK;

fail:
    DEBUG(2, ("Failed to save user %s\n", name));
    return ret;
}


/* ==Generic-Function-to-save-multiple-groups============================= */

static int sdap_save_groups(TALLOC_CTX *memctx,
                            struct sysdb_ctx *sysdb,
                            struct sss_domain_info *dom,
                            struct sdap_options *opts,
                            struct sysdb_attrs **groups,
                            int num_groups,
                            bool populate_members,
                            hash_table_t *ghosts,
                            char **_usn_value)
{
    TALLOC_CTX *tmpctx;
    char *higher_usn = NULL;
    char *usn_value;
    bool twopass;
    bool has_nesting = false;
    int ret;
    errno_t sret;
    int i;
    struct sysdb_attrs **saved_groups = NULL;
    int nsaved_groups = 0;
    time_t now;
    bool in_transaction = false;

    switch (opts->schema_type) {
    case SDAP_SCHEMA_RFC2307:
        twopass = false;
        break;

    case SDAP_SCHEMA_RFC2307BIS:
    case SDAP_SCHEMA_IPA_V1:
    case SDAP_SCHEMA_AD:
        twopass = true;
        has_nesting = true;
        break;

    default:
        return EINVAL;
    }

    tmpctx = talloc_new(memctx);
    if (!tmpctx) {
        return ENOMEM;
    }

    ret = sysdb_transaction_start(sysdb);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to start transaction\n"));
        goto done;
    }
    in_transaction = true;

    if (twopass && !populate_members) {
        saved_groups = talloc_array(tmpctx, struct sysdb_attrs *,
                                    num_groups);
        if (!saved_groups) {
            ret = ENOMEM;
            goto done;
        }
    }

    now = time(NULL);
    for (i = 0; i < num_groups; i++) {
        usn_value = NULL;

        /* if 2 pass savemembers = false */
        ret = sdap_save_group(tmpctx, sysdb,
                              opts, dom, groups[i],
                              populate_members, has_nesting,
                              ghosts, &usn_value, now);

        /* Do not fail completely on errors.
         * Just report the failure to save and go on */
        if (ret) {
            DEBUG(2, ("Failed to store group %d. Ignoring.\n", i));
        } else {
            DEBUG(9, ("Group %d processed!\n", i));
            if (twopass && !populate_members) {
                saved_groups[nsaved_groups] = groups[i];
                nsaved_groups++;
            }
        }

        if (usn_value) {
            if (higher_usn) {
                if ((strlen(usn_value) > strlen(higher_usn)) ||
                    (strcmp(usn_value, higher_usn) > 0)) {
                    talloc_zfree(higher_usn);
                    higher_usn = usn_value;
                } else {
                    talloc_zfree(usn_value);
                }
            } else {
                higher_usn = usn_value;
            }
        }
    }

    if (twopass && !populate_members) {

        for (i = 0; i < nsaved_groups; i++) {

            ret = sdap_save_grpmem(tmpctx, sysdb, opts, dom, saved_groups[i],
                                   ghosts, now);
            /* Do not fail completely on errors.
             * Just report the failure to save and go on */
            if (ret) {
                DEBUG(2, ("Failed to store group %d members.\n", i));
            } else {
                DEBUG(9, ("Group %d members processed!\n", i));
            }
        }
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to commit transaction!\n"));
        goto done;
    }
    in_transaction = false;

    if (_usn_value) {
        *_usn_value = talloc_steal(memctx, higher_usn);
    }

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to cancel transaction\n"));
        }
    }
    talloc_zfree(tmpctx);
    return ret;
}


/* ==Process-Groups======================================================= */

struct sdap_process_group_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sdap_handle *sh;
    struct sss_domain_info *dom;
    struct sysdb_ctx *sysdb;

    struct sysdb_attrs *group;
    struct ldb_message_element* sysdb_dns;
    struct ldb_message_element* ghost_dns;
    char **queued_members;
    int queue_len;
    const char **attrs;
    const char *filter;
    size_t queue_idx;
    size_t count;
    size_t check_count;

    bool enumeration;
};

#define GROUPMEMBER_REQ_PARALLEL 50
static void sdap_process_group_members(struct tevent_req *subreq);

static int sdap_process_group_members_2307bis(struct tevent_req *req,
                                   struct sdap_process_group_state *state,
                                   struct ldb_message_element *memberel);
static int sdap_process_group_members_2307(struct sdap_process_group_state *state,
                                   struct ldb_message_element *memberel,
                                   struct ldb_message_element *ghostel);

static errno_t sdap_process_group_create_dns(TALLOC_CTX *mem_ctx,
                                             size_t num_values,
                                             struct ldb_message_element **_dns)
{
    struct ldb_message_element *dns;

    dns = talloc(mem_ctx, struct ldb_message_element);
    if (dns == NULL) {
        return ENOMEM;
    }

    dns->num_values = 0;
    dns->values = talloc_array(dns, struct ldb_val,
                               num_values);
    if (dns->values == NULL) {
        talloc_zfree(dns);
        return ENOMEM;
    }

    *_dns = dns;

    return EOK;
}

struct tevent_req *sdap_process_group_send(TALLOC_CTX *memctx,
                                           struct tevent_context *ev,
                                           struct sss_domain_info *dom,
                                           struct sysdb_ctx *sysdb,
                                           struct sdap_options *opts,
                                           struct sdap_handle *sh,
                                           struct sysdb_attrs *group,
                                           bool enumeration)
{
    struct ldb_message_element *el;
    struct ldb_message_element *ghostel;
    struct sdap_process_group_state *grp_state;
    struct tevent_req *req = NULL;
    const char **attrs;
    char* filter;
    int ret;

    req = tevent_req_create(memctx, &grp_state,
                            struct sdap_process_group_state);
    if (!req) return NULL;

    ret = build_attrs_from_map(grp_state, opts->user_map, SDAP_OPTS_USER,
                               NULL, &attrs, NULL);
    if (ret) {
        goto done;
    }

    /* FIXME: we ignore nested rfc2307bis groups for now */
    filter = talloc_asprintf(grp_state, "(objectclass=%s)",
                             opts->user_map[SDAP_OC_USER].name);
    if (!filter) {
        talloc_zfree(req);
        return NULL;
    }

    grp_state->ev = ev;
    grp_state->opts = opts;
    grp_state->dom = dom;
    grp_state->sh = sh;
    grp_state->sysdb = sysdb;
    grp_state->group =  group;
    grp_state->check_count = 0;
    grp_state->queue_idx = 0;
    grp_state->queued_members = NULL;
    grp_state->queue_len = 0;
    grp_state->filter = filter;
    grp_state->attrs = attrs;
    grp_state->enumeration = enumeration;

    ret = sysdb_attrs_get_el(group,
                             opts->group_map[SDAP_AT_GROUP_MEMBER].sys_name,
                             &el);
    if (ret) {
        goto done;
    }

    /* Group without members */
    if (el->num_values == 0) {
        DEBUG(2, ("No Members. Done!\n"));
        ret = EOK;
        goto done;
    }

    ret = sysdb_attrs_get_el(group,
                             SYSDB_GHOST,
                             &ghostel);
    if (ret) {
        goto done;
    }

    if (ghostel->num_values == 0) {
        /* Element was probably newly created, look for "member" again */
        ret = sysdb_attrs_get_el(group,
                                 opts->group_map[SDAP_AT_GROUP_MEMBER].sys_name,
                                 &el);
        if (ret != EOK) {
            goto done;
        }
    }


    ret = sdap_process_group_create_dns(grp_state, el->num_values,
                                        &grp_state->sysdb_dns);
    if (ret != EOK) {
        goto done;
    }

    ret = sdap_process_group_create_dns(grp_state, el->num_values,
                                        &grp_state->ghost_dns);
    if (ret != EOK) {
        goto done;
    }

    switch (opts->schema_type) {
        case SDAP_SCHEMA_RFC2307:
            ret = sdap_process_group_members_2307(grp_state, el, ghostel);
            break;

        case SDAP_SCHEMA_IPA_V1:
        case SDAP_SCHEMA_AD:
        case SDAP_SCHEMA_RFC2307BIS:
            /* Note that this code branch will be used only if
             * ldap_nesting_level = 0 is set in config file
             */
            ret = sdap_process_group_members_2307bis(req, grp_state, el);
            break;

        default:
            DEBUG(1, ("Unknown schema type %d\n", opts->schema_type));
            ret = EINVAL;
            break;
    }

done:
    /* We managed to process all the entries */
    /* EBUSY means we need to wait for entries in LDAP */
    if (ret == EOK) {
        DEBUG(7, ("All group members processed\n"));
        tevent_req_done(req);
        tevent_req_post(req, ev);
    }

    if (ret != EOK && ret != EBUSY) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }
    return req;
}

static int
sdap_process_missing_member_2307bis(struct tevent_req *req,
                                    char *user_dn,
                                    int num_users)
{
    struct sdap_process_group_state *grp_state =
        tevent_req_data(req, struct sdap_process_group_state);
    struct tevent_req *subreq;

    /*
     * Issue at most GROUPMEMBER_REQ_PARALLEL LDAP searches at once.
     * The rest is sent while the results are being processed.
     * We limit the number as of request here, as the Server might
     * enforce limits on the number of pending operations per
     * connection.
     */
    if (grp_state->check_count > GROUPMEMBER_REQ_PARALLEL) {
        DEBUG(7, (" queueing search for: %s\n", user_dn));
        if (!grp_state->queued_members) {
            DEBUG(7, ("Allocating queue for %d members\n",
                      num_users - grp_state->check_count));

            grp_state->queued_members = talloc_array(grp_state, char *,
                    num_users - grp_state->check_count + 1);
            if (!grp_state->queued_members) {
                return ENOMEM;
            }
        }
        grp_state->queued_members[grp_state->queue_len] = user_dn;
        grp_state->queue_len++;
    } else {
        subreq = sdap_get_generic_send(grp_state,
                                       grp_state->ev,
                                       grp_state->opts,
                                       grp_state->sh,
                                       user_dn,
                                       LDAP_SCOPE_BASE,
                                       grp_state->filter,
                                       grp_state->attrs,
                                       grp_state->opts->user_map,
                                       SDAP_OPTS_USER,
                                       dp_opt_get_int(grp_state->opts->basic,
                                                      SDAP_SEARCH_TIMEOUT),
                                       false);
        if (!subreq) {
            return ENOMEM;
        }
        tevent_req_set_callback(subreq, sdap_process_group_members, req);
    }

    grp_state->check_count++;
    return EOK;
}

static int
sdap_process_group_members_2307bis(struct tevent_req *req,
                                   struct sdap_process_group_state *state,
                                   struct ldb_message_element *memberel)
{
    char *member_dn;
    char *strdn;
    int ret;
    int i;

    for (i=0; i < memberel->num_values; i++) {
        member_dn = (char *)memberel->values[i].data;

        ret = sdap_find_entry_by_origDN(state->sysdb_dns->values,
                                        state->sysdb,
                                        state->dom,
                                        member_dn,
                                        &strdn);
        if (ret == EOK) {
            /*
             * User already cached in sysdb. Remember the sysdb DN for later
             * use by sdap_save_groups()
             */
            DEBUG(7, ("sysdbdn: %s\n", strdn));
            state->sysdb_dns->values[state->sysdb_dns->num_values].data =
                (uint8_t*) strdn;
            state->sysdb_dns->values[state->sysdb_dns->num_values].length =
                strlen(strdn);
            state->sysdb_dns->num_values++;
        } else if (ret == ENOENT) {
            if (!state->enumeration) {
                /* The user is not in sysdb, need to add it
                 * We don't need to do this if we're in an enumeration,
                 * because all real members should all be populated
                 * already by the first pass of the enumeration.
                 * Also, we don't want to be holding the sysdb
                 * transaction while we're performing LDAP lookups.
                 */
                DEBUG(7, ("Searching LDAP for missing user entry\n"));
                ret = sdap_process_missing_member_2307bis(req,
                                                          member_dn,
                                                          memberel->num_values);
                if (ret != EOK) {
                    DEBUG(1, ("Error processing missing member #%d (%s):\n",
                              i, member_dn));
                    return ret;
                }
            }
        } else {
            DEBUG(1, ("Error checking cache for member #%d (%s):\n",
                       i, (char *)memberel->values[i].data));
            return ret;
        }
    }

    if (state->queue_len > 0) {
        state->queued_members[state->queue_len]=NULL;
    }

    if (state->check_count == 0) {
        /*
         * All group members are already cached in sysdb, we are done
         * with this group. To avoid redundant sysdb lookups, populate the
         * "member" attribute of the group entry with the sysdb DNs of
         * the members.
         */
        ret = EOK;
        memberel->values = talloc_steal(state->group, state->sysdb_dns->values);
        memberel->num_values = state->sysdb_dns->num_values;
    } else {
        state->count = state->check_count;
        ret = EBUSY;
    }

    return ret;
}

static int
sdap_add_group_member_2307(struct ldb_message_element *sysdb_dns,
                           struct sss_domain_info *dom,
                           const char *username)
{
    sysdb_dns->values[sysdb_dns->num_values].data =
            (uint8_t *) talloc_strdup(sysdb_dns->values, username);
    if (sysdb_dns->values[sysdb_dns->num_values].data == NULL) {
        return ENOMEM;
    }
    sysdb_dns->values[sysdb_dns->num_values].length =
            strlen(username);
    sysdb_dns->num_values++;

    return EOK;
}

static int
sdap_process_missing_member_2307(struct sdap_process_group_state *state,
                                 char *member_name, time_t now)
{
    int ret;
    TALLOC_CTX *tmp_ctx;
    const char *filter;
    const char *username;
    const char *user_dn;
    size_t count;
    struct ldb_message **msgs = NULL;
    static const char *attrs[] = { SYSDB_NAME, NULL };

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    /* Check for the alias in the sysdb */
    filter = talloc_asprintf(tmp_ctx, "(%s=%s)", SYSDB_NAME_ALIAS, member_name);
    if (!filter) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_users(tmp_ctx, state->sysdb, filter,
                             attrs, &count, &msgs);
    if (ret == EOK && count > 0) {
        /* Entry exists but the group references it with an alias. */

        if (count != 1) {
            DEBUG(1, ("More than one entry with this alias?\n"));
            ret = EIO;
            goto done;
        }

        /* fill username with primary name */
        username = ldb_msg_find_attr_as_string(msgs[0], SYSDB_NAME, NULL);
        if (username == NULL) {
            ret = EINVAL;
            DEBUG(SSSDBG_MINOR_FAILURE, ("Inconsistent sysdb: user "
                                         "without primary name?\n"));
            goto done;
        }
        user_dn = sysdb_user_strdn(tmp_ctx, state->dom->name, username);
        if (user_dn == NULL) {
            return ENOMEM;
        }

        ret = sdap_add_group_member_2307(state->sysdb_dns, state->dom, user_dn);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, ("Could not add group member %s\n", username));
        }
    } else if (ret == ENOENT || count == 0) {
        /* The entry really does not exist, add a ghost */
        DEBUG(SSSDBG_TRACE_FUNC, ("Adding a ghost entry\n"));
        ret = sdap_add_group_member_2307(state->ghost_dns, state->dom, member_name);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, ("Could not add group member %s\n", member_name));
        }
    } else {
        ret = EIO;
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}

static int
sdap_process_group_members_2307(struct sdap_process_group_state *state,
                                struct ldb_message_element *memberel,
                                struct ldb_message_element *ghostel)
{
    struct ldb_message *msg;
    char *member_name;
    char *userdn;
    int ret;
    time_t now;
    int i;

    now = time(NULL);
    for (i=0; i < memberel->num_values; i++) {
        member_name = (char *)memberel->values[i].data;

        /* We need to skip over zero-length usernames */
        if (member_name[0] == '\0') continue;

        ret = sysdb_search_user_by_name(state, state->sysdb,
                                        member_name, NULL, &msg);
        if (ret == EOK) {
            /*
             * User already cached in sysdb. Remember the sysdb DN for later
             * use by sdap_save_groups()
             */
            DEBUG(7, ("Member already cached in sysdb: %s\n", member_name));

            userdn = sysdb_user_strdn(state->sysdb_dns, state->dom->name, member_name);
            if (userdn == NULL) {
                return ENOMEM;
            }

            ret = sdap_add_group_member_2307(state->sysdb_dns, state->dom, userdn);
            if (ret != EOK) {
                DEBUG(1, ("Could not add member %s into sysdb\n", member_name));
                goto done;
            }
        } else if (ret == ENOENT) {
            /* The user is not in sysdb, need to add it */
            DEBUG(7, ("member #%d (%s): not found in sysdb\n",
                       i, member_name));

            ret = sdap_process_missing_member_2307(state, member_name, now);
            if (ret != EOK) {
                DEBUG(1, ("Error processing missing member #%d (%s):\n",
                          i, member_name));
                goto done;
            }
        } else {
            DEBUG(1, ("Error checking cache for member #%d (%s):\n",
                       i, (char *) memberel->values[i].data));
            goto done;
        }
    }

    ret = EOK;
    talloc_free(memberel->values);
    memberel->values = talloc_steal(state->group, state->sysdb_dns->values);
    memberel->num_values = state->sysdb_dns->num_values;
    talloc_free(ghostel->values);
    ghostel->values = talloc_steal(state->group, state->ghost_dns->values);
    ghostel->num_values = state->ghost_dns->num_values;

done:
    return ret;
}

static void sdap_process_group_members(struct tevent_req *subreq)
{
    struct sysdb_attrs **usr_attrs;
    size_t count;
    int ret;
    struct tevent_req *req =
                        tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_process_group_state *state =
                        tevent_req_data(req, struct sdap_process_group_state);
    struct ldb_message_element *el;
    uint8_t* name_string;

    state->check_count--;
    DEBUG(9, ("Members remaining: %d\n", state->check_count));

    ret = sdap_get_generic_recv(subreq, state, &count, &usr_attrs);
    talloc_zfree(subreq);
    if (ret) {
        goto next;
    }
    if (count != 1) {
        ret = EINVAL;
        DEBUG(7, ("Expected one user entry and got %d\n", count));
        goto next;
    }
    ret = sysdb_attrs_get_el(usr_attrs[0],
            state->opts->user_map[SDAP_AT_USER_NAME].sys_name, &el);
    if (el->num_values == 0) {
        ret = EINVAL;
    }
    if (ret) {
        DEBUG(2, ("Failed to get the member's name\n"));
        goto next;
    }

    name_string = el[0].values[0].data;
    state->ghost_dns->values[state->ghost_dns->num_values].data =
            talloc_steal(state->ghost_dns->values, name_string);
    state->ghost_dns->values[state->ghost_dns->num_values].length =
            strlen((char *)name_string);
    state->ghost_dns->num_values++;

next:
    if (ret) {
        DEBUG(7, ("Error reading group member. Skipping\n", ret));
        state->count--;
    }
    /* Are there more searches for uncached users to submit ? */
    if (state->queued_members && state->queued_members[state->queue_idx]) {
        subreq = sdap_get_generic_send(state,
                                       state->ev, state->opts, state->sh,
                                       state->queued_members[state->queue_idx],
                                       LDAP_SCOPE_BASE,
                                       state->filter,
                                       state->attrs,
                                       state->opts->user_map,
                                       SDAP_OPTS_USER,
                                       dp_opt_get_int(state->opts->basic,
                                                      SDAP_SEARCH_TIMEOUT),
                                       false);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }

        tevent_req_set_callback(subreq,
                                sdap_process_group_members, req);
        state->queue_idx++;
    }

    if (state->check_count == 0) {
        /*
         * To avoid redundant sysdb lookups, populate the "member" attribute
         * of the group entry with the sysdb DNs of the members.
         */
        ret = sysdb_attrs_get_el(state->group,
                        state->opts->group_map[SDAP_AT_GROUP_MEMBER].sys_name,
                        &el);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  ("Failed to get the group member attribute [%d]: %s\n",
                  ret, strerror(ret)));
            tevent_req_error(req, ret);
            return;
        }
        el->values = talloc_steal(state->group, state->sysdb_dns->values);
        el->num_values = state->sysdb_dns->num_values;

        ret = sysdb_attrs_get_el(state->group, SYSDB_GHOST, &el);
        if (ret != EOK) {
            tevent_req_error(req, ret);
            return;
        }
        el->values = talloc_steal(state->group, state->ghost_dns->values);
        el->num_values = state->ghost_dns->num_values;
        DEBUG(9, ("Processed Group - Done\n"));
        tevent_req_done(req);
    }
}

static int sdap_process_group_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}


/* ==Search-Groups-with-filter============================================ */

struct sdap_get_groups_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sdap_handle *sh;
    struct sss_domain_info *dom;
    struct sysdb_ctx *sysdb;
    const char **attrs;
    const char *base_filter;
    char *filter;
    int timeout;
    bool enumeration;

    char *higher_usn;
    struct sysdb_attrs **groups;
    size_t count;
    size_t check_count;

    hash_table_t *user_hash;
    hash_table_t *group_hash;

    size_t base_iter;
    struct sdap_search_base **search_bases;
};

static errno_t sdap_get_groups_next_base(struct tevent_req *req);
static void sdap_get_groups_process(struct tevent_req *subreq);
static void sdap_get_groups_done(struct tevent_req *subreq);

struct tevent_req *sdap_get_groups_send(TALLOC_CTX *memctx,
                                       struct tevent_context *ev,
                                       struct sss_domain_info *dom,
                                       struct sysdb_ctx *sysdb,
                                       struct sdap_options *opts,
                                       struct sdap_search_base **search_bases,
                                       struct sdap_handle *sh,
                                       const char **attrs,
                                       const char *filter,
                                       int timeout,
                                       bool enumeration)
{
    errno_t ret;
    struct tevent_req *req;
    struct sdap_get_groups_state *state;

    req = tevent_req_create(memctx, &state, struct sdap_get_groups_state);
    if (!req) return NULL;

    state->ev = ev;
    state->opts = opts;
    state->dom = dom;
    state->sh = sh;
    state->sysdb = sysdb;
    state->attrs = attrs;
    state->higher_usn = NULL;
    state->groups =  NULL;
    state->count = 0;
    state->timeout = timeout;
    state->enumeration = enumeration;
    state->base_filter = filter;
    state->base_iter = 0;
    state->search_bases = search_bases;

    if (!search_bases) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Group lookup request without a search base\n"));
        ret = EINVAL;
        goto done;
    }

    ret = sdap_get_groups_next_base(req);

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static errno_t sdap_get_groups_next_base(struct tevent_req *req)
{
    struct tevent_req *subreq;
    struct sdap_get_groups_state *state;

    state = tevent_req_data(req, struct sdap_get_groups_state);

    talloc_zfree(state->filter);
    state->filter = sdap_get_id_specific_filter(state,
                        state->base_filter,
                        state->search_bases[state->base_iter]->filter);
    if (!state->filter) {
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          ("Searching for groups with base [%s]\n",
           state->search_bases[state->base_iter]->basedn));

    subreq = sdap_get_generic_send(
            state, state->ev, state->opts, state->sh,
            state->search_bases[state->base_iter]->basedn,
            state->search_bases[state->base_iter]->scope,
            state->filter, state->attrs,
            state->opts->group_map, SDAP_OPTS_GROUP,
            state->timeout,
            state->enumeration); /* If we're enumerating, we need paging */
    if (!subreq) {
        return ENOMEM;
    }
    tevent_req_set_callback(subreq, sdap_get_groups_process, req);

    return EOK;
}

static struct tevent_req *sdap_nested_group_process_send(
        TALLOC_CTX *mem_ctx, struct tevent_context *ev,
        struct sss_domain_info *domain,
        struct sysdb_ctx *sysdb, struct sysdb_attrs *group,
        hash_table_t *users, hash_table_t *groups,
        struct sdap_options *opts, struct sdap_handle *sh,
        bool enable_deref, uint32_t nesting);
static void sdap_nested_done(struct tevent_req *req);
static errno_t sdap_nested_group_process_recv(struct tevent_req *req);
static void sdap_ad_match_rule_members_process(struct tevent_req *subreq);

static void sdap_get_groups_process(struct tevent_req *subreq)
{
    struct tevent_req *req =
                        tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_get_groups_state *state =
                        tevent_req_data(req, struct sdap_get_groups_state);
    int ret;
    int i;
    bool next_base = false;
    size_t count;
    struct sysdb_attrs **groups;
    bool enable_deref = true;

    ret = sdap_get_generic_recv(subreq, state,
                                &count, &groups);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(6, ("Search for groups, returned %d results.\n", count));

    if (!state->enumeration && count > 1) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Individual group search returned multiple results\n"));
        tevent_req_error(req, EINVAL);
        return;
    }

    if (state->enumeration || count == 0) {
        next_base = true;
    }

    /* Add this batch of groups to the list */
    if (count > 0) {
        state->groups =
                talloc_realloc(state,
                               state->groups,
                               struct sysdb_attrs *,
                               state->count + count + 1);
        if (!state->groups) {
            tevent_req_error(req, ENOMEM);
            return;
        }

        /* Copy the new groups into the list
         */
        for (i = 0; i < count; i++) {
            state->groups[state->count + i] =
                talloc_steal(state->groups, groups[i]);
        }

        state->count += count;
        state->groups[state->count] = NULL;
    }

    if (next_base) {
        state->base_iter++;
        if (state->search_bases[state->base_iter]) {
            /* There are more search bases to try */
            ret = sdap_get_groups_next_base(req);
            if (ret != EOK) {
                tevent_req_error(req, ret);
            }
            return;
        }
    }

    /* No more search bases
     * Return ENOENT if no groups were found
     */
    if (state->count == 0) {
        tevent_req_error(req, ENOENT);
        return;
    }

    /* Check whether we need to do nested searches
     * for RFC2307bis/FreeIPA/ActiveDirectory
     * We don't need to do this for enumeration,
     * because all groups will be picked up anyway.
     *
     * We can also skip this if we're using the
     * LDAP_MATCHING_RULE_IN_CHAIN available in
     * AD 2008 and later
     */
    if (!state->enumeration) {
        if ((state->opts->schema_type != SDAP_SCHEMA_RFC2307)
                && (dp_opt_get_int(state->opts->basic, SDAP_NESTING_LEVEL) != 0)
                && !dp_opt_get_bool(state->opts->basic, SDAP_AD_MATCHING_RULE_GROUPS)) {

            /* Prepare hashes for nested user processing */
            ret = sss_hash_create(state, 32, &state->user_hash);
            if (ret != EOK) {
                tevent_req_error(req, ret);
                return;
            }

            ret = sss_hash_create(state, 32, &state->group_hash);
            if (ret != EOK) {
                tevent_req_error(req, ret);
                return;
            }

            /*
             * If any search base contains filter, disable dereference.
             */
            enable_deref = true;
            for (i = 0; state->opts->user_search_bases[i] != NULL; i++) {
                if (state->opts->user_search_bases[i]->filter != NULL) {
                    DEBUG(SSSDBG_TRACE_FUNC,
                          ("User search base contains filter, "
                           "dereference will be disabled\n"));
                    enable_deref = false;
                    break;
                }
            }

            if (enable_deref) {
                for (i = 0; state->opts->group_search_bases[i] != NULL; i++) {
                    if (state->opts->group_search_bases[i]->filter != NULL) {
                        DEBUG(SSSDBG_TRACE_FUNC,
                              ("Group search base contains filter, "
                               "dereference will be disabled\n"));
                        enable_deref = false;
                        break;
                    }
                }
            }

            subreq = sdap_nested_group_process_send(state,
                                                    state->ev,
                                                    state->dom,
                                                    state->sysdb,
                                                    state->groups[0],
                                                    state->user_hash,
                                                    state->group_hash,
                                                    state->opts,
                                                    state->sh,
                                                    enable_deref,
                                                    0);
            if (!subreq) {
                tevent_req_error(req, EIO);
                return;
            }

            tevent_req_set_callback(subreq, sdap_nested_done, req);
            return;
        }
    }

    /* We have all of the groups. Save them to the sysdb */
    state->check_count = state->count;

    /* If we're using LDAP_MATCHING_RULE_IN_CHAIN, start a subreq to
     * retrieve the members so we can save them in a single step.
     */
    if (!state->enumeration
            && (state->opts->schema_type != SDAP_SCHEMA_RFC2307)
            && state->opts->support_matching_rule
            && dp_opt_get_bool(state->opts->basic, SDAP_AD_MATCHING_RULE_GROUPS)) {
        subreq = sdap_get_ad_match_rule_members_send(
                state, state->ev, state->opts, state->sh,
                state->groups[0], state->timeout);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq,
                                sdap_ad_match_rule_members_process,
                                req);
        return;
    }

    ret = sysdb_transaction_start(state->sysdb);
    if (ret != EOK) {
        DEBUG(0, ("Failed to start transaction\n"));
        tevent_req_error(req, ret);
        return;
    }

    if (state->enumeration
            && state->opts->schema_type != SDAP_SCHEMA_RFC2307
            && dp_opt_get_int(state->opts->basic, SDAP_NESTING_LEVEL) != 0) {
        DEBUG(9, ("Saving groups without members first "
                  "to allow unrolling of nested groups.\n"));
        ret = sdap_save_groups(state, state->sysdb, state->dom, state->opts,
                               state->groups, state->count, false,
                               NULL, NULL);
        if (ret) {
            DEBUG(2, ("Failed to store groups.\n"));
            tevent_req_error(req, ret);
            return;
        }
    }

    for (i = 0; i < state->count; i++) {
        subreq = sdap_process_group_send(state, state->ev, state->dom,
                                         state->sysdb, state->opts,
                                         state->sh, state->groups[i],
                                         state->enumeration);

        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, sdap_get_groups_done, req);
    }
}

static void sdap_get_groups_done(struct tevent_req *subreq)
{
    struct tevent_req *req =
                        tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_get_groups_state *state =
                        tevent_req_data(req, struct sdap_get_groups_state);

    int ret;
    errno_t sysret;

    ret = sdap_process_group_recv(subreq);
    talloc_zfree(subreq);
    if (ret) {
        sysret = sysdb_transaction_cancel(state->sysdb);
        if (sysret != EOK) {
            DEBUG(0, ("Could not cancel sysdb transaction\n"));
        }
        tevent_req_error(req, ret);
        return;
    }

    state->check_count--;
    DEBUG(9, ("Groups remaining: %d\n", state->check_count));


    if (state->check_count == 0) {
        DEBUG(9, ("All groups processed\n"));

        ret = sdap_save_groups(state, state->sysdb, state->dom, state->opts,
                               state->groups, state->count, true, NULL,
                               &state->higher_usn);
        if (ret) {
            DEBUG(2, ("Failed to store groups.\n"));
            tevent_req_error(req, ret);
            return;
        }
        DEBUG(9, ("Saving %d Groups - Done\n", state->count));
        sysret = sysdb_transaction_commit(state->sysdb);
        if (sysret != EOK) {
            DEBUG(0, ("Couldn't commit transaction\n"));
            tevent_req_error(req, sysret);
        } else {
            tevent_req_done(req);
        }
    }
}

static errno_t sdap_nested_group_populate_users(TALLOC_CTX *mem_ctx,
                                                struct sysdb_ctx *sysdb,
                                                struct sdap_options *opts,
                                                struct sysdb_attrs **users,
                                                int num_users,
                                                hash_table_t **_ghosts);

static void sdap_ad_match_rule_members_process(struct tevent_req *subreq)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx = NULL;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_get_groups_state *state = tevent_req_data(req,
                                            struct sdap_get_groups_state);
    struct sysdb_attrs **users;
    struct sysdb_attrs *group = state->groups[0];
    struct ldb_message_element *member_el;
    struct ldb_message_element *orig_dn_el;
    size_t count;
    size_t i;
    hash_table_t *ghosts;

    ret = sdap_get_ad_match_rule_members_recv(subreq, state,
                                              &count, &users);
    talloc_zfree(subreq);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Could not retrieve members using AD match rule. [%s]\n",
               strerror(ret)));

        goto done;
    }

    /* Save the group and users to the cache */

    /* Truncate the member attribute of the group.
     * It will be repopulated below, and it may currently
     * be incomplete anyway, thanks to the range extension.
     */

    ret = sysdb_attrs_get_el(group, SYSDB_MEMBER, &member_el);
    if (ret != EOK) {
        goto done;
    }

    member_el->num_values = 0;
    talloc_zfree(member_el->values);

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        ret = ENOMEM;
        goto done;
    }

    /* Figure out which users are already cached in the sysdb and
     * which ones need to be added as ghost users.
     */
    ret = sdap_nested_group_populate_users(tmp_ctx, state->sysdb,
                                           state->opts, users, count,
                                           &ghosts);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Could not determine which users are ghosts: [%s]\n",
               strerror(ret)));
        goto done;
    }

    /* Add any entries that aren't in the ghost hash table to the
     * member element of the group. This will get converted to a
     * native sysdb representation later in sdap_save_groups().
     */

    /* Add all of the users as members
     */
    member_el->values = talloc_zero_array(tmp_ctx, struct ldb_val, count);
    if (!member_el->values) {
        ret = ENOMEM;
        goto done;
    }

    /* Copy the origDN values of the users into the member element */
    for (i = 0; i < count; i++) {
        ret = sysdb_attrs_get_el(users[i], SYSDB_ORIG_DN,
                                 &orig_dn_el);
        if (ret != EOK) {
            /* This should never happen. Every entry should have
             * an originalDN.
             */
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("BUG: Missing originalDN for user?\n"));
            goto done;
        }

        /* These values will have the same lifespan, so instead
         * of copying them, just point at the data.
         */
        member_el->values[i].data = orig_dn_el->values[0].data;
        member_el->values[i].length = orig_dn_el->values[0].length;
    }
    member_el->num_values = count;

    /* Now save the group, users and ghosts to the cache */
    ret = sdap_save_groups(tmp_ctx, state->sysdb, state->dom,
                           state->opts, state->groups, 1,
                           false, ghosts, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Could not save group to the cache: [%s]\n",
               strerror(ret)));
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
}

int sdap_get_groups_recv(struct tevent_req *req,
                         TALLOC_CTX *mem_ctx, char **usn_value)
{
    struct sdap_get_groups_state *state = tevent_req_data(req,
                                            struct sdap_get_groups_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (usn_value) {
        *usn_value = talloc_steal(mem_ctx, state->higher_usn);
    }

    return EOK;
}

static void sdap_nested_done(struct tevent_req *subreq)
{
    errno_t ret, tret;
    int hret;
    unsigned long i;
    unsigned long user_count;
    unsigned long group_count;
    hash_value_t *values;
    bool in_transaction = false;
    struct sysdb_attrs **users = NULL;
    struct sysdb_attrs **groups = NULL;
    hash_table_t *ghosts;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_groups_state *state = tevent_req_data(req,
                                            struct sdap_get_groups_state);

    ret = sdap_nested_group_process_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(1, ("Nested group processing failed: [%d][%s]\n",
                  ret, strerror(ret)));
        goto fail;
    }

    hret = hash_values(state->user_hash, &user_count, &values);
    if (hret != HASH_SUCCESS) {
        ret = EIO;
        goto fail;
    }

    if (user_count) {
        users = talloc_array(state, struct sysdb_attrs *, user_count);
        if (!users) {
            talloc_free(values);
            ret = ENOMEM;
            goto fail;
        }

        for (i = 0; i < user_count; i++) {
            users[i] = talloc_get_type(values[i].ptr, struct sysdb_attrs);
        }
        talloc_zfree(values);
    }

    /* Users are all retrieved. Now retrieve groups */
    hret = hash_values(state->group_hash, &group_count, &values);
    if (hret != HASH_SUCCESS) {
        ret = EIO;
        goto fail;
    }

    groups = talloc_array(state, struct sysdb_attrs *, group_count);
    if (!groups) {
        talloc_free(values);
        ret = ENOMEM;
        goto fail;
    }

    for (i = 0; i < group_count; i++) {
        groups[i] = talloc_get_type(values[i].ptr, struct sysdb_attrs);
    }
    talloc_zfree(values);

    /* Save all of the users first so that they are in
     * place for the groups to add them.
     */
    ret = sysdb_transaction_start(state->sysdb);
    if (ret != EOK) {
        DEBUG(1, ("Failed to start transaction\n"));
        goto fail;
    }
    in_transaction = true;

    ret = sdap_nested_group_populate_users(state, state->sysdb, state->opts,
                                           users, user_count, &ghosts);
    if (ret != EOK) {
        goto fail;
    }

    ret = sdap_save_groups(state, state->sysdb, state->dom, state->opts,
                           groups, group_count, false, ghosts,
                           &state->higher_usn);
    if (ret != EOK) {
        goto fail;
    }

    ret = sysdb_transaction_commit(state->sysdb);
    if (ret != EOK) {
        DEBUG(1, ("Failed to commit transaction\n"));
        goto fail;
    }
    in_transaction = false;

    /* Processing complete */
    tevent_req_done(req);
    return;

fail:
    if (in_transaction) {
        tret = sysdb_transaction_cancel(state->sysdb);
        if (tret != EOK) {
            DEBUG(1, ("Failed to cancel transaction\n"));
        }
    }
    tevent_req_error(req, ret);
}

static errno_t sdap_nested_group_populate_users(TALLOC_CTX *mem_ctx,
                                                struct sysdb_ctx *sysdb,
                                                struct sdap_options *opts,
                                                struct sysdb_attrs **users,
                                                int num_users,
                                                hash_table_t **_ghosts)
{
    int i;
    errno_t ret, sret;
    struct ldb_message_element *el;
    const char *username;
    char *clean_orig_dn;
    const char *original_dn;

    TALLOC_CTX *tmp_ctx;
    struct ldb_message **msgs;
    char *filter;
    const char *sysdb_name;
    struct sysdb_attrs *attrs;
    static const char *search_attrs[] = { SYSDB_NAME, NULL };
    hash_table_t *ghosts;
    hash_key_t key;
    hash_value_t value;
    size_t count;
    bool in_transaction = false;

    if (_ghosts == NULL) {
        return EINVAL;
    }

    if (num_users == 0) {
        /* Nothing to do if there are no users */
        *_ghosts = NULL;
        return EOK;
    }

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    ret = sss_hash_create(tmp_ctx, num_users, &ghosts);
    if (ret != HASH_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_transaction_start(sysdb);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to start transaction!\n"));
        goto done;
    }
    in_transaction = true;

    for (i = 0; i < num_users; i++) {
        ret = sysdb_attrs_primary_name(sysdb, users[i],
                                    opts->user_map[SDAP_AT_USER_NAME].name,
                                    &username);
        if (ret != EOK) {
            DEBUG(1, ("User entry %d has no name attribute. Skipping\n", i));
            continue;
        }

        ret = sysdb_attrs_get_el(users[i], SYSDB_ORIG_DN, &el);
        if (el->num_values == 0) {
            ret = EINVAL;
        }
        if (ret != EOK) {
            DEBUG(1, ("User entry %s has no originalDN attribute\n", i));
            goto done;
        }
        original_dn = (const char *) el->values[0].data;

        ret = sss_filter_sanitize(tmp_ctx, original_dn,
                                  &clean_orig_dn);
        if (ret != EOK) {
            DEBUG(1, ("Cannot sanitize originalDN\n", i));
            goto done;
        }

        /* Check for the specified origDN in the sysdb */
        filter = talloc_asprintf(tmp_ctx, "(%s=%s)",
                                 SYSDB_ORIG_DN,
                                 clean_orig_dn);
        if (!filter) {
            ret = ENOMEM;
            goto done;
        }
        ret = sysdb_search_users(tmp_ctx, sysdb, filter,
                                 search_attrs, &count, &msgs);
        talloc_zfree(filter);
        talloc_zfree(clean_orig_dn);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(1, ("Error checking cache for user entry\n"));
            goto done;
        }
        if (ret == EOK) {
            /* The entry is cached but expired. Update the username
             * if needed. */
            if (count != 1) {
                DEBUG(1, ("More than one entry with this origDN? Skipping\n"));
                continue;
            }

            sysdb_name = ldb_msg_find_attr_as_string(msgs[0], SYSDB_NAME, NULL);
            if (strcmp(sysdb_name, username) == 0) {
                /* Username is correct, continue */
                continue;
            }

            attrs = sysdb_new_attrs(tmp_ctx);
            if (!attrs) {
                ret = ENOMEM;
                goto done;
            }

            ret = sysdb_attrs_add_string(attrs, SYSDB_NAME, username);
            if (ret) goto done;
            ret = sysdb_set_user_attr(sysdb, sysdb_name, attrs, SYSDB_MOD_REP);
            if (ret != EOK) goto done;
        }
        else
        {
            key.type = HASH_KEY_STRING;
            key.str = discard_const(original_dn);
            value.type = HASH_VALUE_PTR;
            value.ptr = discard_const(username);
            ret = hash_enter(ghosts, &key, &value);
            if (ret != HASH_SUCCESS) {
                ret = ENOMEM;
                goto done;
            }
        }
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to commit transaction!\n"));
        goto done;
    }
    in_transaction = false;

    ret = EOK;
done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Could not cancel transaction\n"));
        }
    }

    if (ret != EOK) {
        *_ghosts = NULL;
    } else {
        *_ghosts = talloc_steal(mem_ctx, ghosts);
    }
    talloc_zfree(tmp_ctx);
    return ret;
}

/*
 * Get user based on a user DN. Optimized for environments where the containers
 * are strictly defined, such as IPA.
 */
static void
sdap_nested_get_user_done(struct tevent_req *subreq);
static errno_t
sdap_nested_get_ipa_user(TALLOC_CTX *mem_ctx, const char *user_dn,
                         struct sysdb_ctx *sysdb, struct sysdb_attrs ***_reply);

struct sdap_nested_get_user_state {
    size_t count;
    struct sysdb_attrs **replies;
};

static struct tevent_req *
sdap_nested_get_user_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
                          struct sss_domain_info *domain,
                          struct sysdb_ctx *sysdb,
                          struct sdap_options *opts,
                          struct sdap_handle *sh,
                          const char *user_dn,
                          const char *search_bases_filter)
{
    errno_t ret;
    struct tevent_req *req;
    struct tevent_req *subreq;
    const char **sdap_attrs;
    const char *filter;
    struct sdap_nested_get_user_state *state;

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_nested_get_user_state);
    if (!req) {
        return NULL;
    }

    if (opts->schema_type == SDAP_SCHEMA_IPA_V1) {
        /* If the schema is IPA, then just shortcut and guess the name */
        ret = sdap_nested_get_ipa_user(state, user_dn, sysdb, &state->replies);
        if (ret == EOK) {
            state->count = 1;
            goto immediate;
        } else {
            DEBUG(SSSDBG_MINOR_FAILURE, ("Couldn't parse out user information "
                  "based on DN %s, falling back to an LDAP lookup\n"));
        }
    }

    /* Only pull down username and originalDN */
    sdap_attrs = talloc_array(state, const char *, 3);
    if (!sdap_attrs) {
        ret = ENOMEM;
        goto immediate;
    }
    sdap_attrs[0] = "objectClass";
    sdap_attrs[1] = opts->user_map[SDAP_AT_USER_NAME].name;
    sdap_attrs[2] = NULL;

    if (search_bases_filter != NULL) {
        filter = talloc_asprintf(sdap_attrs, "(&%s(objectclass=%s))",
                                 search_bases_filter,
                                 opts->user_map[SDAP_OC_USER].name);
    } else {
        filter = talloc_asprintf(sdap_attrs, "(objectclass=%s)",
                                 opts->user_map[SDAP_OC_USER].name);
    }
    if (!filter) {
        ret = ENOMEM;
        goto immediate;
    }

    subreq = sdap_get_generic_send(state, ev, opts, sh, user_dn,
                                   LDAP_SCOPE_BASE, filter, sdap_attrs,
                                   opts->user_map, SDAP_OPTS_USER,
                                   dp_opt_get_int(opts->basic,
                                                  SDAP_SEARCH_TIMEOUT),
                                   false);
    if (!subreq) {
        ret = EIO;
        goto immediate;
    }
    talloc_steal(subreq, sdap_attrs);

    tevent_req_set_callback(subreq, sdap_nested_get_user_done, req);
    return req;

immediate:
    if (ret) {
        tevent_req_error(req, ret);
    } else {
        tevent_req_done(req);
    }
    tevent_req_post(req, ev);
    return req;
}

/* This should be a function pointer set from the IPA provider */
static errno_t
sdap_nested_get_ipa_user(TALLOC_CTX *mem_ctx, const char *user_dn,
                         struct sysdb_ctx *sysdb, struct sysdb_attrs ***_reply)
{
    errno_t ret;
    struct sysdb_attrs **reply = NULL;
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

    dn = ldb_dn_new(tmp_ctx, sysdb_ctx_get_ldb(sysdb), user_dn);
    if (dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (ldb_dn_get_comp_num(dn) < 4) {
        /* RDN, users, accounts, and at least one DC=
         * For example:
         * uid=admin,cn=users,cn=accounts,dc=example,dc=com */
        /* If it's fewer, it's not a user DN */
        ret = ENOENT;
        goto done;
    }

    /* If the RDN attribute name is 'uid' */
    rdn_name = ldb_dn_get_rdn_name(dn);
    if (rdn_name == NULL) {
        /* Shouldn't happen if ldb_dn_validate()
         * passed, but we'll be careful.
         */
        ret = EINVAL;
        goto done;
    }

    if (strcasecmp("uid", rdn_name) != 0) {
        /* RDN has the wrong attribute name.
         * It's not a service.
         */
        ret = ENOENT;
        goto done;
    }

    /* and the second component is "cn=users" */
    users_comp_name = ldb_dn_get_component_name(dn, 1);
    if (strcasecmp("cn", users_comp_name) != 0) {
        /* The second component name is not "cn" */
        ret = ENOENT;
        goto done;
    }

    users_comp_val = ldb_dn_get_component_val(dn, 1);
    if (strncasecmp("users",
                    (const char *) users_comp_val->data,
                    users_comp_val->length) != 0) {
        /* The second component value is not "users" */
        ret = ENOENT;
        goto done;
    }

    /* and the third component is "cn=accounts" */
    acct_comp_name = ldb_dn_get_component_name(dn, 2);
    if (strcasecmp("cn", acct_comp_name) != 0) {
        /* The third component name is not "cn" */
        ret = ENOENT;
        goto done;
    }

    acct_comp_val = ldb_dn_get_component_val(dn, 2);
    if (strncasecmp("accounts",
                    (const char *) acct_comp_val->data,
                    acct_comp_val->length) != 0) {
        /* The third component value is not "accounts" */
        ret = ENOENT;
        goto done;
    }

    /* Then the value of the RDN is the group name */
    reply = talloc_zero_array(tmp_ctx, struct sysdb_attrs *, 2);
    if (!reply) {
        ret = ENOMEM;
        goto done;
    }

    reply[0] = sysdb_new_attrs(reply);
    if (!reply[0]) {
        ret = ENOMEM;
        goto done;
    }
    user = reply[0];

    rdn_val = ldb_dn_get_rdn_val(dn);
    name = talloc_strndup(user, (const char *)rdn_val->data,
                          rdn_val->length);
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

    ret = EOK;
    *_reply = talloc_steal(mem_ctx, reply);
done:
    talloc_free(tmp_ctx);
    return ret;
}

static void
sdap_nested_get_user_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_nested_get_user_state *state = tevent_req_data(req,
                                           struct sdap_nested_get_user_state);

    ret = sdap_get_generic_recv(subreq, state, &state->count, &state->replies);
    talloc_zfree(subreq);
    if (ret != EOK && ret != ENOENT) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static errno_t
sdap_nested_get_user_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                          size_t *_count, struct sysdb_attrs ***_replies)
{
    struct sdap_nested_get_user_state *state = tevent_req_data(req,
                                            struct sdap_nested_get_user_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (_count) {
        *_count = state->count;
    }

    if (_replies) {
        *_replies = talloc_steal(mem_ctx, state->replies);
    }

    return EOK;
}

struct sdap_deref_ctx {
    const char *orig_dn;

    size_t expired_users_num;
    uint32_t expired_users_index;
    char **expired_users;

    size_t expired_groups_num;
    uint32_t expired_groups_index;
    char **expired_groups;

    size_t missing_dns_num;
    uint32_t missing_dns_index;
    char **missing_dns;

    struct sdap_deref_attrs **deref_result;
    size_t num_results;
    uint32_t result_index;

    int deref_threshold;
};

struct sdap_nested_group_ctx {
    struct tevent_context *ev;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;

    hash_table_t *users;
    hash_table_t *groups;

    struct sdap_options *opts;
    struct sdap_handle *sh;

    uint32_t nesting_level;

    struct ldb_message_element *members;
    uint32_t member_index;
    char *member_dn;

    bool enable_deref;
    struct sdap_deref_ctx *derefctx;

    /**
     * FIXME: Remove me!
     */
    bool send_finished;
};

static errno_t sdap_nested_group_process_deref_step(struct tevent_req *req);
static errno_t sdap_nested_group_process_step(struct tevent_req *req);

static struct tevent_req *sdap_nested_group_process_send(
        TALLOC_CTX *mem_ctx, struct tevent_context *ev,
        struct sss_domain_info *domain,
        struct sysdb_ctx *sysdb, struct sysdb_attrs *group,
        hash_table_t *users, hash_table_t *groups,
        struct sdap_options *opts, struct sdap_handle *sh,
        bool enable_deref, uint32_t nesting)
{
    errno_t ret;
    int hret;
    struct tevent_req *req;
    struct sdap_nested_group_ctx *state;
    const char *groupname;
    hash_key_t key;
    hash_value_t value;
    gid_t gid;

    req = tevent_req_create(mem_ctx, &state, struct sdap_nested_group_ctx);
    if (!req) {
        return NULL;
    }

    state->ev = ev;
    state->sysdb = sysdb;
    state->domain = domain;
    state->users = users;
    state->groups = groups;
    state->opts = opts;
    state->sh = sh;
    state->enable_deref = enable_deref;
    state->nesting_level = nesting;
    state->send_finished = false;

    /* If this is too many levels deep, just return success */
    if (nesting > dp_opt_get_int(opts->basic, SDAP_NESTING_LEVEL)) {
        ret = EOK;
        goto immediate;
    }

    /* Add the current group to the groups hash so we don't
     * look it up more than once
     */
    key.type = HASH_KEY_STRING;

    ret = sysdb_attrs_primary_name(sysdb, group,
                                   opts->group_map[SDAP_AT_GROUP_NAME].sys_name,
                                   &groupname);
    if (ret != EOK) {
        goto immediate;
    }

    key.str = talloc_strdup(state, groupname);
    if (!key.str) {
        ret = ENOMEM;
        goto immediate;
    }

    if (hash_has_key(groups, &key)) {
        /* This group has already been processed
         * (or is in progress)
         * Skip it and just return success
         */
        ret = EOK;
        goto immediate;
    }

    ret = sysdb_attrs_get_uint32_t(group,
                                   opts->group_map[SDAP_AT_GROUP_GID].sys_name,
                                   &gid);
    if (ret == ENOENT || (ret == EOK && gid == 0)) {
        DEBUG(9, ("The group's gid was %s\n", ret == ENOENT ? "missing" : "zero"));
        DEBUG(8, ("Marking group as non-posix and setting GID=0!\n"));

        if (ret == ENOENT) {
            ret = sysdb_attrs_add_uint32(group,
                                      opts->group_map[SDAP_AT_GROUP_GID].sys_name,
                                      0);
            if (ret != EOK) {
                DEBUG(1, ("Failed to add a GID to non-posix group!\n"));
                goto immediate;
            }
        }

        ret = sysdb_attrs_add_bool(group, SYSDB_POSIX, false);
        if (ret != EOK) {
            DEBUG(2, ("Error: Failed to mark group as non-posix!\n"));
            goto immediate;
        }
    } else if (ret) {
        goto immediate;
    }

    value.type = HASH_VALUE_PTR;
    value.ptr = talloc_steal(groups, group);

    hret = hash_enter(groups, &key, &value);
    if (hret != HASH_SUCCESS) {
        ret = EIO;
        goto immediate;
    }
    talloc_free(key.str);

    /* Process group memberships */

    /* TODO: future enhancement, check for memberuid as well
     * See https://fedorahosted.org/sssd/ticket/445
     */

    ret = sysdb_attrs_get_el(
            group,
            opts->group_map[SDAP_AT_GROUP_MEMBER].sys_name,
            &state->members);
    if (ret != EOK) {
        if (ret == ENOENT) {
            /* No members to process */
            ret = EOK;
        }
        goto immediate;
    }

    state->member_index = 0;

    if (enable_deref && sdap_has_deref_support(state->sh, state->opts)) {
        state->derefctx = talloc_zero(state, struct sdap_deref_ctx);
        if (!state->derefctx) {
            ret = ENOMEM;
            goto immediate;
        }

        ret = sysdb_attrs_get_string(group, SYSDB_ORIG_DN,
                                     &state->derefctx->orig_dn);
        if (ret != EOK) goto immediate;

        ret = sdap_nested_group_process_deref_step(req);
        if (ret != EAGAIN) goto immediate;
    } else {
        ret = sdap_nested_group_process_step(req);
        if (ret != EAGAIN) goto immediate;
    }

    state->send_finished = true;
    return req;

immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    state->send_finished = true;
    return req;
}

static errno_t sdap_nested_group_check_hash(struct sdap_nested_group_ctx *);
static errno_t sdap_nested_group_check_cache(TALLOC_CTX *mem_ctx,
                                    struct sysdb_ctx *sysdb,
                                    struct sss_domain_info *dom,
                                    struct sdap_options *opts,
                                    char *member_dn,
                                    struct ldb_message ***_msgs,
                                    enum sysdb_member_type *_mtype);

static void sdap_nested_group_process_ldap_user(struct tevent_req *subreq);
static void sdap_nested_group_process_user(struct tevent_req *subreq);
static errno_t sdap_nested_group_lookup_user(struct tevent_req *req,
                                             tevent_req_fn fn);
static errno_t sdap_nested_group_lookup_group(struct tevent_req *req);
static errno_t sdap_nested_group_process_deref_call(struct tevent_req *req);
static errno_t sdap_nested_group_process_noderef(struct tevent_req *req);

static errno_t sdap_nested_group_process_deref_step(struct tevent_req *req)
{
    errno_t ret;
    struct sdap_nested_group_ctx *state =
            tevent_req_data(req, struct sdap_nested_group_ctx);
    size_t missing = 0;
    struct ldb_message **msgs = NULL;
    enum sysdb_member_type mtype;
    struct sdap_deref_ctx *dctx = state->derefctx;

    dctx->deref_threshold = dp_opt_get_int(state->opts->basic,
                                           SDAP_DEREF_THRESHOLD);

    dctx->expired_users = talloc_array(dctx, char *,
                                       state->members->num_values + 1);
    dctx->expired_groups = talloc_array(dctx, char *,
                                       state->members->num_values + 1);
    dctx->missing_dns = talloc_array(dctx, char *,
                                     state->members->num_values + 1);
    if (!dctx->expired_users ||
        !dctx->expired_groups ||
        !dctx->missing_dns) return ENOMEM;

    while (true) {
        if (state->member_index >= state->members->num_values) {
            /* No more entries to check. Return success */
            talloc_zfree(state->member_dn);
            ret = EOK;
            break;
        }

        /* Continue to loop through until all entries have been
         * processed.
         */
        ret = sdap_nested_group_check_hash(state);
        if (ret == EOK) {
            talloc_zfree(state->member_dn);
            break; /* All remaining members in hash, check missing */
        } else if (ret != ENOENT) {
            goto done; /* Unexpected error */
        }

        ret = sdap_nested_group_check_cache(state, state->sysdb,
                                            state->domain,
                                            state->opts,
                                            state->member_dn,
                                            &msgs, &mtype);
        if (ret == EOK) {
            /* The entry is cached and valid */
            state->member_index++;
            talloc_zfree(state->member_dn);
            continue;
        } else if (ret == EAGAIN) {
            /* The entry is cached but needs refresh */
            switch(mtype) {
            case SYSDB_MEMBER_GROUP:
                DEBUG(8, ("Cached LDAP group [%s] needs refresh\n",
                           state->member_dn));

                missing++;

                dctx->expired_groups[dctx->expired_groups_num] =
                    talloc_move(dctx, &state->member_dn);
                dctx->expired_groups_num++;

                state->member_index++;
                continue;
            case SYSDB_MEMBER_USER:
                DEBUG(8, ("Cached LDAP user [%s] needs refresh\n",
                           state->member_dn));
                missing++;

                dctx->expired_users[dctx->expired_users_num] =
                    talloc_move(dctx, &state->member_dn);
                dctx->expired_users_num++;

                state->member_index++;
                continue;
            default:
                DEBUG(2, ("Unknown member value\n"));
                ret = EINVAL;
                goto done;
            }
        } else if (ret == ENOENT) {
            /* The entry is missing. It is unclear whether it
             * is a user or a group so we'll need to try looking
             * it up */
            missing++;

            dctx->missing_dns[dctx->missing_dns_num] =
                talloc_move(dctx, &state->member_dn);
            dctx->missing_dns_num++;

            state->member_index++;
            continue;
        }

        /* Unexpected error, skip this entry */
        state->member_index++;
        continue;
    } /* while (true) */


    dctx->expired_users[dctx->expired_users_num] = NULL;
    dctx->expired_groups[dctx->expired_groups_num] = NULL;
    dctx->missing_dns[dctx->missing_dns_num] = NULL;

    if (missing == 0) {
        ret = EOK;
        goto done;
    }

    if (missing > dctx->deref_threshold) {
        DEBUG(6, ("Missing data past threshold, doing a full deref\n"));
        ret = sdap_nested_group_process_deref_call(req);
    } else {
        DEBUG(6, ("Falling back to individual lookups\n"));
        ret = sdap_nested_group_process_noderef(req);
    }

    if (ret != EOK && ret != EAGAIN) goto done;
    return EAGAIN;

done:
    talloc_zfree(state->member_dn);
    return ret;
}


static errno_t sdap_nested_group_process_step(struct tevent_req *req)
{
    errno_t ret;
    struct sdap_nested_group_ctx *state =
            tevent_req_data(req, struct sdap_nested_group_ctx);
    struct ldb_message **msgs = NULL;
    enum sysdb_member_type mtype;

    while (true) {
        /* Continue to loop through until all entries have been
         * processed.
         */
        ret = sdap_nested_group_check_hash(state);
        if (ret == EOK) {
            talloc_zfree(state->member_dn);
            return EOK; /* All members in hash */
        } else if (ret != ENOENT) {
            goto error; /* Unexpected error */
        }

        ret = sdap_nested_group_check_cache(state, state->sysdb,
                                            state->domain,
                                            state->opts,
                                            state->member_dn,
                                            &msgs, &mtype);
        if (ret == EOK) {
            /* The entry is cached and valid */
            state->member_index++;
            talloc_zfree(state->member_dn);
            continue;
        } else if (ret == EAGAIN) {
            /* The entry is cached but needs refresh */
            switch(mtype) {
            case SYSDB_MEMBER_GROUP:
                DEBUG(6, ("Refreshing cached group from LDAP\n"));
                ret = sdap_nested_group_lookup_group(req);
                if (ret != EOK) goto error;
                break;
            case SYSDB_MEMBER_USER:
                DEBUG(6, ("Refreshing cached user from LDAP\n"));
                ret = sdap_nested_group_lookup_user(
                        req, sdap_nested_group_process_user);
                if (ret != EOK) goto error;
                break;
            default:
                DEBUG(2, ("Unknown member value\n"));
                ret = EINVAL;
                goto error;
            }

            return EAGAIN;
        } else if (ret == ENOENT) {
            /* It wasn't found in the cache either
             * We'll have to do a blind lookup in LDAP
             */

            /* Try users first */
            ret = sdap_nested_group_lookup_user(
                    req, sdap_nested_group_process_ldap_user);
            if (ret != EOK) {
                goto error;
            }
            return EAGAIN;
        }

        /* Unexpected error, skip this entry */
        state->member_index++;
        talloc_zfree(state->member_dn);
        continue;
    } /* while (true) */

error:
    talloc_zfree(state->member_dn);
    return ret;
}

static errno_t
sdap_nested_group_check_hash(struct sdap_nested_group_ctx *state)
{
    hash_key_t key;
    bool has_key = false;
    uint8_t *data;

    do {
        if (state->member_index >= state->members->num_values) {
            /* No more entries to check. Return success */
            return EOK;
        }

        data = state->members->values[state->member_index].data;
        state->member_dn = talloc_strdup(state, (const char *)data);
        if (!state->member_dn) {
            return ENOMEM;
        }

        /* Check the user hash
         * If it's there, we can save ourselves a trip to the
         * sysdb and possibly LDAP as well
         */
        key.type = HASH_KEY_STRING;
        key.str = state->member_dn;
        has_key = hash_has_key(state->users, &key);
        if (has_key) {
            talloc_zfree(state->member_dn);
            state->member_index++;
            continue;
        }
    } while (has_key);

    return ENOENT;
}

static errno_t
sdap_nested_group_check_cache(TALLOC_CTX *mem_ctx,
                              struct sysdb_ctx *sysdb,
                              struct sss_domain_info *dom,
                              struct sdap_options *opts,
                              char *dn,
                              struct ldb_message ***_msgs,
                              enum sysdb_member_type *_mtype)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    struct ldb_message **msgs = NULL;
    char *member_dn;
    uint64_t expiration;
    uid_t user_uid;
    time_t now = time(NULL);
    static const char *attrs[] = { SYSDB_CACHE_EXPIRE, SYSDB_UIDNUM,
                                   SYSDB_CREATE_TIME, SYSDB_NAME,
                                   NULL };
    char *filter;
    enum sysdb_member_type mtype;
    size_t count;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    ret = sss_filter_sanitize(tmp_ctx, dn, &member_dn);
    if (ret != EOK) {
        goto fail;
    }

    /* Check for the specified origDN in the sysdb */
    filter = talloc_asprintf(tmp_ctx, "(%s=%s)",
                             SYSDB_ORIG_DN,
                             member_dn);
    if (!filter) {
        ret = ENOMEM;
        goto fail;
    }

    /* Try users first */
    ret = sysdb_search_users(tmp_ctx, sysdb, filter, attrs, &count, &msgs);
    if (ret != EOK && ret != ENOENT) {
        ret = EIO;
        goto fail;
    } else if (ret == EOK && count > 0) {
        /* We found a user with this origDN in the sysdb. Check if it is valid
         */
        mtype = SYSDB_MEMBER_USER;

        /* Check whether the entry is valid */
        if (count != 1) {
            DEBUG(1, ("More than one entry with this origDN? Skipping\n"));
            ret = EIO;
            goto fail;
        }

        user_uid = ldb_msg_find_attr_as_uint64(msgs[0], SYSDB_UIDNUM, 0);
        if (!user_uid) {
            DEBUG(SSSDBG_OP_FAILURE, ("User with no UID? Skipping\n"));
            ret = EIO;
            goto fail;
        } else {
            /* Regular user, check if we need a refresh */
            expiration = ldb_msg_find_attr_as_uint64(msgs[0],
                                                    SYSDB_CACHE_EXPIRE,
                                                    0);
        }

        if (expiration && expiration > now) {
            DEBUG(6, ("Cached values are still valid. Skipping\n"));
            ret = EOK;
            goto done;
        }

        /* Refresh the user from LDAP */
        ret = EAGAIN;
        goto done;
    }

    /* It wasn't a user. Check whether it's a group */
    if (ret == EOK) talloc_zfree(msgs);

    ret = sysdb_search_groups(tmp_ctx, sysdb, filter, attrs, &count, &msgs);
    if (ret != EOK && ret != ENOENT) {
        ret = EIO;
        goto fail;
    } else if (ret == EOK && count > 0) {
        /* We found a group with this origDN in the sysdb */
        mtype = SYSDB_MEMBER_GROUP;

        /* Check whether the entry is valid */
        if (count != 1) {
            DEBUG(1, ("More than one entry with this origDN? Skipping\n"));
            ret = EIO;
            goto fail;
        }

        expiration = ldb_msg_find_attr_as_uint64(msgs[0],
                                                 SYSDB_CACHE_EXPIRE,
                                                 0);
        if (expiration && expiration > now) {
            DEBUG(6, ("Cached values are still valid.\n"));
            ret = EOK;
            goto done;
        }

        /* Refresh the group from LDAP */
        ret = EAGAIN;
        goto done;
    }

    /* It wasn't found in the groups either */
    ret = ENOENT;
done:
    if (ret == EOK || ret == EAGAIN) {
        *_msgs = talloc_steal(mem_ctx, msgs);
        *_mtype = mtype;
    }
    talloc_zfree(tmp_ctx);
    return ret;

fail:
    talloc_zfree(tmp_ctx);
    return ret;
}

static void sdap_nested_group_process_deref(struct tevent_req *subreq);

static errno_t
sdap_nested_group_process_deref_call(struct tevent_req *req)
{
    struct tevent_req *subreq;
    struct sdap_attr_map_info *maps;
    const char **sdap_attrs;
    int ret;
    int timeout;
    size_t attr_count;
    const int num_maps = 2;
    struct sdap_nested_group_ctx *state =
            tevent_req_data(req, struct sdap_nested_group_ctx);

    maps = talloc_array(state, struct sdap_attr_map_info, num_maps+1);
    if (!maps) return ENOMEM;

    maps[0].map = state->opts->user_map;
    maps[0].num_attrs = SDAP_OPTS_USER;
    maps[1].map = state->opts->group_map;
    maps[1].num_attrs = SDAP_OPTS_GROUP;
    maps[2].map = NULL;

    /* Pull down the whole group map, but only pull down username
     * and originalDN for users. */
    ret = build_attrs_from_map(state, state->opts->group_map, SDAP_OPTS_GROUP,
                               NULL, &sdap_attrs, &attr_count);
    if (ret != EOK) goto fail;

    sdap_attrs = talloc_realloc(NULL, sdap_attrs, const char *,
                                attr_count + 2);
    if (!sdap_attrs) {
        ret = ENOMEM;
        goto fail;
    }

    sdap_attrs[attr_count] = \
                        state->opts->user_map[SDAP_AT_USER_NAME].name;
    sdap_attrs[attr_count + 1] = NULL;

    timeout = dp_opt_get_int(state->opts->basic, SDAP_SEARCH_TIMEOUT);

    subreq = sdap_deref_search_send(state, state->ev, state->opts,
                    state->sh, state->derefctx->orig_dn,
                    state->opts->group_map[SDAP_AT_GROUP_MEMBER].name,
                    sdap_attrs, num_maps, maps, timeout);
    if (!subreq) {
        ret = EIO;
        goto fail;
    }
    talloc_steal(subreq, sdap_attrs);
    talloc_steal(subreq, maps);

    tevent_req_set_callback(subreq, sdap_nested_group_process_deref, req);
    return EOK;

fail:
    talloc_free(sdap_attrs);
    talloc_free(maps);
    return ret;
}

static errno_t sdap_nested_group_process_noderef(struct tevent_req *req)
{
    struct sdap_nested_group_ctx *state =
            tevent_req_data(req, struct sdap_nested_group_ctx);
    struct sdap_deref_ctx *dctx = state->derefctx;
    errno_t ret;

    if (dctx->expired_users_index < dctx->expired_users_num) {
        state->member_dn = dctx->expired_users[dctx->expired_users_index];
        DEBUG(8, ("Refreshing expired user [%s]\n", state->member_dn));

        ret = sdap_nested_group_lookup_user(
                req, sdap_nested_group_process_user);
        if (ret != EOK) goto done;
        return EAGAIN;
    }

    if (dctx->expired_groups_index < dctx->expired_groups_num) {
        state->member_dn = dctx->expired_groups[dctx->expired_groups_index];
        DEBUG(8, ("Refreshing expired group [%s]\n", state->member_dn));

        ret = sdap_nested_group_lookup_group(req);
        if (ret != EOK) goto done;
        return EAGAIN;
    }

    if (dctx->missing_dns_index < dctx->missing_dns_num) {
        state->member_dn = dctx->missing_dns[dctx->missing_dns_index];
        DEBUG(8, ("Looking up missing DN [%s]\n", state->member_dn));

        /* Try users first for generic missing DNs */
        ret = sdap_nested_group_lookup_user(
                req, sdap_nested_group_process_ldap_user);
        if (ret != EOK) goto done;
        return EAGAIN;
    }

    ret = EOK;
done:
    return ret;
}

static errno_t sdap_nested_group_lookup_user(struct tevent_req *req,
                                             tevent_req_fn fn)
{
    char *search_bases_filter = NULL;
    struct tevent_req *subreq;
    struct sdap_nested_group_ctx *state =
            tevent_req_data(req, struct sdap_nested_group_ctx);
    errno_t ret;

    /*
     * If dn is not in user search base and object may be group
     * continue with group lookup. If it can't be group, skip it.
     */
    if (!sss_ldap_dn_in_search_bases(state, state->member_dn,
                                     state->opts->user_search_bases,
                                     &search_bases_filter)) {
        if (fn == sdap_nested_group_process_ldap_user) {
            return sdap_nested_group_lookup_group(req);
        } else if (fn == sdap_nested_group_process_user) {
            if (state->derefctx) {
                state->derefctx->expired_users_index++;
                ret = sdap_nested_group_process_noderef(req);
            } else {
                state->member_index++;
                talloc_zfree(state->member_dn);
                ret = sdap_nested_group_process_step(req);
            }

            if (ret != EOK && ret != EAGAIN) {
                DEBUG(SSSDBG_OP_FAILURE, ("Nested group processing failed\n"));
                return ret;
            } else if (ret == EOK) {
                DEBUG(SSSDBG_TRACE_FUNC, ("All done.\n"));
                tevent_req_done(req);

                /**
                 * FIXME: Rewrite nested group processing so we call
                 *        tevent_req_post() only in _send().
                 */
                if (state->send_finished == false) {
                    tevent_req_post(req, state->ev);
                }
            }
            return EOK;
        }
        /*
         * Something else? Continue.
         */
    }

    subreq = sdap_nested_get_user_send(state, state->ev, state->domain,
                                       state->sysdb, state->opts, state->sh,
                                       state->member_dn, search_bases_filter);
    if (!subreq) {
        return EIO;
    }
    talloc_steal(subreq, search_bases_filter);
    tevent_req_set_callback(subreq, fn, req);
    return EOK;
}

static void sdap_nested_group_process_group(struct tevent_req *subreq);
static errno_t sdap_nested_group_lookup_group(struct tevent_req *req)
{
    errno_t ret;
    const char **sdap_attrs;
    char *filter;
    char *search_bases_filter = NULL;
    struct tevent_req *subreq;
    struct sdap_nested_group_ctx *state =
            tevent_req_data(req, struct sdap_nested_group_ctx);

    /*
     * If dn is not in group search base, skip it.
     */
    if (!sss_ldap_dn_in_search_bases(state, state->member_dn,
                                     state->opts->group_search_bases,
                                     &search_bases_filter)) {
        if (state->derefctx) {
            if (state->derefctx->expired_groups_index <
                state->derefctx->expired_groups_num) {
                state->derefctx->expired_groups_index++;
            } else {
                state->derefctx->missing_dns_index++;
            }
            ret = sdap_nested_group_process_noderef(req);
        } else {
            state->member_index++;
            talloc_zfree(state->member_dn);
            ret = sdap_nested_group_process_step(req);
        }

        if (ret != EOK && ret != EAGAIN) {
            DEBUG(SSSDBG_OP_FAILURE, ("Nested group processing failed\n"));
            return ret;
        } else if (ret == EOK) {
            DEBUG(SSSDBG_TRACE_FUNC, ("All done.\n"));
            tevent_req_done(req);

            /**
             * FIXME: Rewrite nested group processing so we call
             *        tevent_req_post() only in _send().
             */
            if (state->send_finished == false) {
                tevent_req_post(req, state->ev);
            }
        }
        return EOK;
    }

    ret = build_attrs_from_map(state, state->opts->group_map, SDAP_OPTS_GROUP,
                               NULL, &sdap_attrs, NULL);
    if (ret != EOK) {
        return ret;
    }

    if (search_bases_filter != NULL) {
        filter = talloc_asprintf(sdap_attrs, "(&%s(objectclass=%s)(%s=*))",
                                 search_bases_filter,
                                 state->opts->group_map[SDAP_OC_GROUP].name,
                                 state->opts->group_map[SDAP_AT_GROUP_NAME].name);
    } else {
        filter = talloc_asprintf(sdap_attrs, "(&(objectclass=%s)(%s=*))",
                                 state->opts->group_map[SDAP_OC_GROUP].name,
                                 state->opts->group_map[SDAP_AT_GROUP_NAME].name);
    }
    if (!filter) {
        talloc_free(sdap_attrs);
        return ENOMEM;
    }

    subreq = sdap_get_generic_send(state, state->ev, state->opts,
                                   state->sh, state->member_dn,
                                   LDAP_SCOPE_BASE,
                                   filter, sdap_attrs,
                                   state->opts->group_map,
                                   SDAP_OPTS_GROUP,
                                   dp_opt_get_int(state->opts->basic,
                                                  SDAP_SEARCH_TIMEOUT),
                                   false);
    if (!subreq) {
        talloc_free(sdap_attrs);
        return EIO;
    }
    talloc_steal(subreq, sdap_attrs);

    tevent_req_set_callback(subreq, sdap_nested_group_process_group, req);
    return EOK;
}

static void sdap_nested_group_process_user(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_nested_group_ctx *state =
            tevent_req_data(req, struct sdap_nested_group_ctx);
    TALLOC_CTX *tmp_ctx;
    size_t count;
    struct sysdb_attrs **replies;
    int hret;
    hash_key_t key;
    hash_value_t value;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    ret = sdap_nested_get_user_recv(subreq, tmp_ctx, &count, &replies);
    talloc_zfree(subreq);
    if (ret != EOK && ret != ENOENT) {
        tevent_req_error(req, ret);
        goto done;
    } else if (ret == ENOENT || count == 0) {
        /* Nothing to do if the user doesn't exist */
        goto skip;
    }

    if (count != 1) {
        /* There should only ever be one reply for a
         * BASE search. If otherwise, it's a serious
         * error.
         */
        DEBUG(1,("Received multiple replies for a BASE search!\n"));
        tevent_req_error(req, EIO);
        goto done;
    }

    /* Save the user attributes to the user hash so we can store
     * them all at once later.
     */

    key.type = HASH_KEY_STRING;
    key.str = state->member_dn;

    value.type = HASH_VALUE_PTR;
    value.ptr = replies[0];

    hret = hash_enter(state->users, &key, &value);
    if (hret != HASH_SUCCESS) {
        tevent_req_error(req, EIO);
        goto done;
    }
    talloc_steal(state->users, replies[0]);

skip:
    if (state->derefctx) {
        state->derefctx->expired_users_index++;
        ret = sdap_nested_group_process_noderef(req);
    } else {
        state->member_index++;
        talloc_zfree(state->member_dn);
        ret = sdap_nested_group_process_step(req);
    }

    if (ret == EOK) {
        /* EOK means it's complete */
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }

    /* EAGAIN means that we should re-enter
     * the mainloop
     */

done:
    talloc_free(tmp_ctx);
}

static void sdap_group_internal_nesting_done(struct tevent_req *subreq);
static void sdap_nested_group_process_group(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_nested_group_ctx *state =
            tevent_req_data(req, struct sdap_nested_group_ctx);
    TALLOC_CTX *tmp_ctx;
    size_t count;
    struct sysdb_attrs **replies;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    ret = sdap_get_generic_recv(subreq, tmp_ctx, &count, &replies);
    talloc_zfree(subreq);
    if (ret != EOK && ret != ENOENT) {
        tevent_req_error(req, ret);
        goto done;
    } else if (ret == ENOENT || count == 0) {
        /* Nothing to do if the group doesn't exist */
        goto skip;
    }

    if (count != 1) {
        /* There should only ever be one reply for a
         * BASE search. If otherwise, it's a serious
         * error.
         */
        DEBUG(1,("Received multiple replies for a BASE search!\n"));
        tevent_req_error(req, EIO);
        goto done;
    }

    /* Recurse down into the member group */
    subreq = sdap_nested_group_process_send(state, state->ev, state->domain,
                                            state->sysdb, replies[0],
                                            state->users, state->groups,
                                            state->opts, state->sh,
                                            state->enable_deref,
                                            state->nesting_level + 1);
    if (!subreq) {
        tevent_req_error(req, EIO);
        goto done;
    }
    tevent_req_set_callback(subreq, sdap_group_internal_nesting_done, req);

    talloc_free(tmp_ctx);
    return;

skip:
    if (state->derefctx) {
        if (state->derefctx->expired_groups_index <
            state->derefctx->expired_groups_num) {
            state->derefctx->expired_groups_index++;
        } else {
            state->derefctx->missing_dns_index++;
        }
        ret = sdap_nested_group_process_noderef(req);
    } else {
        state->member_index++;
        talloc_zfree(state->member_dn);
        ret = sdap_nested_group_process_step(req);
    }

    if (ret == EOK) {
        /* EOK means it's complete */
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }

    /* EAGAIN means that we should re-enter
     * the mainloop
     */

done:
    talloc_free(tmp_ctx);
}

static void sdap_group_internal_nesting_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_nested_group_ctx *state =
            tevent_req_data(req, struct sdap_nested_group_ctx);

    ret = sdap_nested_group_process_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    if (state->derefctx) {
        if (state->derefctx->expired_groups_index <
            state->derefctx->expired_groups_num) {
            state->derefctx->expired_groups_index++;
        } else {
            state->derefctx->missing_dns_index++;
        }

        state->derefctx->expired_users_index++;
        ret = sdap_nested_group_process_noderef(req);
    } else {
        state->member_index++;
        talloc_zfree(state->member_dn);
        ret = sdap_nested_group_process_step(req);
    }

    if (ret == EOK) {
        /* EOK means it's complete */
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }

    /* EAGAIN means that we should re-enter
     * the mainloop
     */
}

static void sdap_nested_group_process_ldap_user(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_nested_group_ctx *state =
            tevent_req_data(req, struct sdap_nested_group_ctx);
    TALLOC_CTX *tmp_ctx;
    size_t count;
    struct sysdb_attrs **replies;
    int hret;
    hash_key_t key;
    hash_value_t value;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    ret = sdap_nested_get_user_recv(subreq, tmp_ctx, &count, &replies);
    talloc_zfree(subreq);
    if (ret != EOK && ret != ENOENT) {
        tevent_req_error(req, ret);
        goto done;
    } else if (ret == ENOENT || count == 0) {
        /* No user found. Assume it's a group */
        ret = sdap_nested_group_lookup_group(req);
        if (ret != EOK) {
            tevent_req_error(req, ret);
        }
        goto done;
    }

    if (count != 1) {
        /* There should only ever be one reply for a
         * BASE search. If otherwise, it's a serious
         * error.
         */
        DEBUG(1,("Received multiple replies for a BASE search!\n"));
        tevent_req_error(req, EIO);
        goto done;
    }

    /* Save the user attributes to the user hash so we can store
     * them all at once later.
     */
    key.type = HASH_KEY_STRING;
    key.str = state->member_dn;

    value.type = HASH_VALUE_PTR;
    value.ptr = replies[0];

    hret = hash_enter(state->users, &key, &value);
    if (hret != HASH_SUCCESS) {
        tevent_req_error(req, EIO);
        goto done;
    }
    talloc_steal(state->users, replies[0]);

    /* Move on to the next member */
    if (state->derefctx) {
        state->derefctx->missing_dns_index++;
        ret = sdap_nested_group_process_noderef(req);
    } else {
        state->member_index++;
        talloc_zfree(state->member_dn);
        ret = sdap_nested_group_process_step(req);
    }

    if (ret == EOK) {
        /* EOK means it's complete */
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }

    /* EAGAIN means that we should re-enter
     * the mainloop
     */

done:
    talloc_free(tmp_ctx);
}

static errno_t
sdap_nested_group_process_deref_result(struct tevent_req *req);

static void sdap_nested_group_process_deref(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_nested_group_ctx *state =
            tevent_req_data(req, struct sdap_nested_group_ctx);

    ret = sdap_deref_search_recv(subreq, state->derefctx,
                                 &state->derefctx->num_results,
                                 &state->derefctx->deref_result);
    talloc_zfree(subreq);
    if (ret != EOK && ret != ENOENT) {
        tevent_req_error(req, ret);
        return;
    } else if (ret == ENOENT || state->derefctx->deref_result == NULL) {
        /* Nothing could be dereferenced. Done. */
        tevent_req_done(req);
        return;
    }

    state->derefctx->result_index = 0;

    DEBUG(8, ("Received %d dereference results, about to process them\n",
              state->derefctx->num_results));
    ret = sdap_nested_group_process_deref_result(req);
    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }

    /* EAGAIN means a recursive search is in progress */
}

static void
sdap_nested_group_process_deref_recurse_done(struct tevent_req *subreq);

static errno_t
sdap_nested_group_process_deref_result(struct tevent_req *req)
{
    struct sdap_nested_group_ctx *state =
            tevent_req_data(req, struct sdap_nested_group_ctx);
    struct tevent_req *subreq;
    hash_key_t key;
    hash_value_t value;
    int hret;
    const char *orig_dn;
    errno_t ret;
    struct sdap_deref_ctx *dctx = state->derefctx;
    const char *tmp_name;
    size_t i;

    while (dctx->result_index < dctx->num_results) {
        /* Add to appropriate hash table */
        ret = sysdb_attrs_get_string(
                dctx->deref_result[dctx->result_index]->attrs,
                SYSDB_ORIG_DN, &orig_dn);
        if (ret != EOK) {
            DEBUG(2, ("The entry has no originalDN\n"));
            return ret;
        }

        /* Ensure that all members returned from the deref request are included
         * in the member processing. Sometimes we will get more results back from
         * deref/asq than we got from the initial lookup, as is the case with
         * Active Directory and its range retrieval mechanism.
         */
        for (i = 0; i < state->members->num_values; i++) {
            /* FIXME: This is inefficient for very large sets of groups */
            if (strcasecmp((const char *)state->members->values[i].data,
                           orig_dn) == 0) break;
        }
        if (i >= state->members->num_values) {
            state->members->values = talloc_realloc(state,
                                                    state->members->values,
                                                    struct ldb_val,
                                                    state->members->num_values + 1);
            if (!state->members->values) {
                return ENOMEM;
            }
            state->members->values[state->members->num_values].data =
                    (uint8_t *)talloc_strdup(state->members->values, orig_dn);
            if (!state->members->values[state->members->num_values].data) {
                return ENOMEM;
            }
            state->members->values[state->members->num_values].length = strlen(orig_dn);
            state->members->num_values++;
        }

        if (dctx->deref_result[dctx->result_index]->map == \
            state->opts->user_map) {

            /* check if the user is in search base */
            if (!sss_ldap_dn_in_search_bases(state, orig_dn,
                                             state->opts->user_search_bases,
                                             NULL)) {
                dctx->result_index++;
                continue;
            }

            DEBUG(9, ("Found member user [%s]\n", orig_dn));

            key.type = HASH_KEY_STRING;
            key.str = talloc_strdup(state, orig_dn);

            value.type = HASH_VALUE_PTR;
            value.ptr = dctx->deref_result[dctx->result_index]->attrs;

            hret = hash_enter(state->users, &key, &value);
            if (hret != HASH_SUCCESS) return EIO;

            talloc_steal(state->users,
                         dctx->deref_result[dctx->result_index]->attrs);
            dctx->result_index++;
        } else if (dctx->deref_result[dctx->result_index]->map == \
                   state->opts->group_map) {
            ret = sysdb_attrs_get_string(dctx->deref_result[dctx->result_index]->attrs,
                                       state->opts->group_map[SDAP_AT_GROUP_NAME].sys_name,
                                       &tmp_name);
            if (ret == ENOENT) {
                DEBUG(7, ("Dereferenced a group without name, skipping ...\n"));
            } else if (ret) {
                return EIO;
            }

            /* check if the group is in search base */
            if (!sss_ldap_dn_in_search_bases(state, orig_dn,
                                             state->opts->group_search_bases,
                                             NULL)) {
                dctx->result_index++;
                continue;
            }

            DEBUG(6, ("Recursing down a nested group\n"));
            subreq = sdap_nested_group_process_send(state, state->ev,
                                state->domain, state->sysdb,
                                dctx->deref_result[dctx->result_index]->attrs,
                                state->users, state->groups,
                                state->opts, state->sh,
                                state->enable_deref,
                                state->nesting_level + 1);
            if (!subreq) return EIO;

            tevent_req_set_callback(subreq,
                    sdap_nested_group_process_deref_recurse_done,
                    req);
            return EAGAIN;
        } else {
            /* This should never happen, but if it does,
             * do not loop forever */
            DEBUG(2, ("Entry does not match any known map, skipping\n"));
            dctx->result_index++;
            continue;
        }
    }

    /* All deref results processed */
    DEBUG(8, ("All dereference results processed\n"));
    return EOK;
}

static void
sdap_nested_group_process_deref_recurse_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct sdap_nested_group_ctx *state =
            tevent_req_data(req, struct sdap_nested_group_ctx);

    ret = sdap_nested_group_process_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    state->derefctx->result_index++;

    ret = sdap_nested_group_process_deref_result(req);
    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }

    /* EAGAIN means a recursive search is in progress */
}

static errno_t sdap_nested_group_process_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}
