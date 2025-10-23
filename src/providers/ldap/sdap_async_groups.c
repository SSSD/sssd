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
#include "util/probes.h"
#include "db/sysdb.h"
#include "providers/ldap/sdap_async_private.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_idmap.h"

/* ==Group-Parsing Routines=============================================== */

static int sdap_find_entry_by_origDN(TALLOC_CTX *memctx,
                                     struct sysdb_ctx *ctx,
                                     struct sss_domain_info *domain,
                                     const char *orig_dn,
                                     char **_localdn,
                                     bool *_is_group)
{
    TALLOC_CTX *tmpctx;
    const char *attrs[] = {SYSDB_OBJECTCLASS, SYSDB_OBJECTCATEGORY, NULL};
    struct ldb_dn *base_dn;
    char *filter;
    struct ldb_message **msgs;
    size_t num_msgs;
    int ret;
    char *sanitized_dn;
    const char *objectclass;

    tmpctx = talloc_new(NULL);
    if (!tmpctx) {
        return ENOMEM;
    }

    ret = sss_filter_sanitize_dn(tmpctx, orig_dn, &sanitized_dn);
    if (ret != EOK) {
        ret = ENOMEM;
        goto done;
    }

    filter = talloc_asprintf(tmpctx, "%s=%s", SYSDB_ORIG_DN, sanitized_dn);
    if (!filter) {
        ret = ENOMEM;
        goto done;
    }

    base_dn = sysdb_domain_dn(tmpctx, domain);
    if (!base_dn) {
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_ALL, "Searching cache for [%s].\n", sanitized_dn);
    ret = sysdb_search_entry(tmpctx, ctx,
                             base_dn, LDB_SCOPE_SUBTREE, filter, attrs,
                             &num_msgs, &msgs);
    if (ret) {
        goto done;
    }
    if (num_msgs != 1) {
        ret = ENOENT;
        goto done;
    }

    *_localdn = talloc_strdup(memctx, ldb_dn_get_linearized(msgs[0]->dn));
    if (!*_localdn) {
        ret = ENOENT;
        goto done;
    }

    if (_is_group != NULL) {
        objectclass = ldb_msg_find_attr_as_string(msgs[0], SYSDB_OBJECTCATEGORY,
                                                  NULL);
        if (objectclass == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "An entry without a %s?\n",
                  SYSDB_OBJECTCATEGORY);
            ret = EINVAL;
            goto done;
        }

        *_is_group = strcmp(SYSDB_GROUP_CLASS, objectclass) == 0;
    }

    ret = EOK;

done:
    talloc_zfree(tmpctx);
    return ret;
}

static errno_t
sdap_get_members_with_primary_gid(TALLOC_CTX *mem_ctx,
                                  struct sss_domain_info *domain,
                                  gid_t gid, char ***_localdn, size_t *_ndn)
{
    static const char *search_attrs[] = { SYSDB_NAME, NULL };
    char *filter;
    struct ldb_message **msgs;
    size_t count;
    size_t i;
    errno_t ret;
    char **localdn;

    /* Don't search if the group is non-POSIX */
    if (!gid) return EOK;

    filter = talloc_asprintf(mem_ctx, "(%s=%llu)", SYSDB_GIDNUM,
                             (unsigned long long) gid);
    if (!filter) {
        return ENOMEM;
    }

    ret = sysdb_search_users(mem_ctx, domain, filter,
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
                       struct sss_domain_info *domain,
                       struct sdap_options *opts,
                       char ***_dn_list, size_t *_count)
{
    gid_t gid;
    errno_t ret;

    ret = sysdb_attrs_get_uint32_t(ldap_attrs,
                                   opts->group_map[SDAP_AT_GROUP_GID].sys_name,
                                   &gid);
    if (ret == ENOENT) {
        /* Non-POSIX AD group. Skip. */
        *_dn_list = NULL;
        *_count = 0;
        return EOK;
    } else if (ret && ret != ENOENT) {
        return ret;
    }

    ret = sdap_get_members_with_primary_gid(mem_ctx, domain, gid,
                                            _dn_list, _count);
    if (ret) return ret;

    return EOK;
}

static bool has_member(struct ldb_message_element *member_el,
                       char *member)
{
    struct ldb_val val;

    val.data = (uint8_t *) member;
    val.length = strlen(member);

    /* This is bad complexity, but this loop should only be invoked in
     * the very rare scenario of AD POSIX group that is primary group of
     * some users but has user member attributes at the same time
     */
    if (ldb_msg_find_val(member_el, &val) != NULL) {
        return true;
    }

    return false;
}

static void link_pgroup_members(struct sysdb_attrs *group_attrs,
                                struct ldb_message_element *member_el,
                                char **userdns,
                                size_t nuserdns)
{
    int i, j;

    j = 0;
    for (i=0; i < nuserdns; i++) {
        if (has_member(member_el, userdns[i])) {
            DEBUG(SSSDBG_TRACE_INTERNAL,
                  "Member %s already included, skipping\n", userdns[i]);
            continue;
        }

        member_el->values[member_el->num_values + j].data = (uint8_t *) \
                                         talloc_steal(group_attrs, userdns[i]);
        member_el->values[member_el->num_values + j].length = \
                                         strlen(userdns[i]);
        j++;
    }
    member_el->num_values += j;
}

static int sdap_fill_memberships(struct sdap_options *opts,
                                 struct sysdb_attrs *group_attrs,
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
    struct sdap_domain *sdom;
    struct sysdb_ctx *member_sysdb;
    struct sss_domain_info *member_dom;

    ret = sysdb_attrs_get_el(group_attrs, SYSDB_MEMBER, &el);
    if (ret) {
        DEBUG(SSSDBG_MINOR_FAILURE, "sysdb_attrs_get_el failed\n");
        goto done;
    }

    /* Just allocate both big enough to contain all members for now */
    el->values = talloc_realloc(group_attrs, el->values, struct ldb_val,
                                el->num_values + num_values + nuserdns);
    if (!el->values) {
        DEBUG(SSSDBG_MINOR_FAILURE, "No memory to allocate group attrs\n");
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
            sdom = sdap_domain_get_by_dn(opts, (char *)values[i].data);
            if (sdom == NULL) {
                DEBUG(SSSDBG_MINOR_FAILURE, "Member [%s] is it out of domain "
                      "scope?\n", (char *)values[i].data);
                member_sysdb = ctx;
                member_dom = domain;
            } else {
                member_sysdb = sdom->dom->sysdb;
                member_dom = sdom->dom;
            }

            /* sync search entry with this as origDN */
            ret = sdap_find_entry_by_origDN(el->values, member_sysdb,
                                            member_dom, (char *)values[i].data,
                                            (char **)&el->values[j].data,
                                            NULL);
            if (ret == ENOENT) {
                /* member may be outside of the configured search bases
                 * or out of scope of nesting limit */
                DEBUG(SSSDBG_MINOR_FAILURE, "Member [%s] was not found in "
                      "cache. Is it out of scope?\n", (char *)values[i].data);
                continue;
            }
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "'sdap_find_entry_by_origDN' failed for member [%s].\n",
                      (char *)values[i].data);
                goto done;
            }

            DEBUG(SSSDBG_TRACE_LIBS, "    member #%d (%s): [%s]\n",
                      i, (char *)values[i].data,
                      (char *)el->values[j].data);

            el->values[j].length = strlen((char *)el->values[j].data);
            j++;
        } else if (hret != HASH_SUCCESS) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "hash_lookup failed: [%d]: %s\n", hret, strerror(hret));
            ret = EFAULT;
            goto done;
        }

        /* If the member is in ghost table, it has
         * already been processed - just skip it */
    }
    el->num_values = j;

    link_pgroup_members(group_attrs, el, userdns, nuserdns);
    ret = EOK;

done:
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
              "Error reading ghost attributes: [%s]\n",
               strerror(ret));
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
                "Error reading members: [%s]\n", strerror(ret));
        return ret;
    }

    if (store_original_member) {
        DEBUG(SSSDBG_TRACE_FUNC, "The group has %d members\n", memberel->num_values);
        for (i = 0; i < memberel->num_values; i++) {
            ret = sysdb_attrs_add_string(sysdb_attrs, SYSDB_ORIG_MEMBER,
                                        (const char *) memberel->values[i].data);
            if (ret) {
                DEBUG(SSSDBG_OP_FAILURE, "Could not add member [%s]\n",
                      (const char *) memberel->values[i].data);
                return ret;
            }
        }
    }

    if (populate_members) {
        ret = sysdb_attrs_get_el(sysdb_attrs, SYSDB_MEMBER, &sysdb_memberel);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Error reading group members from group_attrs: [%s]\n",
                   strerror(ret));
            return ret;
        }
        sysdb_memberel->values = memberel->values;
        sysdb_memberel->num_values = memberel->num_values;
    }

    ret = sysdb_attrs_get_el(sysdb_attrs, SYSDB_GHOST, &ghostel);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Error getting ghost element: [%s]\n", strerror(ret));
        return ret;
    }
    ghostel->values = gh->values;
    ghostel->num_values = gh->num_values;

    cnt = ghostel->num_values + memberel->num_values;
    DEBUG(SSSDBG_TRACE_FUNC, "Group has %zu members\n", cnt);

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
                      "Error checking hash table: [%s]\n",
                       hash_error_string(hret));
                return EFAULT;
            }

            DEBUG(SSSDBG_TRACE_FUNC,
                  "Adding ghost member for group [%s]\n", (char *) value.ptr);
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
    const char *group_name = NULL;
    gid_t gid = 0;
    errno_t ret;
    char *usn_value = NULL;
    TALLOC_CTX *tmpctx = NULL;
    bool posix_group;
    bool use_id_mapping;
    bool need_filter;
    char *sid_str;
    struct sss_domain_info *subdomain;

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

    /* Always store SID string if available */
    ret = sdap_attrs_get_sid_str(tmpctx, opts->idmap_ctx, attrs,
                              opts->group_map[SDAP_AT_GROUP_OBJECTSID].sys_name,
                              &sid_str);
    if (ret == EOK) {
        ret = sysdb_attrs_add_string(group_attrs, SYSDB_SID_STR, sid_str);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Could not add SID string: [%s]\n",
                                         sss_strerror(ret));
            goto done;
        }
    } else if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_ALL, "objectSID: not available for group [%s].\n",
                                 group_name);
        sid_str = NULL;
    } else {
        DEBUG(SSSDBG_MINOR_FAILURE, "Could not identify objectSID: [%s]\n",
                                     sss_strerror(ret));
        sid_str = NULL;
    }

    /* Always store UUID if available */
    ret = sysdb_handle_original_uuid(
                                   opts->group_map[SDAP_AT_GROUP_UUID].def_name,
                                   attrs,
                                   opts->group_map[SDAP_AT_GROUP_UUID].sys_name,
                                   group_attrs, SYSDB_UUID);
    if (ret != EOK) {
        DEBUG((ret == ENOENT) ? SSSDBG_TRACE_ALL : SSSDBG_MINOR_FAILURE,
              "Failed to retrieve UUID [%d][%s].\n", ret, sss_strerror(ret));
    }

    /* If this object has a SID available, we will determine the correct
     * domain by its SID. */
    if (sid_str != NULL) {
        subdomain = sss_get_domain_by_sid_ldap_fallback(get_domains_head(dom),
                                                        sid_str);
        if (subdomain) {
            dom = subdomain;
        } else {
            DEBUG(SSSDBG_TRACE_FUNC, "SID %s does not belong to any known "
                                      "domain\n", sid_str);
        }
    }

    ret = sdap_get_group_primary_name(tmpctx, opts, attrs, dom, &group_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to get group name\n");
        goto done;
    }
    DEBUG(SSSDBG_TRACE_FUNC, "Processing group %s\n", group_name);

    posix_group = true;
    ret = sdap_check_ad_group_type(dom, opts, attrs, group_name,
                                   &need_filter);
    if (ret != EOK) {
        goto done;
    }
    if (need_filter) {
        posix_group = false;

        ret = sysdb_attrs_add_bool(group_attrs, SYSDB_POSIX, false);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Error: Failed to mark group as non-POSIX!\n");
            goto done;
        }
    }

    if (posix_group) {
        use_id_mapping = sdap_idmap_domain_has_algorithmic_mapping(opts->idmap_ctx,
                                                                   dom->name,
                                                                   sid_str);
        if (use_id_mapping) {
            posix_group = true;

            if (sid_str == NULL) {
                DEBUG(SSSDBG_MINOR_FAILURE, "SID not available, cannot map a " \
                                             "unix ID to group [%s].\n", group_name);
                ret = ENOENT;
                goto done;
            }

            DEBUG(SSSDBG_TRACE_LIBS,
                  "Mapping group [%s] objectSID [%s] to unix ID\n",
                   group_name, sid_str);

            /* Convert the SID into a UNIX group ID */
            ret = sdap_idmap_sid_to_unix(opts->idmap_ctx, sid_str, &gid);
            if (ret == ENOTSUP) {
                /* ENOTSUP is returned if built-in SID was provided
                 * => do not store the group, but return EOK */
                DEBUG(SSSDBG_TRACE_FUNC, "Skipping built-in object.\n");
                ret = EOK;
                goto done;
            } else if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Could not convert SID string: [%s]\n",
                       sss_strerror(ret));
                goto done;
            }

            /* Store the GID in the ldap_attrs so it doesn't get
             * treated as a missing attribute from LDAP and removed.
             */
            ret = sdap_replace_id(attrs, SYSDB_GIDNUM, gid);
            if (ret) {
                DEBUG(SSSDBG_OP_FAILURE, "Cannot set the id-mapped GID\n");
                goto done;
            }
        } else {
            ret = sysdb_attrs_get_bool(attrs, SYSDB_POSIX, &posix_group);
            if (ret == ENOENT) {
                posix_group = true;
            } else if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Error reading posix attribute: [%s]\n",
                       sss_strerror(ret));
                goto done;
            }

            DEBUG(SSSDBG_TRACE_INTERNAL,
                  "This is%s a posix group\n", (posix_group)?"":" not");
            ret = sysdb_attrs_add_bool(group_attrs, SYSDB_POSIX, posix_group);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Error setting posix attribute: [%s]\n",
                       sss_strerror(ret));
                goto done;
            }

            ret = sysdb_attrs_get_uint32_t(attrs,
                                           opts->group_map[SDAP_AT_GROUP_GID].sys_name,
                                           &gid);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "no gid provided for [%s] in domain [%s].\n",
                          group_name, dom->name);
                ret = EINVAL;
                goto done;
            }
        }
    }

    /* check that the gid is valid for this domain */
    if (posix_group) {
        if (OUT_OF_ID_RANGE(gid, dom->id_min, dom->id_max)) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Group [%s] filtered out! (id out of range)\n", group_name);
            ret = EINVAL;
            goto done;
        }
        /* Group ID OK */
    }

    ret = sdap_attrs_add_string(attrs, SYSDB_ORIG_DN, "original DN",
                                group_name, group_attrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Error setting original DN: [%s]\n",
               sss_strerror(ret));
        goto done;
    }

    ret = sdap_attrs_add_string(attrs,
                            opts->group_map[SDAP_AT_GROUP_MODSTAMP].sys_name,
                            "original mod-Timestamp",
                            group_name, group_attrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Error setting mod timestamp: [%s]\n",
               sss_strerror(ret));
        goto done;
    }

    ret = sysdb_attrs_get_el(attrs,
                      opts->group_map[SDAP_AT_GROUP_USN].sys_name, &el);
    if (ret) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Error looking up group USN: [%s]\n",
               sss_strerror(ret));
        goto done;
    }
    if (el->num_values == 0) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Original USN value is not available for [%s].\n", group_name);
    } else {
        ret = sysdb_attrs_add_string(group_attrs,
                          opts->group_map[SDAP_AT_GROUP_USN].sys_name,
                          (const char*)el->values[0].data);
        if (ret) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Error setting group USN: [%s]\n",
                   sss_strerror(ret));
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
        DEBUG(SSSDBG_OP_FAILURE, "Failed to save ghost members\n");
        goto done;
    }

    ret = sdap_save_all_names(group_name, attrs, dom,
                              SYSDB_MEMBER_GROUP, group_attrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to save group names\n");
        goto done;
    }
    DEBUG(SSSDBG_TRACE_FUNC, "Storing info for group %s\n", group_name);

    ret = sysdb_store_group(dom, group_name, gid, group_attrs,
                            dom->group_timeout, now);
    if (ret) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Could not store group [%s] with GID [%u]: [%s]\n",
              group_name, gid, sss_strerror(ret));
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
              "Failed to save group [%s]: [%s]\n",
               group_name ? group_name : "Unknown",
               sss_strerror(ret));
    }
    talloc_free(tmpctx);
    return ret;
}

static errno_t
are_sids_from_same_dom(const char *sid1, const char *sid2, bool *_result)
{
    size_t len_prefix_sid1;
    size_t len_prefix_sid2;
    char *rid1, *rid2;
    bool result;

    rid1 = strrchr(sid1, '-');
    if (rid1 == NULL) {
        return EINVAL;
    }

    rid2 = strrchr(sid2, '-');
    if (rid2 == NULL) {
        return EINVAL;
    }

    len_prefix_sid1 = rid1 - sid1;
    len_prefix_sid2 = rid2 - sid2;

    result = (len_prefix_sid1 == len_prefix_sid2) &&
        (strncmp(sid1, sid2, len_prefix_sid1) == 0);

    *_result = result;

    return EOK;
}

static errno_t
retain_extern_members(TALLOC_CTX *mem_ctx,
                      struct sss_domain_info *dom,
                      const char *group_name,
                      const char *group_sid,
                      char ***_userdns,
                      size_t *_nuserdns)
{
    TALLOC_CTX *tmp_ctx;
    const char **sids, **dns;
    bool same_domain;
    errno_t ret;
    size_t i, n;
    size_t nuserdns = 0;
    const char **userdns = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sysdb_get_sids_of_members(tmp_ctx, dom, group_name, &sids, &dns, &n);
    if (ret != EOK) {
        if (ret != ENOENT) {
            DEBUG(SSSDBG_TRACE_ALL,
                  "get_sids_of_members failed: %d [%s]\n",
                  ret, sss_strerror(ret));
        }
        goto done;
    }

    for (i=0; i < n; i++) {
        ret = are_sids_from_same_dom(group_sid, sids[i], &same_domain);
        if (ret == EOK && !same_domain) {
            DEBUG(SSSDBG_TRACE_ALL, "extern member: %s\n", dns[i]);
            nuserdns++;
            userdns = talloc_realloc(tmp_ctx, userdns, const char*, nuserdns);
            if (userdns == NULL) {
                ret = ENOMEM;
                goto done;
            }
            userdns[nuserdns-1] = talloc_steal(userdns, dns[i]);
        }
    }
    *_nuserdns = nuserdns;
    *_userdns = discard_const(talloc_steal(mem_ctx, userdns));
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

/* ==Save-Group-Members=================================================== */

    /* FIXME: support non-legacy */
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
    const char *group_sid;
    const char *group_name;
    char **userdns = NULL;
    size_t nuserdns = 0;
    struct sss_domain_info *group_dom = NULL;
    int ret;
    const char *remove_attrs[] = {SYSDB_MEMBER, SYSDB_ORIG_MEMBER, SYSDB_GHOST,
                                  NULL};
    const char *check_dom;
    const char *check_name;

    if (dom->ignore_group_members) {
        DEBUG(SSSDBG_TRACE_FUNC, "Group members are ignored, nothing to do.\n");
        return EOK;
    }

    ret = sysdb_attrs_get_string(attrs, SYSDB_SID_STR, &group_sid);
    if (ret != EOK) {
        /* Try harder. */
        ret = sdap_attrs_get_sid_str(memctx, opts->idmap_ctx, attrs,
                              opts->group_map[SDAP_AT_GROUP_OBJECTSID].sys_name,
                              discard_const(&group_sid));
        if (ret != EOK) {
            DEBUG(SSSDBG_TRACE_FUNC, "Failed to get group sid\n");
            group_sid = NULL;
        }
    }

    if (group_sid != NULL) {
        group_dom = sss_get_domain_by_sid_ldap_fallback(get_domains_head(dom),
                                                        group_sid);
        if (group_dom == NULL) {
            ret = well_known_sid_to_name(group_sid, &check_dom, &check_name);
            if (ret == EOK) {
                DEBUG(SSSDBG_TRACE_FUNC,
                      "Skipping group with SID [%s][%s\\%s] which is "
                      "currently not handled by SSSD.\n",
                      group_sid, check_dom, check_name);
                return EOK;
            }

            DEBUG(SSSDBG_TRACE_FUNC, "SID [%s] does not belong to any known "
                                     "domain, using [%s].\n", group_sid,
                                                              dom->name);
        }
    }

    if (group_dom == NULL) {
        group_dom = dom;
    }

    ret = sdap_get_group_primary_name(memctx, opts, attrs, group_dom,
                                      &group_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to get group name\n");
        goto fail;
    }
    DEBUG(SSSDBG_TRACE_FUNC, "Processing group %s\n", group_name);

    /* With AD we also want to merge in parent groups of primary GID as they
     * are reported with tokenGroups, too
     */
    if (opts->schema_type == SDAP_SCHEMA_AD) {
        ret = sdap_dn_by_primary_gid(memctx, attrs, group_dom, opts,
                                     &userdns, &nuserdns);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "sdap_dn_by_primary_gid failed: [%d][%s].\n",
                  ret, strerror(ret));
            goto fail;
        }
    }

    /* This is a temporal solution until the IPA provider is able to
     * resolve external group membership.
     * https://fedorahosted.org/sssd/ticket/2522
     */
    if (opts->schema_type == SDAP_SCHEMA_IPA_V1) {
        if (group_sid != NULL) {
            ret = retain_extern_members(memctx, group_dom, group_name,
                                        group_sid, &userdns, &nuserdns);
            if (ret != EOK) {
                DEBUG(SSSDBG_TRACE_INTERNAL,
                      "retain_extern_members failed: %d:[%s].\n",
                      ret, sss_strerror(ret));
            }
        }
    }

    ret = sysdb_attrs_get_el(attrs,
                    opts->group_map[SDAP_AT_GROUP_MEMBER].sys_name, &el);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "sysdb_attrs_get_el failed: [%d][%s].\n",
              ret, strerror(ret));
        goto fail;
    }

    if (el->num_values == 0 && nuserdns == 0) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "No members for group [%s]\n", group_name);

        ret = sysdb_remove_attrs(group_dom, group_name, SYSDB_MEMBER_GROUP,
                                 discard_const(remove_attrs));
        if (ret != EOK) {
            if (ret != ENOENT) {
                DEBUG(SSSDBG_OP_FAILURE, "sysdb_remove_attrs failed.\n");
            } else {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "sysdb_remove_attrs failed for missing entry\n");
            }
            goto fail;
        }
    } else {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Adding member users to group [%s]\n", group_name);

        group_attrs = sysdb_new_attrs(memctx);
        if (!group_attrs) {
            DEBUG(SSSDBG_MINOR_FAILURE, "sysdb_new_attrs failed\n");
            ret = ENOMEM;
            goto fail;
        }

        ret = sdap_fill_memberships(opts, group_attrs, ctx, group_dom, ghosts,
                                    el->values, el->num_values,
                                    userdns, nuserdns);
        if (ret) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "sdap_fill_memberships failed with [%d]: %s\n", ret,
                   strerror(ret));
            goto fail;
        }
    }

    ret = sysdb_store_group(group_dom, group_name, 0, group_attrs,
                            group_dom->group_timeout, now);
    if (ret) {
        DEBUG(SSSDBG_MINOR_FAILURE, "sysdb_store_group failed: [%d][%s].\n",
              ret, strerror(ret));
        goto fail;
    }

    return EOK;

fail:
    DEBUG(SSSDBG_MINOR_FAILURE,
           "Failed to save members of group %s\n", group_name);
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
                            bool save_orig_member,
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
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
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
        ret = sdap_save_group(tmpctx, opts, dom, groups[i],
                              populate_members,
                              has_nesting && save_orig_member,
                              ghosts, &usn_value, now);

        /* Do not fail completely on errors.
         * Just report the failure to save and go on */
        if (ret) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to store group %d. Ignoring.\n", i);
        } else {
            DEBUG(SSSDBG_TRACE_ALL, "Group %d processed!\n", i);
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
                if (ret != ENOENT) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "Failed to store group %d members: %d\n", i, ret);
                } else {
                    DEBUG(SSSDBG_FUNC_DATA,
                          "Can't save members of missing group %d\n", i);
                }
            } else {
                DEBUG(SSSDBG_TRACE_ALL, "Group %d members processed!\n", i);
            }
        }
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to commit transaction!\n");
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
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to cancel transaction\n");
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
    const char **attrs;
    const char *filter;
    size_t check_count;

    bool enumeration;
};

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

static struct tevent_req *
sdap_process_group_send(TALLOC_CTX *memctx,
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

    ret = build_attrs_from_map(grp_state, opts->user_map, opts->user_map_cnt,
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
        DEBUG(SSSDBG_FUNC_DATA, "No Members. Done!\n");
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
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unknown schema type %d\n", opts->schema_type);
            ret = EINVAL;
            break;
    }

done:
    /* We managed to process all the entries */
    /* EBUSY means we need to wait for entries in LDAP */
    if (ret == EOK) {
        DEBUG(SSSDBG_TRACE_LIBS, "All group members processed\n");
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
                                    char *user_dn)
{
    struct sdap_process_group_state *grp_state =
        tevent_req_data(req, struct sdap_process_group_state);
    struct tevent_req *subreq;

    subreq = sdap_get_generic_send(grp_state,
                                   grp_state->ev,
                                   grp_state->opts,
                                   grp_state->sh,
                                   user_dn,
                                   LDAP_SCOPE_BASE,
                                   grp_state->filter,
                                   grp_state->attrs,
                                   grp_state->opts->user_map,
                                   grp_state->opts->user_map_cnt,
                                   dp_opt_get_int(grp_state->opts->basic,
                                                  SDAP_SEARCH_TIMEOUT),
                                   false);
    if (!subreq) {
        return ENOMEM;
    }
    tevent_req_set_callback(subreq, sdap_process_group_members, req);

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
    int nesting_level;
    bool is_group;

    nesting_level = dp_opt_get_int(state->opts->basic, SDAP_NESTING_LEVEL);

    for (i=0; i < memberel->num_values; i++) {
        member_dn = (char *)memberel->values[i].data;

        ret = sdap_find_entry_by_origDN(state->sysdb_dns->values,
                                        state->sysdb,
                                        state->dom,
                                        member_dn,
                                        &strdn,
                                        &is_group);

        if (ret == EOK) {
            if (nesting_level == 0 && is_group) {
                /* Ignore group members which are groups themselves. */
                continue;
            }

            /*
             * User already cached in sysdb. Remember the sysdb DN for later
             * use by sdap_save_groups()
             */
            DEBUG(SSSDBG_TRACE_LIBS, "sysdbdn: %s\n", strdn);
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
                DEBUG(SSSDBG_TRACE_LIBS,
                      "Searching LDAP for missing user entry\n");
                ret = sdap_process_missing_member_2307bis(req,
                                                          member_dn);
                if (ret != EOK) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Error processing missing member #%d (%s):\n",
                              i, member_dn);
                    return ret;
                }
            }
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Error checking cache for member #%d (%s):\n",
                       i, (char *)memberel->values[i].data);
            return ret;
        }
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
        ret = EBUSY;
    }

    return ret;
}

static int
sdap_add_group_member_2307(struct ldb_message_element *sysdb_dns,
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
                                 char *member_name)
{
    int ret;
    TALLOC_CTX *tmp_ctx;
    const char *filter;
    const char *username;
    const char *user_dn;
    char *sanitized_name;
    size_t count;
    struct ldb_message **msgs = NULL;
    static const char *attrs[] = { SYSDB_NAME, NULL };

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    ret = sss_filter_sanitize(tmp_ctx, member_name, &sanitized_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to sanitize the given name:'%s'.\n", member_name);
        goto done;
    }

    /* Check for the alias in the sysdb */
    filter = talloc_asprintf(tmp_ctx, "(%s=%s)", SYSDB_NAME_ALIAS,
                             sanitized_name);
    if (!filter) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_users(tmp_ctx, state->dom, filter,
                             attrs, &count, &msgs);
    if (ret == EOK && count > 0) {
        /* Entry exists but the group references it with an alias. */

        if (count != 1) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "More than one entry with this alias?\n");
            ret = EIO;
            goto done;
        }

        /* fill username with primary name */
        username = ldb_msg_find_attr_as_string(msgs[0], SYSDB_NAME, NULL);
        if (username == NULL) {
            ret = EINVAL;
            DEBUG(SSSDBG_MINOR_FAILURE, "Inconsistent sysdb: user "
                                         "without primary name?\n");
            goto done;
        }
        user_dn = sysdb_user_strdn(tmp_ctx, state->dom->name, username);
        if (user_dn == NULL) {
            return ENOMEM;
        }

        ret = sdap_add_group_member_2307(state->sysdb_dns, user_dn);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not add group member %s\n", username);
        }
    } else if (ret == ENOENT) {
        /* The entry really does not exist, add a ghost */
        DEBUG(SSSDBG_TRACE_FUNC, "Adding a ghost entry\n");
        ret = sdap_add_group_member_2307(state->ghost_dns, member_name);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not add group member %s\n", member_name);
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
    char *member_attr_val;
    char *member_name;
    char *userdn;
    int ret;
    int i;

    for (i=0; i < memberel->num_values; i++) {
        member_attr_val = (char *)memberel->values[i].data;

        /* We need to skip over zero-length usernames */
        if (member_attr_val[0] == '\0') continue;

        /* RFC2307 stores members as plain usernames in the member attribute.
         * Internally, we use FQDNs in the cache.
         */
        member_name = sss_create_internal_fqname(state, member_attr_val,
                                                 state->dom->name);
        if (member_name == NULL) {
            return ENOMEM;
        }

        ret = sysdb_search_user_by_name(state, state->dom, member_name,
                                        NULL, &msg);
        if (ret == EOK) {
            /*
             * User already cached in sysdb. Remember the sysdb DN for later
             * use by sdap_save_groups()
             */
            DEBUG(SSSDBG_TRACE_LIBS,
                  "Member already cached in sysdb: %s\n", member_name);

            userdn = sysdb_user_strdn(state->sysdb_dns, state->dom->name, member_name);
            if (userdn == NULL) {
                return ENOMEM;
            }

            ret = sdap_add_group_member_2307(state->sysdb_dns, userdn);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Could not add member %s into sysdb\n", member_name);
                goto done;
            }
        } else if (ret == ENOENT) {
            /* The user is not in sysdb, need to add it */
            DEBUG(SSSDBG_TRACE_LIBS, "member #%d (%s): not found in sysdb\n",
                       i, member_name);

            ret = sdap_process_missing_member_2307(state, member_name);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Error processing missing member #%d (%s):\n",
                          i, member_name);
                goto done;
            }
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Error checking cache for member #%d (%s):\n",
                       i, (char *) memberel->values[i].data);
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
    char *name_string;

    state->check_count--;
    DEBUG(SSSDBG_TRACE_ALL, "Members remaining: %zu\n", state->check_count);

    ret = sdap_get_generic_recv(subreq, state, &count, &usr_attrs);
    talloc_zfree(subreq);
    if (ret) {
        goto next;
    }
    if (count != 1) {
        ret = EINVAL;
        DEBUG(SSSDBG_TRACE_LIBS,
              "Expected one user entry and got %zu\n", count);
        goto next;
    }
    ret = sysdb_attrs_get_el(usr_attrs[0],
            state->opts->user_map[SDAP_AT_USER_NAME].sys_name, &el);
    if (el->num_values == 0) {
        ret = EINVAL;
    }
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to get the member's name\n");
        goto next;
    }

    name_string = sss_create_internal_fqname(state,
                                            (const char *) el[0].values[0].data,
                                            state->dom->name);
    if (name_string == NULL) {
        ret = ENOMEM;
        goto next;
    }

    state->ghost_dns->values[state->ghost_dns->num_values].data =
            talloc_steal(state->ghost_dns->values, (uint8_t *) name_string);
    state->ghost_dns->values[state->ghost_dns->num_values].length =
            strlen(name_string);
    state->ghost_dns->num_values++;

next:
    if (ret) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Error reading group member[%d]: %s. Skipping\n",
               ret, strerror(ret));
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
                  "Failed to get the group member attribute [%d]: %s\n",
                  ret, strerror(ret));
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
        DEBUG(SSSDBG_TRACE_ALL, "Processed Group - Done\n");
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
    struct sdap_domain *sdom;
    struct sysdb_ctx *sysdb;
    const char **attrs;
    const char *base_filter;
    char *filter;
    int timeout;
    enum sdap_entry_lookup_type lookup_type;
    bool no_members;

    char *higher_usn;
    struct sysdb_attrs **groups;
    size_t count;
    size_t check_count;
    hash_table_t *missing_external;

    hash_table_t *user_hash;
    hash_table_t *group_hash;

    size_t base_iter;
    struct sdap_search_base **search_bases;

    struct sdap_handle *ldap_sh;
    struct sdap_id_op *op;
};

static errno_t sdap_get_groups_next_base(struct tevent_req *req);
static void sdap_get_groups_ldap_connect_done(struct tevent_req *subreq);
static void sdap_get_groups_process(struct tevent_req *subreq);
static void sdap_get_groups_done(struct tevent_req *subreq);

struct tevent_req *sdap_get_groups_send(TALLOC_CTX *memctx,
                                       struct tevent_context *ev,
                                       struct sdap_domain *sdom,
                                       struct sdap_options *opts,
                                       struct sdap_handle *sh,
                                       const char **attrs,
                                       const char *filter,
                                       int timeout,
                                       enum sdap_entry_lookup_type lookup_type,
                                       bool no_members)
{
    errno_t ret;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct sdap_get_groups_state *state;
    struct sdap_id_conn_ctx *ldap_conn = NULL;

    req = tevent_req_create(memctx, &state, struct sdap_get_groups_state);
    if (!req) return NULL;

    state->ev = ev;
    state->opts = opts;
    state->sdom = sdom;
    state->dom = sdom->dom;
    state->sh = sh;
    state->sysdb = sdom->dom->sysdb;
    state->attrs = attrs;
    state->higher_usn = NULL;
    state->groups =  NULL;
    state->count = 0;
    state->timeout = timeout;
    state->lookup_type = lookup_type;
    state->no_members = no_members;
    state->base_filter = filter;
    state->base_iter = 0;
    state->search_bases = sdom->group_search_bases;

    if (!state->search_bases) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Group lookup request without a search base\n");
        ret = EINVAL;
        goto done;
    }

    /* With AD by default the Global Catalog is used for lookup. But the GC
     * group object might not have full group membership data. To make sure we
     * connect to an LDAP server of the group's domain. */
    ldap_conn = get_ldap_conn_from_sdom_pvt(state->opts, sdom);
    if (ldap_conn != NULL) {
        state->op = sdap_id_op_create(state, ldap_conn->conn_cache);
        if (!state->op) {
            DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create failed\n");
            ret = ENOMEM;
            goto done;
        }

        subreq = sdap_id_op_connect_send(state->op, state, &ret);
        if (subreq == NULL) {
            ret = ENOMEM;
            goto done;
        }

        tevent_req_set_callback(subreq,
                                sdap_get_groups_ldap_connect_done,
                                req);
        return req;
    }

    ret = sdap_get_groups_next_base(req);

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void sdap_get_groups_ldap_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct sdap_get_groups_state *state;
    int ret;
    int dp_error;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_get_groups_state);

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    state->ldap_sh = sdap_id_op_handle(state->op);

    ret = sdap_get_groups_next_base(req);
    if (ret != EOK) {
        tevent_req_error(req, ret);
    }

    return;
}

static errno_t sdap_get_groups_next_base(struct tevent_req *req)
{
    struct tevent_req *subreq;
    struct sdap_get_groups_state *state;
    bool need_paging = false;
    int sizelimit = 0;

    state = tevent_req_data(req, struct sdap_get_groups_state);

    talloc_zfree(state->filter);
    state->filter = sdap_combine_filters(state, state->base_filter,
                        state->search_bases[state->base_iter]->filter);
    if (!state->filter) {
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Searching for groups with base [%s]\n",
           state->search_bases[state->base_iter]->basedn);

    switch (state->lookup_type) {
    case SDAP_LOOKUP_SINGLE:
        break;
    /* Only requests that can return multiple entries should require
     * the paging control
     */
    case SDAP_LOOKUP_WILDCARD:
        sizelimit = dp_opt_get_int(state->opts->basic, SDAP_WILDCARD_LIMIT);
        need_paging = true;
        break;
    case SDAP_LOOKUP_ENUMERATE:
        need_paging = true;
        break;
    }

    subreq = sdap_get_and_parse_generic_send(
            state, state->ev, state->opts,
            state->ldap_sh != NULL ? state->ldap_sh : state->sh,
            state->search_bases[state->base_iter]->basedn,
            state->search_bases[state->base_iter]->scope,
            state->filter, state->attrs,
            state->opts->group_map, SDAP_OPTS_GROUP,
            0, NULL, NULL, sizelimit, state->timeout,
            need_paging);
    if (!subreq) {
        return ENOMEM;
    }
    tevent_req_set_callback(subreq, sdap_get_groups_process, req);

    return EOK;
}

static void sdap_nested_done(struct tevent_req *req);
static void sdap_search_group_copy_batch(struct sdap_get_groups_state *state,
                                         struct sysdb_attrs **groups,
                                         size_t count);

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
    char **sysdb_groupnamelist;

    ret = sdap_get_and_parse_generic_recv(subreq, state,
                                          &count, &groups);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Search for groups, returned %zu results.\n", count);

    if (state->lookup_type == SDAP_LOOKUP_WILDCARD || \
            state->lookup_type == SDAP_LOOKUP_ENUMERATE || \
        count == 0) {
        /* No users found in this search or looking up multiple entries */
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

        sdap_search_group_copy_batch(state, groups, count);
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

    if (state->no_members) {
        ret = sdap_get_primary_fqdn_list(state->dom, state,
                                state->groups, state->count,
                                state->opts->group_map[SDAP_AT_GROUP_NAME].name,
                                state->opts->group_map[SDAP_AT_GROUP_OBJECTSID].name,
                                state->opts->idmap_ctx,
                                &sysdb_groupnamelist);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "sysdb_attrs_primary_name_list failed.\n");
            tevent_req_error(req, ret);
            return;
        }

        ret = sdap_add_incomplete_groups(state->sysdb, state->dom, state->opts,
                                         sysdb_groupnamelist, state->groups,
                                         state->count);
        if (ret == EOK) {
            DEBUG(SSSDBG_TRACE_LIBS,
                  "Writing only group data without members was successful.\n");
            tevent_req_done(req);
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "sdap_add_incomplete_groups failed.\n");
            tevent_req_error(req, ret);
        }
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
    if (state->lookup_type == SDAP_LOOKUP_SINGLE) {
        if ((state->opts->schema_type != SDAP_SCHEMA_RFC2307)
                && (dp_opt_get_int(state->opts->basic, SDAP_NESTING_LEVEL) != 0)) {
            subreq = sdap_nested_group_send(state, state->ev, state->sdom,
                                            state->opts, state->sh,
                                            state->groups[0]);
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

    ret = sysdb_transaction_start(state->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to start transaction\n");
        tevent_req_error(req, ret);
        return;
    }

    if ((state->lookup_type == SDAP_LOOKUP_ENUMERATE
                || state->lookup_type == SDAP_LOOKUP_WILDCARD)
            && state->opts->schema_type != SDAP_SCHEMA_RFC2307
            && dp_opt_get_int(state->opts->basic, SDAP_NESTING_LEVEL) != 0) {
        DEBUG(SSSDBG_TRACE_ALL, "Saving groups without members first "
                  "to allow unrolling of nested groups.\n");
        ret = sdap_save_groups(state, state->sysdb, state->dom, state->opts,
                               state->groups, state->count, false,
                               NULL, true, NULL);
        if (ret) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to store groups.\n");
            tevent_req_error(req, ret);
            return;
        }
    }

    for (i = 0; i < state->count; i++) {
        subreq = sdap_process_group_send(state, state->ev, state->dom,
                                         state->sysdb, state->opts,
                                         state->sh, state->groups[i],
                                         state->lookup_type == SDAP_LOOKUP_ENUMERATE);

        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, sdap_get_groups_done, req);
    }
}

static void sdap_search_group_copy_batch(struct sdap_get_groups_state *state,
                                         struct sysdb_attrs **groups,
                                         size_t count)
{
    size_t copied;
    bool filter;

    /* Always copy all objects for wildcard lookups. */
    filter = state->lookup_type == SDAP_LOOKUP_SINGLE ? true : false;

    copied = sdap_steal_objects_in_dom(state->opts,
                                       state->groups,
                                       state->count,
                                       state->dom,
                                       groups, count, filter);

    state->count += copied;
    state->groups[state->count] = NULL;
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
            DEBUG(SSSDBG_FATAL_FAILURE, "Could not cancel sysdb transaction\n");
        }
        tevent_req_error(req, ret);
        return;
    }

    state->check_count--;
    DEBUG(SSSDBG_TRACE_ALL, "Groups remaining: %zu\n", state->check_count);


    if (state->check_count == 0) {
        DEBUG(SSSDBG_TRACE_ALL, "All groups processed\n");

        /* If ignore_group_members is set for the domain, don't update
         * group memberships in the cache.
         *
         * If enumeration is on, don't overwrite orig_members as they've been
         * saved earlier.
         */
        ret = sdap_save_groups(state, state->sysdb, state->dom, state->opts,
                               state->groups, state->count,
                               !state->dom->ignore_group_members, NULL,
                               state->lookup_type == SDAP_LOOKUP_SINGLE,
                               &state->higher_usn);
        if (ret) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to store groups.\n");
            tevent_req_error(req, ret);
            return;
        }
        DEBUG(SSSDBG_TRACE_ALL, "Saving %zu Groups - Done\n", state->count);
        sysret = sysdb_transaction_commit(state->sysdb);
        if (sysret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE, "Couldn't commit transaction\n");
            tevent_req_error(req, sysret);
        } else {
            tevent_req_done(req);
        }
    }
}

static errno_t sdap_nested_group_populate_users(TALLOC_CTX *mem_ctx,
                                                struct sysdb_ctx *sysdb,
                                                struct sss_domain_info *domain,
                                                struct sdap_options *opts,
                                                struct sysdb_attrs **users,
                                                int num_users,
                                                hash_table_t **_ghosts);


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

static void sdap_nested_ext_done(struct tevent_req *subreq);

static void sdap_nested_done(struct tevent_req *subreq)
{
    errno_t ret, tret;
    unsigned long user_count;
    unsigned long group_count;
    bool in_transaction = false;
    struct sysdb_attrs **users = NULL;
    struct sysdb_attrs **groups = NULL;
    hash_table_t *ghosts;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_groups_state *state = tevent_req_data(req,
                                            struct sdap_get_groups_state);

    ret = sdap_nested_group_recv(state, subreq, &user_count, &users,
                                 &group_count, &groups,
                                 &state->missing_external);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Nested group processing failed: [%d][%s]\n",
                  ret, strerror(ret));
        goto fail;
    }

    /* Save all of the users first so that they are in
     * place for the groups to add them.
     */
    ret = sysdb_transaction_start(state->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
        goto fail;
    }
    in_transaction = true;

    PROBE(SDAP_NESTED_GROUP_POPULATE_PRE);
    ret = sdap_nested_group_populate_users(state, state->sysdb,
                                           state->dom, state->opts,
                                           users, user_count, &ghosts);
    PROBE(SDAP_NESTED_GROUP_POPULATE_POST);
    if (ret != EOK) {
        goto fail;
    }

    PROBE(SDAP_NESTED_GROUP_SAVE_PRE);
    ret = sdap_save_groups(state, state->sysdb, state->dom, state->opts,
                           groups, group_count, false, ghosts, true,
                           &state->higher_usn);
    PROBE(SDAP_NESTED_GROUP_SAVE_POST);
    if (ret != EOK) {
        goto fail;
    }

    ret = sysdb_transaction_commit(state->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to commit transaction\n");
        goto fail;
    }
    in_transaction = false;

    if (hash_count(state->missing_external) == 0) {
        /* No external members. Processing complete */
        DEBUG(SSSDBG_TRACE_INTERNAL, "No external members, done\n");
        tevent_req_done(req);
        return;
    }

    /* At the moment, we need to save the direct groups & members in one
     * transaction and then query the others in a separate requests
     */
    subreq = sdap_nested_group_lookup_external_send(state, state->ev,
                                                    state->dom,
                                                    state->opts->ext_ctx,
                                                    state->missing_external);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, sdap_nested_ext_done, req);
    return;

fail:
    if (in_transaction) {
        tret = sysdb_transaction_cancel(state->sysdb);
        if (tret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to cancel transaction\n");
        }
    }
    tevent_req_error(req, ret);
}

static void sdap_nested_ext_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_groups_state *state = tevent_req_data(req,
                                            struct sdap_get_groups_state);

    ret = sdap_nested_group_lookup_external_recv(state, subreq);
    talloc_free(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot resolve external members [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

static errno_t sdap_nested_group_populate_users(TALLOC_CTX *mem_ctx,
                                                struct sysdb_ctx *sysdb,
                                                struct sss_domain_info *domain,
                                                struct sdap_options *opts,
                                                struct sysdb_attrs **users,
                                                int num_users,
                                                hash_table_t **_ghosts)
{
    int i;
    errno_t ret, sret;
    struct ldb_message_element *el;
    const char *username;
    const char *original_dn;
    const char *hash_key_dn;
    struct sss_domain_info *user_dom;
    struct sdap_domain *sdap_dom;

    TALLOC_CTX *tmp_ctx;
    struct ldb_message **msgs;
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
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction!\n");
        goto done;
    }
    in_transaction = true;

    for (i = 0; i < num_users; i++) {
        ret = sysdb_attrs_get_el(users[i], SYSDB_ORIG_DN, &el);
        if (el->num_values == 0) {
            ret = EINVAL;
        }
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "User entry %d has no originalDN attribute\n", i);
            goto done;
        }
        original_dn = (const char *) el->values[0].data;

        sdap_dom = sdap_domain_get_by_dn(opts, original_dn);
        user_dom = sdap_dom == NULL ? domain : sdap_dom->dom;

        ret = sdap_get_user_primary_name(tmp_ctx, opts, users[i],
                                         user_dom, &username);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "User entry %d has no name attribute. Skipping\n", i);
            continue;
        }

        /* Check for the specified origDN in the sysdb */
        PROBE(SDAP_NESTED_GROUP_POPULATE_SEARCH_USERS_PRE);
        ret = sysdb_search_users_by_orig_dn(tmp_ctx, user_dom, original_dn,
                                            search_attrs, &count, &msgs);
        PROBE(SDAP_NESTED_GROUP_POPULATE_SEARCH_USERS_POST);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Error checking cache for user entry\n");
            goto done;
        } else if (ret == EOK) {
            /* The entry is cached but expired. Update the username
             * if needed. */
            if (count != 1) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "More than one entry with this origDN? Skipping\n");
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
            ret = sysdb_set_entry_attr(user_dom->sysdb, msgs[0]->dn, attrs,
                                       SYSDB_MOD_REP);
            if (ret != EOK) goto done;
        } else {
            /* The DN of the user object and the DN in the member attribute
             * might differ, e.g. in case. Since we later search the hash with
             * DNs from the member attribute we should try to use DN from the
             * member attribute here as well. This should be added earlier in
             * the SYSDB_DN_FOR_MEMBER_HASH_TABLE attribute. If this does not
             * exists we fall-back to original_dn which should work in the
             * most cases as well. */
            ret = sysdb_attrs_get_string(users[i],
                                         SYSDB_DN_FOR_MEMBER_HASH_TABLE,
                                         &hash_key_dn);
            if (ret != EOK) {
                hash_key_dn = original_dn;
            }

            key.type = HASH_KEY_STRING;
            key.str = talloc_steal(ghosts, discard_const(hash_key_dn));
            value.type = HASH_VALUE_PTR;
            /* Already qualified from sdap_get_user_primary_name() */
            value.ptr = talloc_steal(ghosts, discard_const(username));
            ret = hash_enter(ghosts, &key, &value);
            if (ret != HASH_SUCCESS) {
                talloc_free(key.str);
                talloc_free(value.ptr);
                ret = ENOMEM;
                goto done;
            }
        }
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to commit transaction!\n");
        goto done;
    }
    in_transaction = false;

    ret = EOK;
done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not cancel transaction\n");
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
