/*
    SSSD

    Async LDAP Helper routines - retrieving users

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

#include <ctype.h>

#include "util/util.h"
#include "util/probes.h"
#include "db/sysdb.h"
#include "providers/ldap/sdap_async_private.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_idmap.h"
#include "providers/ldap/sdap_users.h"

#define REALM_SEPARATOR '@'

static void make_realm_upper_case(const char *upn)
{
    char *c;

    c = strchr(upn, REALM_SEPARATOR);
    if (c == NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "No realm delimiter found in upn [%s].\n", upn);
        return;
    }

    while(*(++c) != '\0') {
        c[0] = toupper(*c);
    }

    return;
}

/* ==Save-User-Entry====================================================== */

static errno_t
sdap_get_idmap_primary_gid(struct sdap_options *opts,
                           struct sysdb_attrs *attrs,
                           char *sid_str,
                           char *dom_sid_str,
                           gid_t *_gid)
{
    errno_t ret;
    TALLOC_CTX *tmpctx = NULL;
    gid_t gid, primary_gid;
    char *group_sid_str;

    tmpctx = talloc_new(NULL);
    if (!tmpctx) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_attrs_get_uint32_t(attrs,
                opts->user_map[SDAP_AT_USER_PRIMARY_GROUP].sys_name,
                &primary_gid);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "no primary group ID provided\n");
        ret = EINVAL;
        goto done;
    }

    /* The primary group ID is just the RID part of the objectSID
     * of the group. Generate the GID by adding this to the domain
     * SID value.
     */

    /* First, get the domain SID if we didn't do so above */
    if (!dom_sid_str) {
        ret = sdap_idmap_get_dom_sid_from_object(tmpctx, sid_str,
                                                 &dom_sid_str);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Could not parse domain SID from [%s]\n", sid_str);
            goto done;
        }
    }

    /* Add the RID to the end */
    group_sid_str = talloc_asprintf(tmpctx, "%s-%lu", dom_sid_str,
                                   (unsigned long) primary_gid);
    if (!group_sid_str) {
        ret = ENOMEM;
        goto done;
    }

    /* Convert the SID into a UNIX group ID */
    ret = sdap_idmap_sid_to_unix(opts->idmap_ctx, group_sid_str, &gid);
    if (ret != EOK) goto done;

    ret = EOK;
    *_gid = gid;
done:
    talloc_free(tmpctx);
    return ret;
}

static errno_t sdap_set_non_posix_flag(struct sysdb_attrs *attrs,
                                       const char *pkey)
{
    errno_t ret;

    ret = sysdb_attrs_add_uint32(attrs, pkey, 0);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to add a zero ID to a non-POSIX object!\n");
        return ret;
    }

    ret = sysdb_attrs_add_bool(attrs, SYSDB_POSIX, false);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Error: Failed to mark objects as non-POSIX!\n");
        return ret;
    }

    return EOK;
}

static int sdap_user_set_mpg(struct sysdb_attrs *user_attrs,
                             gid_t *_gid)
{
    errno_t ret;

    if (_gid == NULL) {
        return EINVAL;
    }

    if (*_gid == 0) {
        /* The original entry had no GID number. This is OK, we just won't add
         * the SYSDB_PRIMARY_GROUP_GIDNUM attribute
         */
        return EOK;
    }

    ret = sysdb_attrs_add_uint32(user_attrs,
                                 SYSDB_PRIMARY_GROUP_GIDNUM,
                                 (uint32_t) *_gid);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_add_uint32 failed.\n");
        return ret;
    }

    /* We won't really store gidNumber=0, but the zero value tells
     * the sysdb layer that no GID is set, which sysdb requires for
     * MPG-enabled domains
     */
    *_gid = 0;
    return EOK;
}

/* FIXME: support storing additional attributes */
int sdap_save_user(TALLOC_CTX *memctx,
                   struct sdap_options *opts,
                   struct sss_domain_info *dom,
                   struct sysdb_attrs *attrs,
                   struct sysdb_attrs *mapped_attrs,
                   char **_usn_value,
                   time_t now,
                   bool set_non_posix)
{
    struct ldb_message_element *el;
    int ret;
    const char *user_name = NULL;
    const char *fullname = NULL;
    const char *pwd;
    const char *gecos;
    const char *homedir;
    const char *shell;
    const char *orig_dn = NULL;
    uid_t uid = 0;
    gid_t gid = 0;
    struct sysdb_attrs *user_attrs;
    char *upn = NULL;
    size_t i;
    int cache_timeout;
    char *usn_value = NULL;
    char **missing = NULL;
    TALLOC_CTX *tmpctx = NULL;
    bool use_id_mapping;
    char *sid_str;
    char *dom_sid_str = NULL;
    struct sss_domain_info *subdomain;
    size_t c;
    char *p1;
    char *p2;
    bool is_posix = true;

    DEBUG(SSSDBG_TRACE_FUNC, "Save user\n");

    tmpctx = talloc_new(NULL);
    if (!tmpctx) {
        ret = ENOMEM;
        goto done;
    }

    user_attrs = sysdb_new_attrs(tmpctx);
    if (user_attrs == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Always store SID string if available */
    ret = sdap_attrs_get_sid_str(tmpctx, opts->idmap_ctx, attrs,
                                opts->user_map[SDAP_AT_USER_OBJECTSID].sys_name,
                                &sid_str);
    if (ret == EOK) {
        ret = sysdb_attrs_add_string(user_attrs, SYSDB_SID_STR, sid_str);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Could not add SID string: [%s]\n",
                                         sss_strerror(ret));
            goto done;
        }
    } else if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_ALL, "objectSID: not available for user\n");
        sid_str = NULL;
    } else {
        DEBUG(SSSDBG_MINOR_FAILURE, "Could not identify objectSID: [%s]\n",
                                     sss_strerror(ret));
        sid_str = NULL;
    }

    /* Always store UUID if available */
    ret = sysdb_handle_original_uuid(opts->user_map[SDAP_AT_USER_UUID].def_name,
                                     attrs,
                                     opts->user_map[SDAP_AT_USER_UUID].sys_name,
                                     user_attrs, SYSDB_UUID);
    if (ret != EOK) {
        DEBUG((ret == ENOENT) ? SSSDBG_TRACE_ALL : SSSDBG_MINOR_FAILURE,
              "Failed to retrieve UUID [%d][%s].\n", ret, sss_strerror(ret));
    }

    /* If this object has a SID available, we will determine the correct
     * domain by its SID. */
    if (sid_str != NULL) {
        subdomain = find_domain_by_sid(get_domains_head(dom), sid_str);
        if (subdomain) {
            dom = subdomain;
        } else {
            DEBUG(SSSDBG_TRACE_FUNC, "SID %s does not belong to any known "
                                      "domain\n", sid_str);
        }
    }

    ret = sdap_get_user_primary_name(memctx, opts, attrs, dom, &user_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to get user name\n");
        goto done;
    }
    DEBUG(SSSDBG_TRACE_FUNC, "Processing user %s\n", user_name);

    if (opts->schema_type == SDAP_SCHEMA_AD) {
        ret = sysdb_attrs_get_string(attrs,
                    opts->user_map[SDAP_AT_USER_FULLNAME].sys_name, &fullname);
        if (ret == EOK) {
            ret = sysdb_attrs_add_string(user_attrs, SYSDB_FULLNAME, fullname);
            if (ret != EOK) {
                goto done;
            }
        } else if (ret != ENOENT) {
            goto done;
        }
    }

    ret = sysdb_attrs_get_el(attrs,
                             opts->user_map[SDAP_AT_USER_PWD].sys_name, &el);
    if (ret) goto done;
    if (el->num_values == 0) pwd = NULL;
    else pwd = (const char *)el->values[0].data;

    ret = sysdb_attrs_get_el(attrs,
                             opts->user_map[SDAP_AT_USER_GECOS].sys_name, &el);
    if (ret) goto done;
    if (el->num_values == 0) gecos = NULL;
    else gecos = (const char *)el->values[0].data;

    if (!gecos) {
        /* Fall back to the user's full name */
        ret = sysdb_attrs_get_el(
                attrs,
                opts->user_map[SDAP_AT_USER_FULLNAME].sys_name, &el);
        if (ret) goto done;
        if (el->num_values > 0) gecos = (const char *)el->values[0].data;
    }

    ret = sysdb_attrs_get_el(attrs,
                             opts->user_map[SDAP_AT_USER_HOME].sys_name, &el);
    if (ret) goto done;
    if (el->num_values == 0) homedir = NULL;
    else homedir = (const char *)el->values[0].data;

    ret = sysdb_attrs_get_el(attrs,
                             opts->user_map[SDAP_AT_USER_SHELL].sys_name, &el);
    if (ret) goto done;
    if (el->num_values == 0) shell = NULL;
    else shell = (const char *)el->values[0].data;

    use_id_mapping = sdap_idmap_domain_has_algorithmic_mapping(opts->idmap_ctx,
                                                               dom->name,
                                                               sid_str);

    /* Retrieve or map the UID as appropriate */
    if (use_id_mapping) {

        if (sid_str == NULL) {
            DEBUG(SSSDBG_MINOR_FAILURE, "SID not available, cannot map a " \
                                         "unix ID to user [%s].\n", user_name);
            ret = ENOENT;
            goto done;
        }

        DEBUG(SSSDBG_TRACE_LIBS,
              "Mapping user [%s] objectSID [%s] to unix ID\n", user_name, sid_str);

        /* Convert the SID into a UNIX user ID */
        ret = sdap_idmap_sid_to_unix(opts->idmap_ctx, sid_str, &uid);
        if (ret == ENOTSUP) {
            DEBUG(SSSDBG_TRACE_FUNC, "Skipping built-in object.\n");
            ret = EOK;
            goto done;
        } else if (ret != EOK) {
            goto done;
        }

        /* Store the UID in the ldap_attrs so it doesn't get
         * treated as a missing attribute from LDAP and removed.
         */
        ret = sdap_replace_id(attrs, SYSDB_UIDNUM, uid);
        if (ret) {
            DEBUG(SSSDBG_OP_FAILURE, "Cannot set the id-mapped UID\n");
            goto done;
        }
    } else {
        ret = sysdb_attrs_get_uint32_t(attrs,
                                       opts->user_map[SDAP_AT_USER_UID].sys_name,
                                       &uid);
        if (ret == ENOENT && (dom->type == DOM_TYPE_APPLICATION || set_non_posix)) {
            DEBUG(SSSDBG_TRACE_INTERNAL,
                  "Marking object as non-POSIX and setting ID=0!\n");
            ret = sdap_set_non_posix_flag(user_attrs,
                    opts->user_map[SDAP_AT_USER_UID].sys_name);
            if (ret != EOK) {
                goto done;
            }
            is_posix = false;
        } else if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Cannot retrieve UID for [%s] in domain [%s].\n",
                   user_name, dom->name);
            ret = ERR_NO_POSIX;
            goto done;
        }
    }

    /* check that the uid is valid for this domain if the user is a POSIX one */
    if (is_posix == true && OUT_OF_ID_RANGE(uid, dom->id_min, dom->id_max)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "User [%s] filtered out! (uid out of range)\n",
              user_name);
        ret = EINVAL;
        goto done;
    }

    if (use_id_mapping) {
        ret = sdap_get_idmap_primary_gid(opts, attrs, sid_str, dom_sid_str,
                                         &gid);
        if (ret) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Cannot get the GID for [%s] in domain [%s].\n",
                   user_name, dom->name);
            goto done;
        }

        if (sss_domain_is_mpg(dom) == true) {
            /* For subdomain users, only create the private group as
             * the subdomain is an MPG domain.
             * But we have to save the GID of the original primary group
             * because otherwise this information might be lost because
             * typically (UNIX and AD) the user is not listed in his primary
             * group as a member.
             */
            ret = sdap_user_set_mpg(user_attrs, &gid);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "sdap_user_set_mpg failed [%d]: %s\n", ret,
                      sss_strerror(ret));
                goto done;
            }
        }

        /* Store the GID in the ldap_attrs so it doesn't get
        * treated as a missing attribute from LDAP and removed.
        */
        ret = sysdb_attrs_add_uint32(attrs, SYSDB_GIDNUM, gid);
        if (ret != EOK) goto done;
    } else if (sss_domain_is_mpg(dom)) {
        /* Likewise, if a domain is set to contain 'magic private groups', do
         * not process the real GID, but save it in the cache as originalGID
         * (if available)
         */
        ret = sysdb_attrs_get_uint32_t(attrs,
                                       opts->user_map[SDAP_AT_USER_GID].sys_name,
                                       &gid);
        if (ret == ENOENT) {
            DEBUG(SSSDBG_TRACE_LIBS,
                  "Missing GID, won't save the %s attribute\n",
                  SYSDB_PRIMARY_GROUP_GIDNUM);

            /* Store the UID as GID (since we're in a MPG domain so that it doesn't
             * get treated as a missing attribute and removed
             */
            ret = sdap_replace_id(attrs, SYSDB_GIDNUM, uid);
            if (ret) {
                DEBUG(SSSDBG_OP_FAILURE, "Cannot set the id-mapped UID\n");
                goto done;
            }
            gid = 0;
        } else if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Cannot retrieve GID, won't save the %s attribute\n",
                  SYSDB_PRIMARY_GROUP_GIDNUM);
            gid = 0;
        }

        ret = sdap_user_set_mpg(user_attrs, &gid);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "sdap_user_set_mpg failed [%d]: %s\n", ret, sss_strerror(ret));
            goto done;
        }
    } else {
        ret = sysdb_attrs_get_uint32_t(attrs,
                                       opts->user_map[SDAP_AT_USER_GID].sys_name,
                                       &gid);
        if (ret == ENOENT && (dom->type == DOM_TYPE_APPLICATION || set_non_posix)) {
            DEBUG(SSSDBG_TRACE_INTERNAL,
                  "Marking object as non-POSIX and setting ID=0!\n");
            ret = sdap_set_non_posix_flag(attrs,
                    opts->user_map[SDAP_AT_USER_GID].sys_name);
            if (ret != EOK) {
                goto done;
            }
            is_posix = false;
        } else if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Cannot retrieve GID for [%s] in domain [%s].\n",
                   user_name, dom->name);
            ret = ERR_NO_POSIX;
            goto done;
        }
    }

    /* check that the gid is valid for this domain */
    if (is_posix == true && IS_SUBDOMAIN(dom) == false
            && sss_domain_is_mpg(dom) == false
            && OUT_OF_ID_RANGE(gid, dom->id_min, dom->id_max)) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "User [%s] filtered out! (primary gid out of range)\n",
               user_name);
        ret = EINVAL;
        goto done;
    }

    ret = sysdb_attrs_get_el(attrs, SYSDB_ORIG_DN, &el);
    if (ret) {
        goto done;
    }
    if (!el || el->num_values == 0) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "originalDN is not available for [%s].\n", user_name);
    } else {
        orig_dn = (const char *) el->values[0].data;
        DEBUG(SSSDBG_TRACE_INTERNAL, "Adding originalDN [%s] to attributes "
                "of [%s].\n", orig_dn, user_name);

        ret = sysdb_attrs_add_string(user_attrs, SYSDB_ORIG_DN, orig_dn);
        if (ret) {
            goto done;
        }
    }

    ret = sysdb_attrs_get_el(attrs, SYSDB_MEMBEROF, &el);
    if (ret) {
        goto done;
    }
    if (el->num_values == 0) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Original memberOf is not available for [%s].\n", user_name);
    } else {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Adding original memberOf attributes to [%s].\n", user_name);
        for (i = 0; i < el->num_values; i++) {
            ret = sysdb_attrs_add_string(user_attrs, SYSDB_ORIG_MEMBEROF,
                    (const char *) el->values[i].data);
            if (ret) {
                goto done;
            }
        }
    }

    ret = sdap_attrs_add_string(attrs,
                            opts->user_map[SDAP_AT_USER_MODSTAMP].sys_name,
                            "original mod-Timestamp",
                            user_name, user_attrs);
    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_attrs_get_el(attrs,
                      opts->user_map[SDAP_AT_USER_USN].sys_name, &el);
    if (ret) {
        goto done;
    }
    if (el->num_values == 0) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Original USN value is not available for [%s].\n", user_name);
    } else {
        ret = sysdb_attrs_add_string(user_attrs,
                          opts->user_map[SDAP_AT_USER_USN].sys_name,
                          (const char*)el->values[0].data);
        if (ret) {
            goto done;
        }
        usn_value = talloc_strdup(tmpctx, (const char*)el->values[0].data);
        if (!usn_value) {
            ret = ENOMEM;
            goto done;
        }
    }

    ret = sysdb_attrs_get_el(attrs,
                             opts->user_map[SDAP_AT_USER_PRINC].sys_name, &el);
    if (ret) {
        goto done;
    }
    if (el->num_values == 0) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "User principal is not available for [%s].\n", user_name);
    } else {
        for (c = 0; c < el->num_values; c++) {
            upn = talloc_strdup(tmpctx, (const char*) el->values[c].data);
            if (!upn) {
                ret = ENOMEM;
                goto done;
            }

            /* Check for IPA Kerberos enterprise principal strings
             * 'user\@my.realm@IPA.REALM' and use 'user@my.realm' */
            if ( (p1 = strchr(upn,'\\')) != NULL
                    && *(p1 + 1) == '@'
                    && (p2 = strchr(p1 + 2, '@')) != NULL) {
                *p1 = '\0';
                *p2 = '\0';
                upn = talloc_asprintf(tmpctx, "%s%s", upn, p1 + 1);
                if (upn == NULL) {
                    DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
                    ret = ENOMEM;
                    goto done;
                }
            }

            if (dp_opt_get_bool(opts->basic, SDAP_FORCE_UPPER_CASE_REALM)) {
                make_realm_upper_case(upn);
            }
            DEBUG(SSSDBG_TRACE_FUNC,
                  "Adding user principal [%s] to attributes of [%s].\n",
                   upn, user_name);
            ret = sysdb_attrs_add_string(user_attrs, SYSDB_UPN, upn);
            if (ret) {
                goto done;
            }
        }
    }

    for (i = SDAP_FIRST_EXTRA_USER_AT; i < opts->user_map_cnt; i++) {
        ret = sdap_attrs_add_list(attrs, opts->user_map[i].sys_name,
                                  NULL, user_name, user_attrs);
        if (ret) {
            goto done;
        }
    }

    cache_timeout = dom->user_timeout;

    ret = sdap_save_all_names(user_name, attrs, dom,
                              SYSDB_MEMBER_USER, user_attrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to save user names\n");
        goto done;
    }

    /* Make sure that any attributes we requested from LDAP that we
     * did not receive are also removed from the sysdb
     */
    ret = list_missing_attrs(user_attrs, opts->user_map, opts->user_map_cnt,
                             attrs, &missing);
    if (ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Storing info for user %s\n", user_name);

    ret = sysdb_store_user(dom, user_name, pwd, uid, gid,
                           gecos, homedir, shell, orig_dn,
                           user_attrs, missing, cache_timeout, now);
    if (ret) goto done;

    if (mapped_attrs != NULL) {
        ret = sysdb_set_user_attr(dom, user_name, mapped_attrs, SYSDB_MOD_ADD);
        if (ret) return ret;
    }

    if (_usn_value) {
        *_usn_value = talloc_steal(memctx, usn_value);
    }

    talloc_steal(memctx, user_attrs);
    ret = EOK;

done:
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to save user [%s]\n",
               user_name ? user_name : "Unknown");
    }
    talloc_free(tmpctx);
    return ret;
}


/* ==Generic-Function-to-save-multiple-users============================= */

int sdap_save_users(TALLOC_CTX *memctx,
                    struct sysdb_ctx *sysdb,
                    struct sss_domain_info *dom,
                    struct sdap_options *opts,
                    struct sysdb_attrs **users,
                    int num_users,
                    struct sysdb_attrs *mapped_attrs,
                    char **_usn_value)
{
    TALLOC_CTX *tmpctx;
    char *higher_usn = NULL;
    char *usn_value;
    int ret;
    errno_t sret;
    int i;
    time_t now;
    bool in_transaction = false;

    if (num_users == 0) {
        /* Nothing to do if there are no users */
        return EOK;
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

    if (mapped_attrs != NULL) {
        ret = sysdb_remove_mapped_data(dom, mapped_attrs);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_remove_mapped_data failed, "
                  "some cached entries might contain invalid mapping data.\n");
        }
    }

    now = time(NULL);
    for (i = 0; i < num_users; i++) {
        usn_value = NULL;

        ret = sdap_save_user(tmpctx, opts, dom, users[i], mapped_attrs,
                             &usn_value, now, false);

        /* Do not fail completely on errors.
         * Just report the failure to save and go on */
        if (ret) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to store user %d. Ignoring.\n", i);
        } else {
            DEBUG(SSSDBG_TRACE_ALL, "User %d processed!\n", i);
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


/* ==Search-Users-with-filter============================================= */

struct sdap_search_user_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sdap_handle *sh;
    struct sss_domain_info *dom;

    const char **attrs;
    const char *base_filter;
    const char *filter;
    int timeout;
    enum sdap_entry_lookup_type lookup_type;

    char *higher_usn;
    struct sysdb_attrs **users;
    size_t count;

    size_t base_iter;
    struct sdap_search_base **search_bases;
};

static errno_t sdap_search_user_next_base(struct tevent_req *req);
static void sdap_search_user_copy_batch(struct sdap_search_user_state *state,
                                        struct sysdb_attrs **users,
                                        size_t count);
static void sdap_search_user_process(struct tevent_req *subreq);

struct tevent_req *sdap_search_user_send(TALLOC_CTX *memctx,
                                         struct tevent_context *ev,
                                         struct sss_domain_info *dom,
                                         struct sdap_options *opts,
                                         struct sdap_search_base **search_bases,
                                         struct sdap_handle *sh,
                                         const char **attrs,
                                         const char *filter,
                                         int timeout,
                                         enum sdap_entry_lookup_type lookup_type)
{
    errno_t ret;
    struct tevent_req *req;
    struct sdap_search_user_state *state;

    req = tevent_req_create(memctx, &state, struct sdap_search_user_state);
    if (req == NULL) return NULL;

    state->ev = ev;
    state->opts = opts;
    state->dom = dom;
    state->sh = sh;
    state->attrs = attrs;
    state->higher_usn = NULL;
    state->users =  NULL;
    state->count = 0;
    state->timeout = timeout;
    state->base_filter = filter;
    state->base_iter = 0;
    state->search_bases = search_bases;
    state->lookup_type = lookup_type;

    if (!state->search_bases) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "User lookup request without a search base\n");
        ret = EINVAL;
        goto done;
    }

    ret = sdap_search_user_next_base(req);

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, state->ev);
    }

    return req;
}

static errno_t sdap_search_user_next_base(struct tevent_req *req)
{
    struct tevent_req *subreq;
    struct sdap_search_user_state *state;
    bool need_paging = false;
    int sizelimit = 0;

    state = tevent_req_data(req, struct sdap_search_user_state);

    talloc_zfree(state->filter);
    state->filter = sdap_combine_filters(state, state->base_filter,
                        state->search_bases[state->base_iter]->filter);
    if (state->filter == NULL) {
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Searching for users with base [%s]\n",
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
            state, state->ev, state->opts, state->sh,
            state->search_bases[state->base_iter]->basedn,
            state->search_bases[state->base_iter]->scope,
            state->filter, state->attrs,
            state->opts->user_map, state->opts->user_map_cnt,
            0, NULL, NULL, sizelimit, state->timeout,
            need_paging);
    if (subreq == NULL) {
        return ENOMEM;
    }
    tevent_req_set_callback(subreq, sdap_search_user_process, req);

    return EOK;
}

static void sdap_search_user_process(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_search_user_state *state = tevent_req_data(req,
                                            struct sdap_search_user_state);
    int ret;
    size_t count;
    struct sysdb_attrs **users;
    bool next_base = false;

    ret = sdap_get_and_parse_generic_recv(subreq, state,
                                          &count, &users);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Search for users, returned %zu results.\n", count);

    if (state->lookup_type == SDAP_LOOKUP_WILDCARD || \
            state->lookup_type == SDAP_LOOKUP_ENUMERATE || \
        count == 0) {
        /* No users found in this search or looking up multiple entries */
        next_base = true;
    }

    /* Add this batch of users to the list */
    if (count > 0) {
        state->users =
                talloc_realloc(state,
                               state->users,
                               struct sysdb_attrs *,
                               state->count + count + 1);
        if (!state->users) {
            tevent_req_error(req, ENOMEM);
            return;
        }

        sdap_search_user_copy_batch(state, users, count);
    }

    if (next_base) {
        state->base_iter++;
        if (state->search_bases[state->base_iter]) {
            /* There are more search bases to try */
            ret = sdap_search_user_next_base(req);
            if (ret != EOK) {
                tevent_req_error(req, ret);
            }
            return;
        }
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "Retrieved total %zu users\n", state->count);

    /* No more search bases
     * Return ENOENT if no users were found
     */
    if (state->count == 0) {
        tevent_req_error(req, ENOENT);
        return;
    }

    tevent_req_done(req);
}

static void sdap_search_user_copy_batch(struct sdap_search_user_state *state,
                                        struct sysdb_attrs **users,
                                        size_t count)
{
    size_t copied;
    bool filter;

    /* Always copy all objects for wildcard lookups. */
    filter = state->lookup_type == SDAP_LOOKUP_SINGLE ? true : false;

    copied = sdap_steal_objects_in_dom(state->opts,
                                       state->users,
                                       state->count,
                                       state->dom,
                                       users, count, filter);

    state->count += copied;
    state->users[state->count] = NULL;
}

int sdap_search_user_recv(TALLOC_CTX *memctx, struct tevent_req *req,
                          char **higher_usn, struct sysdb_attrs ***users,
                          size_t *count)
{
    struct sdap_search_user_state *state = tevent_req_data(req,
                                            struct sdap_search_user_state);

    if (higher_usn) {
        *higher_usn = talloc_steal(memctx, state->higher_usn);
    }

    if (users) {
        *users = talloc_steal(memctx, state->users);
    }

    if (count) {
        *count = state->count;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

/* ==Search-And-Save-Users-with-filter============================================= */
struct sdap_get_users_state {
    struct sysdb_ctx *sysdb;
    struct sdap_options *opts;
    struct sss_domain_info *dom;
    const char *filter;

    char *higher_usn;
    struct sysdb_attrs **users;
    struct sysdb_attrs *mapped_attrs;
    size_t count;
};

static void sdap_get_users_done(struct tevent_req *subreq);

struct tevent_req *sdap_get_users_send(TALLOC_CTX *memctx,
                                       struct tevent_context *ev,
                                       struct sss_domain_info *dom,
                                       struct sysdb_ctx *sysdb,
                                       struct sdap_options *opts,
                                       struct sdap_search_base **search_bases,
                                       struct sdap_handle *sh,
                                       const char **attrs,
                                       const char *filter,
                                       int timeout,
                                       enum sdap_entry_lookup_type lookup_type,
                                       struct sysdb_attrs *mapped_attrs)
{
    errno_t ret;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct sdap_get_users_state *state;

    req = tevent_req_create(memctx, &state, struct sdap_get_users_state);
    if (!req) return NULL;

    state->sysdb = sysdb;
    state->opts = opts;
    state->dom = dom;

    state->filter = filter;
    PROBE(SDAP_SEARCH_USER_SEND, state->filter);

    if (mapped_attrs == NULL) {
        state->mapped_attrs = NULL;
    } else {
        state->mapped_attrs = sysdb_new_attrs(state);
        if (state->mapped_attrs == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_new_attrs failed.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = sysdb_attrs_copy(mapped_attrs, state->mapped_attrs);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_copy failed.\n");
            goto done;
        }
    }

    subreq = sdap_search_user_send(state, ev, dom, opts, search_bases,
                                   sh, attrs, filter, timeout, lookup_type);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }
    tevent_req_set_callback(subreq, sdap_get_users_done, req);

    ret = EOK;
done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void sdap_get_users_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_users_state *state = tevent_req_data(req,
                                            struct sdap_get_users_state);
    int ret;

    ret = sdap_search_user_recv(state, subreq, &state->higher_usn,
                                &state->users, &state->count);
    if (ret) {
        if (ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to retrieve users [%d][%s].\n",
                  ret, sss_strerror(ret));
        }
        tevent_req_error(req, ret);
        return;
    }

    PROBE(SDAP_SEARCH_USER_SAVE_BEGIN, state->filter);

    ret = sdap_save_users(state, state->sysdb,
                          state->dom, state->opts,
                          state->users, state->count,
                          state->mapped_attrs,
                          &state->higher_usn);
    PROBE(SDAP_SEARCH_USER_SAVE_END, state->filter);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to store users [%d][%s].\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_ALL, "Saving %zu Users - Done\n", state->count);

    tevent_req_done(req);
}

int sdap_get_users_recv(struct tevent_req *req,
                        TALLOC_CTX *mem_ctx, char **usn_value)
{
    struct sdap_get_users_state *state = tevent_req_data(req,
                                            struct sdap_get_users_state);

    PROBE(SDAP_SEARCH_USER_RECV, state->filter);
    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (usn_value) {
        *usn_value = talloc_steal(mem_ctx, state->higher_usn);
    }

    return EOK;
}

/* ==Fetch-Fallback-local-user============================================ */

errno_t sdap_fallback_local_user(TALLOC_CTX *memctx,
                                 const char *name, uid_t uid,
                                 struct sysdb_attrs ***reply)
{
    struct sysdb_attrs **ua;
    struct sysdb_attrs *user;
    struct passwd *pwd;
    int ret;

    if (name) {
        pwd = getpwnam(name);
    } else {
        pwd = getpwuid(uid);
    }

    if (!pwd) {
        return errno ? errno : ENOENT;
    }

    ua = talloc_array(memctx, struct sysdb_attrs *, 2);
    if (!ua) {
        ret = ENOMEM;
        goto done;
    }
    ua[1] = NULL;

    user = sysdb_new_attrs(ua);
    if (!user) {
        ret = ENOMEM;
        goto done;
    }
    ua[0] = user;

    ret = sysdb_attrs_add_string(user, SYSDB_NAME, pwd->pw_name);
    if (ret != EOK) {
        goto done;
    }

    if (pwd->pw_passwd) {
        ret = sysdb_attrs_add_string(user, SYSDB_PWD, pwd->pw_passwd);
        if (ret != EOK) {
            goto done;
        }
    }

    ret = sysdb_attrs_add_long(user, SYSDB_UIDNUM, (long)pwd->pw_uid);
    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_attrs_add_long(user, SYSDB_GIDNUM, (long)pwd->pw_gid);
    if (ret != EOK) {
        goto done;
    }

    if (pwd->pw_gecos && *pwd->pw_gecos) {
        ret = sysdb_attrs_add_string(user, SYSDB_GECOS, pwd->pw_gecos);
        if (ret != EOK) {
            goto done;
        }
    }

    if (pwd->pw_dir && *pwd->pw_dir) {
        ret = sysdb_attrs_add_string(user, SYSDB_HOMEDIR, pwd->pw_dir);
        if (ret != EOK) {
            goto done;
        }
    }

    if (pwd->pw_shell && *pwd->pw_shell) {
        ret = sysdb_attrs_add_string(user, SYSDB_SHELL, pwd->pw_shell);
        if (ret != EOK) {
            goto done;
        }
    }

done:
    if (ret != EOK) {
        talloc_free(ua);
    } else {
        *reply = ua;
    }

    return ret;
}
