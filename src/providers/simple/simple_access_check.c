/*
   SSSD

   Simple access control

   Copyright (C) Sumit Bose <sbose@redhat.com> 2010

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

#include "providers/simple/simple_access.h"
#include "util/sss_utf8.h"
#include "db/sysdb.h"

errno_t simple_access_check(struct simple_ctx *ctx, const char *username,
                            bool *access_granted)
{
    int i, j;
    errno_t ret;
    TALLOC_CTX *tmp_ctx = NULL;
    const char *user_attrs[] = { SYSDB_MEMBEROF,
                                 SYSDB_GIDNUM,
                                 NULL };
    const char *group_attrs[] = { SYSDB_NAME,
                                  NULL };
    struct ldb_message *msg;
    struct ldb_message_element *el;
    char **groups;
    const char *primary_group;
    gid_t gid;
    bool matched;
    bool cs = ctx->domain->case_sensitive;

    *access_granted = false;

    /* First, check whether the user is in the allowed users list */
    if (ctx->allow_users != NULL) {
        for(i = 0; ctx->allow_users[i] != NULL; i++) {
            if (sss_string_equal(cs, username, ctx->allow_users[i])) {
                DEBUG(9, ("User [%s] found in allow list, access granted.\n",
                      username));

                /* Do not return immediately on explicit allow
                 * We need to make sure none of the user's groups
                 * are denied.
                 */
                *access_granted = true;
            }
        }
    } else if (!ctx->allow_groups) {
        /* If neither allow rule is in place, we'll assume allowed
         * unless a deny rule disables us below.
         */
        *access_granted = true;
    }

    /* Next check whether this user has been specifically denied */
    if (ctx->deny_users != NULL) {
        for(i = 0; ctx->deny_users[i] != NULL; i++) {
            if (sss_string_equal(cs, username, ctx->deny_users[i])) {
                DEBUG(9, ("User [%s] found in deny list, access denied.\n",
                      username));

                /* Return immediately on explicit denial */
                *access_granted = false;
                return EOK;
            }
        }
    }

    if (!ctx->allow_groups && !ctx->deny_groups) {
        /* There are no group restrictions, so just return
         * here with whatever we've decided.
         */
        return EOK;
    }

    /* Now get a list of this user's groups and check those against the
     * simple_allow_groups list.
     */
    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_user_by_name(tmp_ctx, ctx->domain->sysdb, ctx->domain,
                                    username, user_attrs, &msg);
    if (ret != EOK) {
        DEBUG(1, ("Could not look up username [%s]: [%d][%s]\n",
                  username, ret, strerror(ret)));
        goto done;
    }

    /* Construct a list of the user's groups */
    el = ldb_msg_find_element(msg, SYSDB_MEMBEROF);
    if (el && el->num_values) {
        /* Get the groups from the memberOf entries
         * Allocate the array with room for both the NULL
         * terminator and the primary group
         */
        groups = talloc_array(tmp_ctx, char *, el->num_values + 2);
        if (!groups) {
            ret = ENOMEM;
            goto done;
        }

        for (j = 0; j < el->num_values; j++) {
            ret = sysdb_group_dn_name(
                    ctx->domain->sysdb, tmp_ctx,
                    (char *)el->values[j].data,
                    &groups[j]);
            if (ret != EOK) {
                goto done;
            }
        }
    } else {
        /* User is not a member of any groups except primary */
        groups = talloc_array(tmp_ctx, char *, 2);
        if (!groups) {
            ret = ENOMEM;
            goto done;
        }
        j = 0;
    }

    /* Get the user's primary group */
    gid = ldb_msg_find_attr_as_uint64(msg, SYSDB_GIDNUM, 0);
    if (!gid) {
        ret = EINVAL;
        goto done;
    }
    talloc_zfree(msg);

    ret = sysdb_search_group_by_gid(tmp_ctx, ctx->domain->sysdb, ctx->domain,
                                    gid, group_attrs, &msg);
    if (ret != EOK) {
        DEBUG(1, ("Could not look up primary group [%lu]: [%d][%s]\n",
                  gid, ret, strerror(ret)));
        /* We have to treat this as non-fatal, because the primary
         * group may be local to the machine and not available in
         * our ID provider.
         */
    } else {
        primary_group = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
        if (!primary_group) {
            ret = EINVAL;
            goto done;
        }

        groups[j] = talloc_strdup(tmp_ctx, primary_group);
        if (!groups[j]) {
            ret = ENOMEM;
            goto done;
        }
        j++;

        talloc_zfree(msg);
    }

    groups[j] = NULL;

    /* Now process allow and deny group rules
     * If access was already granted above, we'll skip
     * this redundant rule check
     */
    if (ctx->allow_groups && !*access_granted) {
        matched = false;
        for (i = 0; ctx->allow_groups[i]; i++) {
            for(j = 0; groups[j]; j++) {
                if (sss_string_equal(cs, groups[j], ctx->allow_groups[i])) {
                    matched = true;
                    break;
                }
            }

            /* If any group has matched, we can skip out on the
             * processing early
             */
            if (matched) {
                *access_granted = true;
                break;
            }
        }
    }

    /* Finally, process the deny group rules */
    if (ctx->deny_groups) {
        matched = false;
        for (i = 0; ctx->deny_groups[i]; i++) {
            for(j = 0; groups[j]; j++) {
                if (sss_string_equal(cs, groups[j], ctx->deny_groups[i])) {
                    matched = true;
                    break;
                }
            }

            /* If any group has matched, we can skip out on the
             * processing early
             */
            if (matched) {
                *access_granted = false;
                break;
            }
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}
