/*
    SSSD

    SELinux-related utility functions

    Authors:
        Jan Zeleny <jzeleny@redhat.com>

    Copyright (C) 2012 Red Hat

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

#include "util/sss_selinux.h"
#include "util/sss_utf8.h"
#include "db/sysdb_selinux.h"

static bool match_entity(struct ldb_message_element *values,
                         struct ldb_message_element *sought_values)
{
    int i, j;

    for (i = 0; i < values->num_values; i++) {
        for (j = 0; j < sought_values->num_values; j++) {
            if (values->values[i].length != sought_values->values[j].length) {
                continue;
            }

            if (strncasecmp((char *)values->values[i].data,
                            (char *)sought_values->values[j].data,
                            values->values[i].length) == 0)
                return true;
        }
    }

    return false;
}

bool sss_selinux_match(struct sysdb_attrs *usermap,
                       struct sysdb_attrs *user,
                       struct sysdb_attrs *host,
                       uint32_t *_priority)
{
    struct ldb_message_element *users_el = NULL;
    struct ldb_message_element *usercat = NULL;
    struct ldb_message_element *hosts_el = NULL;
    struct ldb_message_element *hostcat = NULL;
    struct ldb_message_element *dn;
    struct ldb_message_element *memberof;
    int i;
    uint32_t priority = 0;
    bool matched_name;
    bool matched_group;
    bool matched_category;
    errno_t ret;

    if (usermap == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE, "NULL given as usermap! Skipping ...\n");
        return false;
    }

    /* Search for user and host related elements */
    for (i = 0; i < usermap->num; i++) {
        if (!strcasecmp(usermap->a[i].name, SYSDB_ORIG_MEMBER_USER)) {
            users_el = &usermap->a[i];
        } else if (!strcasecmp(usermap->a[i].name, SYSDB_ORIG_MEMBER_HOST)) {
            hosts_el = &usermap->a[i];
        } else if (!strcasecmp(usermap->a[i].name, SYSDB_USER_CATEGORY)) {
            usercat = &usermap->a[i];
        } else if (!strcasecmp(usermap->a[i].name, SYSDB_HOST_CATEGORY)) {
            hostcat = &usermap->a[i];
        }
    }

    if (user) {
        ret = sysdb_attrs_get_el(user, SYSDB_ORIG_DN, &dn);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "User does not have origDN\n");
            return false;
        }
        ret = sysdb_attrs_get_el(user, SYSDB_ORIG_MEMBEROF, &memberof);
        if (ret != EOK) {
            DEBUG(SSSDBG_TRACE_ALL,
                  "User does not have orig memberof, "
                   "therefore it can't match to any rule\n");
            return false;
        }

        /**
         * The rule won't match if user category != "all" and user map doesn't
         * contain neither user nor any of his groups in memberUser attribute
         */
        matched_category = false;
        if (usercat != NULL) {
            for (i = 0; i < usercat->num_values; i++) {
                if (strcasecmp((char *)usercat->values[i].data, "all") == 0) {
                    matched_category = true;
                    break;
                }
            }
        }

        if (!matched_category) {
            if (users_el == NULL) {
                DEBUG(SSSDBG_TRACE_ALL, "No users specified in the rule!\n");
                return false;
            } else {
                matched_name = match_entity(users_el, dn);
                matched_group = match_entity(users_el, memberof);
                if (matched_name) {
                    priority |= SELINUX_PRIORITY_USER_NAME;
                } else if (matched_group) {
                    priority |= SELINUX_PRIORITY_USER_GROUP;
                } else {
                    DEBUG(SSSDBG_TRACE_ALL, "User did not match\n");
                    return false;
                }
            }
        } else {
            priority |= SELINUX_PRIORITY_USER_CAT;
        }
    }

    if (host) {
        ret = sysdb_attrs_get_el(host, SYSDB_ORIG_DN, &dn);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Host does not have origDN\n");
            return false;
        }
        ret = sysdb_attrs_get_el(host, SYSDB_ORIG_MEMBEROF, &memberof);
        if (ret != EOK) {
            DEBUG(SSSDBG_TRACE_ALL,
                  "Host does not have orig memberof, "
                   "therefore it can't match to any rule\n");
            return false;
        }

        /**
         * The rule won't match if host category != "all" and user map doesn't
         * contain neither host nor any of its groups in memberHost attribute
         */
        matched_category = false;
        if (hostcat != NULL) {
            for (i = 0; i < hostcat->num_values; i++) {
                if (strcasecmp((char *)hostcat->values[i].data, "all") == 0) {
                    matched_category = true;
                    break;
                }
            }
        }
        if (!matched_category) {
            if (hosts_el == NULL) {
                DEBUG(SSSDBG_TRACE_ALL, "No users specified in the rule!\n");
                return false;
            } else {
                matched_name = match_entity(hosts_el, dn);
                matched_group = match_entity(hosts_el, memberof);
                if (matched_name) {
                    priority |= SELINUX_PRIORITY_HOST_NAME;
                } else if (matched_group) {
                    priority |= SELINUX_PRIORITY_HOST_GROUP;
                } else {
                    DEBUG(SSSDBG_TRACE_ALL, "Host did not match\n");
                    return false;
                }
            }
        } else {
            priority |= SELINUX_PRIORITY_HOST_CAT;
        }
    }

    if (_priority != NULL) {
        *_priority = priority;
    }

    return true;
}

errno_t sss_selinux_extract_user(TALLOC_CTX *mem_ctx,
                                 struct sss_domain_info *domain,
                                 const char *username,
                                 struct sysdb_attrs **_user_attrs)
{
    TALLOC_CTX *tmp_ctx;
    const char **attrs;
    struct sysdb_attrs *user_attrs;
    struct ldb_message *user_msg;

    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    attrs = talloc_array(tmp_ctx, const char *, 3);
    if (attrs == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_array failed.\n");
        ret = ENOMEM;
        goto done;
    }
    attrs[0] = SYSDB_ORIG_DN;
    attrs[1] = SYSDB_ORIG_MEMBEROF;
    attrs[2] = NULL;

    ret = sysdb_search_user_by_name(tmp_ctx, domain, username, attrs,
                                    &user_msg);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_search_user_by_name failed.\n");
        goto done;
    }

    user_attrs = talloc_zero(tmp_ctx, struct sysdb_attrs);
    if (user_attrs == NULL) {
        ret = ENOMEM;
        goto done;
    }
    user_attrs->a = talloc_steal(user_attrs, user_msg->elements);
    user_attrs->num = user_msg->num_elements;

    *_user_attrs = talloc_steal(mem_ctx, user_attrs);
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

const char *sss_selinux_map_get_seuser(struct sysdb_attrs *usermap)
{
    int i;
    const uint8_t *name;
    const uint8_t *template = (const uint8_t *)SYSDB_SELINUX_USER;

    for (i = 0; i < usermap->num; i++) {
        name = (const uint8_t *)usermap->a[i].name;
        if (sss_utf8_case_eq(name, template) == 0) {
            return (const char *)usermap->a[i].values[0].data;
        }
    }

    return NULL;
}
