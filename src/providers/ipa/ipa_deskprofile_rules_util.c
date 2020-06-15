/*
    SSSD

    Authors:
        Fabiano Fidêncio <fidencio@redhat.com>

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

#include "providers/ipa/ipa_deskprofile_rules_util.h"
#include "providers/ipa/ipa_deskprofile_private.h"
#include "providers/ipa/ipa_rules_common.h"
#include <ctype.h>
#include <fcntl.h>

#define DESKPROFILE_GLOBAL_POLICY_MIN_VALUE 1
#define DESKPROFILE_GLOBAL_POLICY_MAX_VALUE 24

enum deskprofile_name {
    RULES_DIR = 0,
    DOMAIN,
    USERNAME,
    PRIORITY,
    USER,
    GROUP,
    HOST,
    HOSTGROUP,
    RULE_NAME,
    EXTENSION,
    DESKPROFILE_NAME_SENTINEL
};

/*
 * The rule's filename has to follow a global policy, used by FleetCommander
 * client that shows how the profile should be applied.
 *
 * This global policy is represented by an integer from 1 to 24 (inclusive) and
 * has the following meaning:
 *  1 = user, group, host, hostgroup
 *  2 = user, group, hostgroup, host
 *  3 = user, host, group, hostgroup
 *  4 = user, host, hostgroup, group
 *  5 = user, hostgroup, group, host
 *  6 = user, hostgroup, host, group
 *  7 = group, user, host, hostgroup
 *  8 = group, user, hostgroup, host
 *  9 = group, host, user, hostgroup
 * 10 = group, host, hostgroup, user
 * 11 = group, hostgroup, user, host
 * 12 = group, hostgroup, host, user
 * 13 = host, user, group, hostgroup
 * 14 = host, user, hostgroup, group
 * 15 = host, group, user, hostgroup
 * 16 = host, group, hostgroup, user
 * 17 = host, hostgroup, user, group
 * 18 = host, hostgroup, group, user
 * 19 = hostgroup, user, group, host
 * 20 = hostgroup, user, host, group
 * 21 = hostgroup, group, user, host
 * 22 = hostgroup, group, host, user
 * 23 = hostgroup, host, user, group
 * 24 = hostgroup, host, group, user
 *
 * Having the table above in mind and considering the following example:
 * - rule name: testrule
 * - policy: 22
 * - priority: 420
 * - client's machine matches: host and group
 *
 * So, the filename will be: "000420_000000_000420_000420_000000_testrule.json"
 *
 * The function below not only helps us to create this filename in the correct
 * format, but also create the whole path for this rule's file.
 *
 * An example of the full path would be:
 * "/var/lib/sss/deskprofile/ipa.example/user_foobar/000420_000000_000420_000420_000000_testrule.json"
 *  |       RULES DIR       |   DOMAIN  |  USERNAME |      |      |GROUP | HOST | USER |        |
 *                                                  PRIORITY                            RULE NAME
 *                                                         HOSTGROUP                            EXTENSION
 *
 * In case a element has to be added/remove, please, remember to update:
 * - deskprofile_name enum;
 * - permuts's matrix;
 * - vals array;
 */
errno_t
ipa_deskprofile_get_filename_path(TALLOC_CTX *mem_ctx,
                                  uint16_t config_priority,
                                  const char *rules_dir,
                                  const char *domain,
                                  const char *username,
                                  const char *priority,
                                  const char *user_priority,
                                  const char *group_priority,
                                  const char *host_priority,
                                  const char *hostgroup_priority,
                                  const char *rule_name,
                                  const char *extension,
                                  char **_filename_path)
{
    TALLOC_CTX *tmp_ctx;
    static const uint8_t permuts[][DESKPROFILE_NAME_SENTINEL] = {
        {RULES_DIR, DOMAIN, USERNAME, PRIORITY, USER, GROUP, HOST, HOSTGROUP, RULE_NAME, EXTENSION},
        {RULES_DIR, DOMAIN, USERNAME, PRIORITY, USER, GROUP, HOSTGROUP, HOST, RULE_NAME, EXTENSION},
        {RULES_DIR, DOMAIN, USERNAME, PRIORITY, USER, HOST, GROUP, HOSTGROUP, RULE_NAME, EXTENSION},
        {RULES_DIR, DOMAIN, USERNAME, PRIORITY, USER, HOST, HOSTGROUP, GROUP, RULE_NAME, EXTENSION},
        {RULES_DIR, DOMAIN, USERNAME, PRIORITY, USER, HOSTGROUP, GROUP, HOST, RULE_NAME, EXTENSION},
        {RULES_DIR, DOMAIN, USERNAME, PRIORITY, USER, HOSTGROUP, HOST, GROUP, RULE_NAME, EXTENSION},
        {RULES_DIR, DOMAIN, USERNAME, PRIORITY, GROUP, USER, HOST, HOSTGROUP, RULE_NAME, EXTENSION},
        {RULES_DIR, DOMAIN, USERNAME, PRIORITY, GROUP, USER, HOSTGROUP, HOST, RULE_NAME, EXTENSION},
        {RULES_DIR, DOMAIN, USERNAME, PRIORITY, GROUP, HOST, USER, HOSTGROUP, RULE_NAME, EXTENSION},
        {RULES_DIR, DOMAIN, USERNAME, PRIORITY, GROUP, HOST, HOSTGROUP, USER, RULE_NAME, EXTENSION},
        {RULES_DIR, DOMAIN, USERNAME, PRIORITY, GROUP, HOSTGROUP, USER, HOST, RULE_NAME, EXTENSION},
        {RULES_DIR, DOMAIN, USERNAME, PRIORITY, GROUP, HOSTGROUP, HOST, USER, RULE_NAME, EXTENSION},
        {RULES_DIR, DOMAIN, USERNAME, PRIORITY, HOST, USER, GROUP, HOSTGROUP, RULE_NAME, EXTENSION},
        {RULES_DIR, DOMAIN, USERNAME, PRIORITY, HOST, USER, HOSTGROUP, GROUP, RULE_NAME, EXTENSION},
        {RULES_DIR, DOMAIN, USERNAME, PRIORITY, HOST, GROUP, USER, HOSTGROUP, RULE_NAME, EXTENSION},
        {RULES_DIR, DOMAIN, USERNAME, PRIORITY, HOST, GROUP, HOSTGROUP, USER, RULE_NAME, EXTENSION},
        {RULES_DIR, DOMAIN, USERNAME, PRIORITY, HOST, HOSTGROUP, USER, GROUP, RULE_NAME, EXTENSION},
        {RULES_DIR, DOMAIN, USERNAME, PRIORITY, HOST, HOSTGROUP, GROUP, USER, RULE_NAME, EXTENSION},
        {RULES_DIR, DOMAIN, USERNAME, PRIORITY, HOSTGROUP, USER, GROUP, HOST, RULE_NAME, EXTENSION},
        {RULES_DIR, DOMAIN, USERNAME, PRIORITY, HOSTGROUP, USER, HOST, GROUP, RULE_NAME, EXTENSION},
        {RULES_DIR, DOMAIN, USERNAME, PRIORITY, HOSTGROUP, GROUP, USER, HOST, RULE_NAME, EXTENSION},
        {RULES_DIR, DOMAIN, USERNAME, PRIORITY, HOSTGROUP, GROUP, HOST, USER, RULE_NAME, EXTENSION},
        {RULES_DIR, DOMAIN, USERNAME, PRIORITY, HOSTGROUP, HOST, USER, GROUP, RULE_NAME, EXTENSION},
        {RULES_DIR, DOMAIN, USERNAME, PRIORITY, HOSTGROUP, HOST, GROUP, USER, RULE_NAME, EXTENSION},
    };
    const char *vals[] = {
        rules_dir,
        domain,
        username,
        priority,
        user_priority,
        group_priority,
        host_priority,
        hostgroup_priority,
        rule_name,
        extension,
        NULL,
    };
    const uint8_t *perms;
    char *result;
    errno_t ret;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    if (config_priority < DESKPROFILE_GLOBAL_POLICY_MIN_VALUE ||
        config_priority > DESKPROFILE_GLOBAL_POLICY_MAX_VALUE) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "The configuration priority has an invalid value: %d!\n",
              config_priority);
        ret = EINVAL;
        goto done;
    }

    perms = permuts[config_priority - 1];

    result = talloc_strdup(tmp_ctx, "");
    if (result == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (int i = 0; i < DESKPROFILE_NAME_SENTINEL; i++) {
        switch(perms[i]) {
            case RULES_DIR:
            case DOMAIN:
            case USERNAME:
                result = talloc_asprintf_append(result, "%s/", vals[perms[i]]);
                break;
            case PRIORITY:
            case USER:
            case GROUP:
            case HOST:
            case HOSTGROUP:
                result = talloc_asprintf_append(result, "%s_", vals[perms[i]]);
                break;
            case RULE_NAME:
                result = talloc_asprintf_append(result, "%s", vals[perms[i]]);
                break;
            case EXTENSION:
                result = talloc_asprintf_append(result, ".%s", vals[perms[i]]);
                break;
            default:
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "This situation should never happen\n");
                ret = EINVAL;
                goto done;
        }

        if (result == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    *_filename_path = talloc_steal(mem_ctx, result);
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
ipa_deskprofile_rules_create_user_dir(
                                    const char *username, /* fully-qualified */
                                    uid_t uid,
                                    gid_t gid)
{
    TALLOC_CTX *tmp_ctx;
    char *shortname;
    char *domain;
    char *domain_dir;
    errno_t ret;
    mode_t old_umask;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sss_parse_internal_fqname(tmp_ctx, username, &shortname, &domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sss_parse_internal_fqname() failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    old_umask = umask(0026);
    ret = sss_create_dir(IPA_DESKPROFILE_RULES_USER_DIR, domain, 0751,
                         getuid(), getgid());
    umask(old_umask);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to create the directory \"%s/%s\" that would be used to "
              "store the Desktop Profile rules users' directory [%d]: %s\n",
              IPA_DESKPROFILE_RULES_USER_DIR, domain,
              ret, sss_strerror(ret));
        goto done;
    }

    domain_dir = talloc_asprintf(tmp_ctx, IPA_DESKPROFILE_RULES_USER_DIR"/%s",
                                 domain);
    if (domain_dir == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* In order to read, create and traverse the directory, we need to have its
     * permissions set as 'rwx------' (700). */
    old_umask = umask(0077);
    ret = sss_create_dir(domain_dir, shortname, 0700, uid, gid);
    umask(old_umask);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
               "Failed to create the directory \"%s/%s/%s\" that would be used "
               "to store the Desktop Profile rules for the user \"%s\" [%d]: "
               "%s\n",
               IPA_DESKPROFILE_RULES_USER_DIR, domain, shortname, username,
               ret, sss_strerror(ret));
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
ipa_deskprofile_get_normalized_rule_name(TALLOC_CTX *mem_ctx,
                                         const char *name,
                                         char **_rule_name)
{
    char buffer[PATH_MAX];
    size_t buffer_len;
    size_t name_len;

    name_len = strlen(name);
    buffer_len = 0;
    for (size_t i = 0; i < name_len; i++) {
        char character;
        bool replace;

        character = name[i];
        replace = false;

        if (isalnum(character) == 0) {
            char next_character;

            next_character = name[i+1];
            if (i + 1 >= name_len || isalnum(next_character) == 0) {
                continue;
            }

            replace = true;
        }

        buffer[buffer_len] = replace ? '_' : character;
        buffer_len++;
    }
    buffer[buffer_len] = '\0';

    *_rule_name = talloc_strdup(mem_ctx, buffer);
    if (*_rule_name == NULL) {
        return ENOMEM;
    }

    return EOK;
}

static errno_t
ipa_deskprofile_rule_check_memberuser(
                                    TALLOC_CTX *mem_ctx,
                                    struct sss_domain_info *domain,
                                    struct sysdb_attrs *rule,
                                    const char *rule_name,
                                    const char *rule_prio,
                                    const char *base_dn,
                                    const char *username, /* fully-qualified */
                                    char **_user_prio,
                                    char **_group_prio)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_message_element *el;
    struct ldb_result *res;
    size_t num_groups;
    char **groups = NULL;
    const char *fqgroupname = NULL;
    char *groupname = NULL;
    char *shortname;
    char *domainname;
    char *data;
    char *memberuser;
    char *membergroup;
    char *user_prio;
    char *group_prio;
    bool user = false;
    bool group = false;
    errno_t ret;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sss_parse_internal_fqname(tmp_ctx, username,
                                    &shortname, &domainname);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sss_parse_internal_fqname() failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = sysdb_initgroups(tmp_ctx, domain, username, &res);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sysdb_initgroups() failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    if (res->count == 0) {
        /* This really should NOT happen at this point */
        DEBUG(SSSDBG_MINOR_FAILURE,
              "User [%s] not found in cache\n", username);
        ret = ENOENT;
        goto done;
    }

    groups = talloc_array(tmp_ctx, char *, res->count);
    if (groups == NULL) {
        ret = ENOMEM;
        goto done;
    }

    num_groups = 0;
    /* Start counting from 1 to exclude the user entry */
    for (size_t i = 1; i < res->count; i++) {
        fqgroupname = ldb_msg_find_attr_as_string(res->msgs[i],
                                                  SYSDB_NAME,
                                                  NULL);
        if (fqgroupname == NULL) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Skipping malformed entry [%s]\n",
                  ldb_dn_get_linearized(res->msgs[i]->dn));
            continue;
        }

        ret = sss_parse_internal_fqname(tmp_ctx, fqgroupname,
                                        &groupname, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Malformed name %s, skipping!\n", fqgroupname);
            continue;
        }

        groups[num_groups] = groupname;
        num_groups++;
    }
    groups[num_groups] = NULL;

    ret = sysdb_attrs_get_el(rule, IPA_MEMBER_USER, &el);
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Failed to get the Desktop Profile Rule memberUser for rule "
              "\"%s\" [%d]: %s\n",
              rule_name, ret, sss_strerror(ret));

        goto done;
    }

    memberuser = talloc_asprintf(tmp_ctx, "uid=%s,cn=users,cn=accounts,%s",
                                 shortname, base_dn);
    if (memberuser == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to allocate memberuser\n");
        ret = ENOMEM;
        goto done;
    }

    for (size_t i = 0; i < el->num_values; i++) {
        if (user && group) {
            break;
        }

        data = (char *)el->values[i].data;

        if (!user && data != NULL && strcmp(memberuser, data) == 0) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "Desktop Profile rule \"%s\" matches with the user \"%s\" "
                  "for the \"%s\" domain!\n",
                  rule_name, shortname, domainname);
            user = true;
            continue;
        }

        if (!group && data != NULL) {
            for (size_t j = 0; !group && groups[j] != NULL; j++) {
                membergroup = talloc_asprintf(tmp_ctx,
                                              "cn=%s,cn=groups,cn=accounts,%s",
                                              groups[j], base_dn);
                if (membergroup == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Failed to allocate membergroup\n");
                    ret = ENOMEM;
                    goto done;
                }

                if (strcmp(membergroup, data) == 0) {
                    DEBUG(SSSDBG_TRACE_FUNC,
                          "Desktop Profile rule \"%s\" matches with (at least) "
                          "the group \"%s\" for the \"%s\" domain!\n",
                          rule_name, groups[j], domainname);
                    group = true;
                }
            }
        }
    }

    user_prio = user ? talloc_strdup(tmp_ctx, rule_prio) :
                       talloc_asprintf(tmp_ctx, "%06d", 0);
    if (user_prio == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to allocate the user priority\n");
        ret = ENOMEM;
        goto done;
    }

    group_prio = group ? talloc_strdup(tmp_ctx, rule_prio) :
                         talloc_asprintf(tmp_ctx, "%06d", 0);
    if (group_prio == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to allocate the group priority\n");
        ret = ENOMEM;
        goto done;
    }

    *_user_prio = talloc_steal(mem_ctx, user_prio);
    *_group_prio = talloc_steal(mem_ctx, group_prio);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
ipa_deskprofile_rule_check_memberhost(TALLOC_CTX *mem_ctx,
                                      struct sss_domain_info *domain,
                                      struct sysdb_attrs *rule,
                                      const char *rule_name,
                                      const char *rule_prio,
                                      const char *base_dn,
                                      const char *hostname,
                                      char **_host_prio,
                                      char **_hostgroup_prio)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *host_dn;
    struct ldb_message_element *el_orig_memberof = NULL;
    struct ldb_message_element *el = NULL;
    struct ldb_message **msgs;
    size_t count;
    size_t num_memberhostgroup;
    char **memberhostgroups = NULL;
    char *data;
    char *memberhost;
    char *memberhostgroup;
    char *name;
    char *host_prio;
    char *hostgroup_prio;
    const char *memberof_attrs[] = { SYSDB_ORIG_MEMBEROF, NULL };
    bool host = false;
    bool hostgroup = false;
    errno_t ret;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    host_dn = sysdb_custom_dn(tmp_ctx, domain, hostname,
                              DESKPROFILE_HOSTS_SUBDIR);
    if (host_dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_entry(tmp_ctx, domain->sysdb, host_dn,
                             LDB_SCOPE_BASE, NULL,
                             memberof_attrs,
                             &count, &msgs);
    if (ret == ENOENT || count == 0) {
        memberhostgroups = talloc_array(tmp_ctx, char *, 1);
        memberhostgroups[0] = NULL;
    } else if (ret != EOK) {
        goto done;
    } else if (count > 1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "More than one result for a BASE search!\n");
        ret = EIO;
        goto done;
    } else { /* ret == EOK && count == 1 */
        el_orig_memberof = ldb_msg_find_element(msgs[0], SYSDB_ORIG_MEMBEROF);
        memberhostgroups = talloc_array(tmp_ctx,
                                        char *,
                                        el_orig_memberof->num_values);
    }

    if (el_orig_memberof != NULL) {
        num_memberhostgroup = 0;
        for (size_t i = 0; i < el_orig_memberof->num_values; i++) {
            data = (char *)el_orig_memberof->values[i].data;

            ret = ipa_common_get_hostgroupname(tmp_ctx, domain->sysdb, data,
                                               &name);

            /* ERR_UNEXPECTED_ENTRY_TYPE means we had a memberOf entry that
             * wasn't a host group, thus we'll just ignore those.
             */
            if (ret != EOK && ret != ERR_UNEXPECTED_ENTRY_TYPE) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Skipping malformed entry [%s]\n",
                      data);
                continue;
            } else if (ret == EOK) {
                memberhostgroups[num_memberhostgroup] = name;
                num_memberhostgroup++;
            }
        }
        memberhostgroups[num_memberhostgroup] = NULL;
    }

    ret = sysdb_attrs_get_el(rule, IPA_MEMBER_HOST, &el);
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Failed to get the Desktop Profile Rule memberHost for rule "
              "\"%s\" [%d]: %s\n",
              rule_name, ret, sss_strerror(ret));

        goto done;
    }

    memberhost = talloc_asprintf(tmp_ctx, "fqdn=%s,cn=computers,cn=accounts,%s",
                                 hostname, base_dn);
    if (memberhost == NULL) {
        ret = ENOMEM;
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to allocate memberhost\n");
        goto done;
    }

    for (size_t i = 0; i < el->num_values; i++) {
        if (host && hostgroup) {
            break;
        }

        data = (char *)el->values[i].data;

        if (!host && data != NULL && strcmp(memberhost, data) == 0) {
            host = true;
            DEBUG(SSSDBG_TRACE_FUNC,
                  "Desktop Profile rule \"%s\" matches with the host \"%s\" "
                  "for the \"%s\" domain!\n",
                  rule_name, hostname, domain->name);
            continue;
        }

        if (!hostgroup && data != NULL) {
            for (size_t j = 0; !hostgroup && memberhostgroups[j] != NULL; j++) {
                memberhostgroup = talloc_asprintf(
                                        tmp_ctx,
                                        "cn=%s,cn=hostgroups,cn=accounts,%s",
                                        memberhostgroups[j], base_dn);

                if (memberhostgroup == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Failed to allocate memberhostgroup\n");
                    ret = ENOMEM;
                    goto done;
                }

                if (strcmp(memberhostgroup, data) == 0) {
                    hostgroup = true;
                    DEBUG(SSSDBG_TRACE_FUNC,
                          "Desktop Profile rule \"%s\" matches with (at least) "
                          "the hostgroup \"%s\" for the \"%s\" domain!\n",
                          rule_name, memberhostgroups[j], domain->name);
                    continue;
                }
            }
        }
    }

    host_prio = host ? talloc_strdup(tmp_ctx, rule_prio) :
                       talloc_asprintf(tmp_ctx, "%06d", 0);
    if (host_prio == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to allocate the host priority\n");
        ret = ENOMEM;
        goto done;
    }

    hostgroup_prio = hostgroup ? talloc_strdup(tmp_ctx, rule_prio) :
                                 talloc_asprintf(tmp_ctx, "%06d", 0);
    if (hostgroup_prio == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to allocate the hostgroup priority\n");
        ret = ENOMEM;
        goto done;
    }

    *_host_prio = talloc_steal(mem_ctx, host_prio);
    *_hostgroup_prio = talloc_steal(mem_ctx, hostgroup_prio);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}


errno_t
ipa_deskprofile_rules_save_rule_to_disk(
                                    TALLOC_CTX *mem_ctx,
                                    uint16_t priority,
                                    struct sysdb_attrs *rule,
                                    struct sss_domain_info *domain,
                                    const char *hostname,
                                    const char *username, /* fully-qualified */
                                    uid_t uid,
                                    gid_t gid)
{
    TALLOC_CTX *tmp_ctx;
    const char *rule_name;
    const char *data;
    const char *hostcat;
    const char *usercat;
    char *shortname;
    char *domainname;
    char *base_dn;
    char *rule_prio;
    char *user_prio;
    char *group_prio;
    char *host_prio;
    char *hostgroup_prio;
    char *normalized_rule_name = NULL;
    char *filename_path = NULL;
    const char *extension = "json";
    uint32_t prio;
    int fd = -1;
    gid_t orig_gid;
    uid_t orig_uid;
    errno_t ret;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    orig_gid = getegid();
    orig_uid = geteuid();

    ret = sysdb_attrs_get_string(rule, IPA_CN, &rule_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Failed to get the Desktop Profile Rule name [%d]: %s\n",
              ret, sss_strerror(ret));

        goto done;
    }

    ret = sysdb_attrs_get_uint32_t(rule, IPA_DESKPROFILE_PRIORITY, &prio);
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Failed to get the Desktop Profile Rule priority for rule "
              "\"%s\" [%d]: %s\n",
              rule_name, ret, sss_strerror(ret));
        goto done;
    }

    ret = sysdb_attrs_get_string(rule, IPA_HOST_CATEGORY, &hostcat);
    if (ret == ENOENT) {
        hostcat = NULL;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Failed to get the Desktop Profile Rule host category for rule "
              "\"%s\" [%d]: %s\n",
              rule_name, ret, sss_strerror(ret));
        goto done;
    }

    ret = sysdb_attrs_get_string(rule, IPA_USER_CATEGORY, &usercat);
    if (ret == ENOENT) {
        usercat = NULL;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Failed to get the Desktop Profile Rule user category for rule "
              "\"%s\" [%d]: %s\n",
              rule_name, ret, sss_strerror(ret));
        goto done;
    }

    rule_prio = talloc_asprintf(tmp_ctx, "%06d", prio);
    if (rule_prio == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to allocate rule priority\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_attrs_get_string(rule, IPA_DESKPROFILE_DATA, &data);
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Failed to get the Desktop Profile Rule data for rule \"%s\" "
              "[%d]: %s\n",
              rule_name, ret, sss_strerror(ret));
        goto done;
    }

    ret = sss_parse_internal_fqname(tmp_ctx, username, &shortname, &domainname);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sss_parse_internal_fqname() failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = domain_to_basedn(tmp_ctx, domainname, &base_dn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "domain_to_basedn() failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    if (usercat != NULL && strcasecmp(usercat, "all") == 0) {
        user_prio = talloc_strdup(tmp_ctx, rule_prio);
        if (user_prio == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to allocate the user priority "
                  "when user category is \"all\"\n");
            ret = ENOMEM;
            goto done;
        }

        group_prio = talloc_strdup(tmp_ctx, rule_prio);
        if (group_prio == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to allocate the group priority "
                  "when user category is \"all\"\n");
            ret = ENOMEM;
            goto done;
        }
    } else {
        ret = ipa_deskprofile_rule_check_memberuser(tmp_ctx, domain, rule,
                                                    rule_name, rule_prio,
                                                    base_dn, username,
                                                    &user_prio, &group_prio);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "ipa_deskprofile_rule_check_memberuser() failed [%d]: %s\n",
                  ret, sss_strerror(ret));
            goto done;
        }
    }

    if (hostcat != NULL && strcasecmp(hostcat, "all") == 0) {
        host_prio = talloc_strdup(tmp_ctx, rule_prio);
        if (host_prio == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to allocate the host priority "
                  "when host category is \"all\"\n");
            ret = ENOMEM;
            goto done;
        }

        hostgroup_prio = talloc_strdup(tmp_ctx, rule_prio);
        if (hostgroup_prio == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to allocate the hostgroup priority "
                  "when host category is \"all\"\n");
            ret = ENOMEM;
            goto done;
        }
    } else {
        ret = ipa_deskprofile_rule_check_memberhost(tmp_ctx, domain, rule,
                                                    rule_name, rule_prio,
                                                    base_dn, hostname,
                                                    &host_prio, &hostgroup_prio);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "ipa_deskprofile_rule_check_memberhost() failed [%d]: %s\n",
                  ret, sss_strerror(ret));
            goto done;
        }
    }

    ret = ipa_deskprofile_get_normalized_rule_name(mem_ctx, rule_name,
                                                   &normalized_rule_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "ipa_deskprofile_get_normalized_rule_name() failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = ipa_deskprofile_get_filename_path(tmp_ctx,
                                            priority,
                                            IPA_DESKPROFILE_RULES_USER_DIR,
                                            domainname,
                                            shortname,
                                            rule_prio,
                                            user_prio,
                                            group_prio,
                                            host_prio,
                                            hostgroup_prio,
                                            normalized_rule_name,
                                            extension,
                                            &filename_path);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "ipa_deskprofile_get_filename_path() failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = setegid(gid);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unable to set effective group id (%"PRIu32") of the domain's "
              "process [%d]: %s\n",
              gid, ret, sss_strerror(ret));
        goto done;
    }

    ret = seteuid(uid);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unable to set effective user id (%"PRIu32") of the domain's "
              "process [%d]: %s\n",
              uid, ret, sss_strerror(ret));
        goto done;
    }

    fd = open(filename_path, O_WRONLY | O_CREAT | O_TRUNC, 0400);
    if (fd == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to create the Desktop Profile rule file \"%s\" "
              "[%d]: %s\n",
              filename_path, ret, sss_strerror(ret));
        goto done;
    }

    ret = dprintf(fd, "%s", data);
    if (ret < 0) {
        ret = EIO;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to write the content of the Desktop Profile rule for "
              "the \"%s\" file.\n",
              filename_path);
        goto done;
    }

    ret = seteuid(orig_uid);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to set the effect user id (%"PRIu32") of the domain's "
              "process [%d]: %s\n",
              orig_uid, ret, sss_strerror(ret));
        goto done;
    }

    ret = setegid(orig_gid);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to set the effect group id (%"PRIu32") of the domain's "
              "process [%d]: %s\n",
              orig_gid, ret, sss_strerror(ret));
        goto done;
    }

    ret = EOK;

done:
    if (fd != -1) {
        close(fd);
    }
    if (geteuid() != orig_uid) {
        ret = seteuid(orig_uid);
        if (ret == -1) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unable to set effective user id (%"PRIu32") of the "
                  "domain's process [%d]: %s\n",
                  orig_uid, ret, sss_strerror(ret));
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Sending SIGUSR2 to the process: %d\n", getpid());
            kill(getpid(), SIGUSR2);
        }
    }
    if (getegid() != orig_gid) {
        ret = setegid(orig_gid);
        if (ret == -1) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unable to set effective group id (%"PRIu32") of the "
                  "domain's process. Let's have the process restarted!\n",
                  orig_gid);
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Sending SIGUSR2 to the process: %d\n", getpid());
            kill(getpid(), SIGUSR2);
        }
    }
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
ipa_deskprofile_rules_remove_user_dir(const char *user_dir,
                                      uid_t uid,
                                      gid_t gid)
{
    gid_t orig_gid;
    uid_t orig_uid;
    errno_t ret;

    orig_gid = getegid();
    orig_uid = geteuid();

    ret = setegid(gid);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unable to set effective group id (%"PRIu32") of the domain's "
              "process [%d]: %s\n",
              gid, ret, sss_strerror(ret));
        goto done;
    }

    ret = seteuid(uid);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unable to set effective user id (%"PRIu32") of the domain's "
              "process [%d]: %s\n",
              uid, ret, sss_strerror(ret));
        goto done;
    }

    ret = sss_remove_subtree(user_dir);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot remove \"%s\" directory [%d]: %s\n",
              user_dir, ret, sss_strerror(ret));
        goto done;
    }

    ret = seteuid(orig_uid);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to set the effect user id (%"PRIu32") of the domain's "
              "process [%d]: %s\n",
              orig_uid, ret, sss_strerror(ret));
        goto done;
    }

    ret = setegid(orig_gid);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to set the effect group id (%"PRIu32") of the domain's "
              "process [%d]: %s\n",
              orig_gid, ret, sss_strerror(ret));
        goto done;
    }

    ret = sss_remove_tree(user_dir);
    if ((ret != EOK) && (ret != ENOENT)) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot remove \"%s\" directory [%d]: %s\n",
              user_dir, ret, sss_strerror(ret));
        goto done;
    }

    ret = EOK;

done:
    if (geteuid() != orig_uid) {
        ret = seteuid(orig_uid);
        if (ret == -1) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "unable to set effective user id (%"PRIu32") of the "
                  "domain's process [%d]: %s\n",
                  orig_uid, ret, sss_strerror(ret));
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Sending SIGUSR2 to the process: %d\n", getpid());
            kill(getpid(), SIGUSR2);
        }
    }
    if (getegid() != orig_gid) {
        ret = setegid(orig_gid);
        if (ret == -1) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unable to set effective user id (%"PRIu32") of the "
                  "domain's process [%d]: %s\n",
                  orig_uid, ret, sss_strerror(ret));
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Sending SIGUSR2 to the process: %d\n", getpid());
            kill(getpid(), SIGUSR2);
        }
    }
    return ret;
}

errno_t
deskprofile_get_cached_priority(struct sss_domain_info *domain,
                                uint16_t *_priority)
{
    TALLOC_CTX *tmp_ctx;
    const char *attrs[] = { IPA_DESKPROFILE_PRIORITY, NULL };
    struct ldb_message **resp;
    size_t resp_count;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sysdb_search_custom_by_name(tmp_ctx,
                                      domain,
                                      IPA_DESKPROFILE_PRIORITY,
                                      DESKPROFILE_CONFIG_SUBDIR,
                                      attrs, &resp_count, &resp);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sysdb_search_custom_by_name() failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    if (resp_count != 1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sysdb_search_custom_by_name() got more attributes than "
              "expected. Expected (1), got (%zu)\n", resp_count);
        ret = EINVAL;
        goto done;
    }

    *_priority = ldb_msg_find_attr_as_uint(resp[0],
                                           IPA_DESKPROFILE_PRIORITY,
                                           0);
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

const char **
deskprofile_get_attrs_to_get_cached_rules(TALLOC_CTX *mem_ctx)
{
    const char **attrs = talloc_zero_array(mem_ctx, const char *, 11);
    if (attrs == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero_array() failed\n");
        goto done;
    }

    attrs[0] = OBJECTCLASS;
    attrs[1] = IPA_CN;
    attrs[2] = IPA_UNIQUE_ID;
    attrs[3] = IPA_ENABLED_FLAG;
    attrs[4] = IPA_MEMBER_USER;
    attrs[5] = IPA_USER_CATEGORY;
    attrs[6] = IPA_MEMBER_HOST;
    attrs[7] = IPA_HOST_CATEGORY;
    attrs[8] = IPA_DESKPROFILE_PRIORITY;
    attrs[9] = IPA_DESKPROFILE_DATA;
    attrs[10] = NULL;

done:
    return attrs;
}
