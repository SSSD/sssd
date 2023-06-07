/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2015 Red Hat

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

#include <ldb.h>
#include <talloc.h>
#include <dhash.h>

#include "providers/ldap/sdap.h"
#include "providers/ipa/ipa_common.h"
#include "providers/ipa/ipa_dn.h"
#include "db/sysdb_sudo.h"
#include "db/sysdb.h"
#include "util/util.h"

#define SUDO_DN_CMDGROUPS "sudocmdgroups"
#define SUDO_DN_CMDS      "sudocmds"
#define SUDO_DN_CONTAINER "sudo"
#define SUDO_DN_CN        "cn"

#define MATCHDN(cat)      SUDO_DN_CN, (cat), SUDO_DN_CN, SUDO_DN_CONTAINER
#define MATCHDN_CMDGROUPS MATCHDN(SUDO_DN_CMDGROUPS)
#define MATCHDN_CMDS      MATCHDN(SUDO_DN_CMDS)

#define MATCHRDN_CMDGROUPS(map)  (map)[IPA_AT_SUDOCMDGROUP_NAME].name, MATCHDN_CMDGROUPS
#define MATCHRDN_CMDS(attr, map) (map)[attr].name, MATCHDN_CMDS

#define MATCHRDN_USER(map)      (map)[SDAP_AT_USER_NAME].name, "cn", "users", "cn", "accounts"
#define MATCHRDN_GROUP(map)     (map)[SDAP_AT_GROUP_NAME].name, "cn", "groups", "cn", "accounts"
#define MATCHRDN_HOST(map)      (map)[SDAP_AT_HOST_FQDN].name, "cn", "computers", "cn", "accounts"
#define MATCHRDN_HOSTGROUP(map) (map)[IPA_AT_HOSTGROUP_NAME].name, "cn", "hostgroups", "cn", "accounts"

struct ipa_sudo_conv {
    struct sss_domain_info *dom;

    struct sdap_attr_map *map_rule;
    struct sdap_attr_map *map_cmdgroup;
    struct sdap_attr_map *map_cmd;
    struct sdap_attr_map *map_user;
    struct sdap_attr_map *map_group;
    struct sdap_attr_map *map_host;
    struct sdap_attr_map *map_hostgroup;

    hash_table_t *rules;
    hash_table_t *cmdgroups;
    hash_table_t *cmds;
};

struct ipa_sudo_dn_list {
    struct ipa_sudo_dn_list *prev, *next;
    const char *dn;
};

struct ipa_sudo_rulemember {
    struct ipa_sudo_dn_list *cmdgroups;
    struct ipa_sudo_dn_list *cmds;
};

struct ipa_sudo_rule {
    struct sysdb_attrs *attrs;
    struct ipa_sudo_rulemember allow;
    struct ipa_sudo_rulemember deny;
};

struct ipa_sudo_cmdgroup {
    struct ipa_sudo_dn_list *cmds;
    const char **expanded;
};

static size_t
ipa_sudo_dn_list_count(struct ipa_sudo_dn_list *list)
{
    struct ipa_sudo_dn_list *item;
    size_t i;

    for (i = 0, item = list; item != NULL; item = item->next, i++) {
        /* no op */
    }

    return i;
}

static errno_t
ipa_sudo_conv_store(hash_table_t *table,
                    const char *key,
                    void *value)
{
    hash_key_t hkey;
    hash_value_t hvalue;
    int hret;

    if (table == NULL || key == NULL) {
        return EINVAL;
    }

    hkey.type = HASH_KEY_STRING;
    hkey.str = discard_const(key);

    /* If value is NULL we don't want to override existing entry. */
    if (value == NULL && hash_has_key(table, &hkey)) {
        return EEXIST;
    }

    hvalue.type = HASH_VALUE_PTR;
    hvalue.ptr = value;

    hret = hash_enter(table, &hkey, &hvalue);
    if (hret != HASH_SUCCESS) {
        return EIO;
    }

    if (value != NULL) {
        talloc_steal(table, value);
    }

    return EOK;
}

static void *
ipa_sudo_conv_lookup(hash_table_t *table,
                     const char *key)
{
    hash_key_t hkey;
    hash_value_t hvalue;
    int hret;

    hkey.type = HASH_KEY_STRING;
    hkey.str = discard_const(key);

    hret = hash_lookup(table, &hkey, &hvalue);
    if (hret == HASH_ERROR_KEY_NOT_FOUND) {
        DEBUG(SSSDBG_OP_FAILURE, "Key not found %s\n", key);
        return NULL;
    } else if (hret != HASH_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to lookup value [%d]\n", hret);
        return NULL;
    }

    return hvalue.ptr;
}

static errno_t
store_rulemember(TALLOC_CTX *mem_ctx,
                 struct ipa_sudo_dn_list **list,
                 hash_table_t *table,
                 const char *dn)
{
    struct ipa_sudo_dn_list *item;
    errno_t ret;

    item = talloc_zero(mem_ctx, struct ipa_sudo_dn_list);
    if (item == NULL) {
        return ENOMEM;
    }

    ret = ipa_sudo_conv_store(table, dn, NULL);
    if (ret != EOK && ret != EEXIST) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to store DN %s [%d]: %s\n",
              dn, ret, sss_strerror(ret));
        goto done;
    }

    item->dn = talloc_steal(item, dn);
    DLIST_ADD(*list, item);

done:
    if (ret != EOK && ret != EEXIST) {
        talloc_free(item);
    }

    return ret;
}

static bool is_ipacmdgroup(struct ipa_sudo_conv *conv, const char *dn)
{
    if (ipa_check_rdn_bool(conv->dom->sysdb, dn,
            MATCHRDN_CMDGROUPS(conv->map_cmdgroup))) {
        return true;
    }

    return false;
}

static bool is_ipacmd(struct ipa_sudo_conv *conv, const char *dn)
{
    if (ipa_check_rdn_bool(conv->dom->sysdb, dn,
            MATCHRDN_CMDS(IPA_AT_SUDOCMD_UUID, conv->map_cmd))) {
        return true;
    }

    /* For older versions of FreeIPA than 3.1. */
    if (ipa_check_rdn_bool(conv->dom->sysdb, dn,
            MATCHRDN_CMDS(IPA_AT_SUDOCMD_CMD, conv->map_cmd))) {
        return true;
    }

    return false;
}

static errno_t
process_rulemember(TALLOC_CTX *mem_ctx,
                   struct ipa_sudo_conv *conv,
                   struct ipa_sudo_rulemember *rulemember,
                   struct sysdb_attrs *rule,
                   const char *attr)
{
    TALLOC_CTX *tmp_ctx;
    const char **members;
    errno_t ret;
    int i;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sysdb_attrs_get_string_array(rule, attr, tmp_ctx, &members);
    if (ret == ENOENT) {
        ret = EOK;
        goto done;
    } else if (ret != EOK) {
        goto done;
    }

    for (i = 0; members[i] != NULL; i++) {
        if (is_ipacmdgroup(conv, members[i])) {
            ret = store_rulemember(mem_ctx, &rulemember->cmdgroups,
                                   conv->cmdgroups, members[i]);
            if (ret == EOK) {
                DEBUG(SSSDBG_TRACE_INTERNAL, "Found sudo command group %s\n",
                      members[i]);
            } else if (ret != EEXIST) {
                goto done;
            }
        } else if (is_ipacmd(conv, members[i])) {
            ret = store_rulemember(mem_ctx, &rulemember->cmds,
                                   conv->cmds, members[i]);
            if (ret == EOK) {
                DEBUG(SSSDBG_TRACE_INTERNAL, "Found sudo command %s\n",
                      members[i]);
            } else if (ret != EEXIST) {
                goto done;
            }
        } else {
            DEBUG(SSSDBG_MINOR_FAILURE, "Invalid member DN %s, skipping...\n",
                  members[i]);
            continue;
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
process_allowcmd(struct ipa_sudo_conv *conv,
                 struct ipa_sudo_rule *rule)
{
    return process_rulemember(rule, conv, &rule->allow, rule->attrs,
                              SYSDB_IPA_SUDORULE_ALLOWCMD);
}

static errno_t
process_denycmd(struct ipa_sudo_conv *conv,
                struct ipa_sudo_rule *rule)
{
    return process_rulemember(rule, conv, &rule->deny, rule->attrs,
                              SYSDB_IPA_SUDORULE_DENYCMD);
}

static errno_t
process_cmdgroupmember(struct ipa_sudo_conv *conv,
                       struct ipa_sudo_cmdgroup *cmdgroup,
                       struct sysdb_attrs *attrs)
{
    TALLOC_CTX *tmp_ctx;
    struct ipa_sudo_dn_list *item;
    const char **members;
    errno_t ret;
    int i;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sysdb_attrs_get_string_array(attrs, SYSDB_MEMBER, tmp_ctx, &members);
    if (ret == ENOENT) {
        ret = EOK;
        goto done;
    } else if (ret != EOK) {
        goto done;
    }

    for (i = 0; members[i] != NULL; i++) {
        ret = ipa_sudo_conv_store(conv->cmds, members[i], NULL);
        if (ret == EOK) {
            DEBUG(SSSDBG_TRACE_INTERNAL, "Found sudo command %s\n",
                  members[i]);
        } else if (ret != EEXIST) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to store DN [%d]: %s\n",
                  ret, sss_strerror(ret));
            goto done;
        }

        item = talloc_zero(tmp_ctx, struct ipa_sudo_dn_list);
        if (item == NULL) {
            ret = ENOMEM;
            goto done;
        }

        item->dn = talloc_steal(item, members[i]);
        DLIST_ADD(cmdgroup->cmds, item);
        talloc_steal(cmdgroup, item);
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

struct ipa_sudo_conv *
ipa_sudo_conv_init(TALLOC_CTX *mem_ctx,
                   struct sss_domain_info *dom,
                   struct sdap_attr_map *map_rule,
                   struct sdap_attr_map *map_cmdgroup,
                   struct sdap_attr_map *map_cmd,
                   struct sdap_attr_map *map_user,
                   struct sdap_attr_map *map_group,
                   struct sdap_attr_map *map_host,
                   struct sdap_attr_map *map_hostgroup)
{
    struct ipa_sudo_conv *conv;
    errno_t ret;

    conv = talloc_zero(mem_ctx, struct ipa_sudo_conv);
    if (conv == NULL) {
        return NULL;
    }

    conv->dom = dom;
    conv->map_rule = map_rule;
    conv->map_cmdgroup = map_cmdgroup;
    conv->map_cmd = map_cmd;
    conv->map_user = map_user;
    conv->map_group = map_group;
    conv->map_host = map_host;
    conv->map_hostgroup = map_hostgroup;

    ret = sss_hash_create(conv, 0, &conv->rules);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create hash table [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = sss_hash_create(conv, 0, &conv->cmdgroups);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create hash table [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = sss_hash_create(conv, 0, &conv->cmds);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create hash table [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

done:
    if (ret != EOK) {
        talloc_free(conv);
        return NULL;
    }

    return conv;
}

errno_t
ipa_sudo_conv_rules(struct ipa_sudo_conv *conv,
                    struct sysdb_attrs **rules,
                    size_t num_rules)
{
    struct ipa_sudo_rule *rule = NULL;
    const char *key;
    errno_t ret;
    size_t i;

    if (num_rules == 0) {
        /* We're done here. */
        return EOK;
    }

    for (i = 0; i < num_rules; i++) {
        ret = sysdb_attrs_get_string(rules[i], SYSDB_NAME, &key);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Failed to get rule name, skipping "
                  "[%d]: %s\n", ret, sss_strerror(ret));
            continue;
        }

        rule = talloc_zero(conv->rules, struct ipa_sudo_rule);
        if (rule == NULL) {
            ret = ENOMEM;
            goto done;
        }

        rule->attrs = rules[i];

        ret = process_allowcmd(conv, rule);
        if (ret != EOK && ret != EEXIST) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to process memberAllowCmd "
                  "[%d]: %s\n", ret, sss_strerror(ret));
            return ret;
        }

        ret = process_denycmd(conv, rule);
        if (ret != EOK && ret != EEXIST) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to process memberDenyCmd "
                  "[%d]: %s\n", ret, sss_strerror(ret));
            return ret;
        }

        ret = ipa_sudo_conv_store(conv->rules, key, rule);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to store rule into table "
                  "[%d]: %s\n", ret, sss_strerror(ret));
            goto done;
        }

        talloc_steal(rule, rule->attrs);
        rule = NULL;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(rule);
    }

    return ret;
}

errno_t
ipa_sudo_conv_cmdgroups(struct ipa_sudo_conv *conv,
                        struct sysdb_attrs **cmdgroups,
                        size_t num_cmdgroups)
{
    struct ipa_sudo_cmdgroup *cmdgroup = NULL;
    const char *key;
    errno_t ret;
    size_t i;

    if (num_cmdgroups == 0) {
        /* We're done here. */
        return EOK;
    }

    for (i = 0; i < num_cmdgroups; i++) {
        ret = sysdb_attrs_get_string(cmdgroups[i], SYSDB_ORIG_DN, &key);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Failed to get command group DN, "
                  "skipping [%d]: %s\n", ret, sss_strerror(ret));
            continue;
        }

        cmdgroup = talloc_zero(conv->cmdgroups, struct ipa_sudo_cmdgroup);
        if (cmdgroup == NULL) {
            ret = ENOMEM;
            goto done;
        }

        ret = process_cmdgroupmember(conv, cmdgroup, cmdgroups[i]);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to process member "
                  "[%d]: %s\n", ret, sss_strerror(ret));
            return ret;
        }

        ret = ipa_sudo_conv_store(conv->cmdgroups, key, cmdgroup);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to store command group into "
                  "table [%d]: %s\n", ret, sss_strerror(ret));
            goto done;
        }

        cmdgroup = NULL;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(cmdgroup);
    }

    return ret;
}

errno_t
ipa_sudo_conv_cmds(struct ipa_sudo_conv *conv,
                   struct sysdb_attrs **cmds,
                   size_t num_cmds)
{
    const char *key;
    const char *cmd;
    errno_t ret;
    size_t i;

    if (num_cmds == 0) {
        /* We're done here. */
        return EOK;
    }

    for (i = 0; i < num_cmds; i++) {
        ret = sysdb_attrs_get_string(cmds[i], SYSDB_ORIG_DN, &key);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Failed to get command DN, skipping "
                  "[%d]: %s\n", ret, sss_strerror(ret));
            continue;
        }

        ret = sysdb_attrs_get_string(cmds[i], SYSDB_IPA_SUDOCMD_SUDOCMD, &cmd);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Failed to get command, skipping "
                  "[%d]: %s\n", ret, sss_strerror(ret));
            continue;
        }

        ret = ipa_sudo_conv_store(conv->cmds, key, discard_const(cmd));
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to store command into table "
                  "[%d]: %s\n", ret, sss_strerror(ret));
            goto done;
        }
    }

    ret = EOK;

done:
    return ret;
}

bool
ipa_sudo_conv_has_cmdgroups(struct ipa_sudo_conv *conv)
{
    return hash_count(conv->cmdgroups) == 0;
}

bool
ipa_sudo_conv_has_cmds(struct ipa_sudo_conv *conv)
{
    return hash_count(conv->cmds) == 0;
}

bool
ipa_sudo_cmdgroups_exceed_threshold(struct ipa_sudo_conv *conv, int threshold)
{
    return (hash_count(conv->cmdgroups)) > threshold;
}
bool
ipa_sudo_cmds_exceed_threshold(struct ipa_sudo_conv *conv, int threshold)
{
    return (hash_count(conv->cmds)) > threshold;
}

typedef errno_t (*ipa_sudo_conv_rdn_fn)(TALLOC_CTX *mem_ctx,
                                      struct sdap_attr_map *map,
                                      struct sysdb_ctx *sysdb,
                                      const char *dn,
                                      char **_rdn_val,
                                      const char **_rdn_attr);

static errno_t get_sudo_cmdgroup_rdn(TALLOC_CTX *mem_ctx,
                                     struct sdap_attr_map *map,
                                     struct sysdb_ctx *sysdb,
                                     const char *dn,
                                     char **_rdn_val,
                                     const char **_rdn_attr)
{
    char *rdn_val;
    errno_t ret;

    ret = ipa_get_rdn(mem_ctx, sysdb, dn, &rdn_val,
                      MATCHRDN_CMDGROUPS(map));
    if (ret != EOK) {
        return ret;
    }

    *_rdn_val = rdn_val;
    *_rdn_attr = map[IPA_AT_SUDOCMDGROUP_NAME].name;

    return EOK;
}

static errno_t get_sudo_cmd_rdn(TALLOC_CTX *mem_ctx,
                                struct sdap_attr_map *map,
                                struct sysdb_ctx *sysdb,
                                const char *dn,
                                char **_rdn_val,
                                const char **_rdn_attr)
{
    char *rdn_val;
    errno_t ret;

    ret = ipa_get_rdn(mem_ctx, sysdb, dn, &rdn_val,
                      MATCHRDN_CMDS(IPA_AT_SUDOCMD_UUID, map));
    if (ret == EOK) {
        *_rdn_val = rdn_val;
        *_rdn_attr = map[IPA_AT_SUDOCMD_UUID].name;

        return EOK;
    } else if (ret != ENOENT) {
        return ret;
    }

    /* For older versions of FreeIPA than 3.1. */
    ret = ipa_get_rdn(mem_ctx, sysdb, dn, &rdn_val,
                      MATCHRDN_CMDS(IPA_AT_SUDOCMD_CMD, map));
    if (ret != EOK) {
        return ret;
    }

    *_rdn_val = rdn_val;
    *_rdn_attr = map[IPA_AT_SUDOCMD_CMD].name;

    return EOK;
}

static char *
build_filter(TALLOC_CTX *mem_ctx,
             struct sysdb_ctx *sysdb,
             hash_table_t *table,
             struct sdap_attr_map *map,
             ipa_sudo_conv_rdn_fn rdn_fn)
{
    TALLOC_CTX *tmp_ctx;
    hash_key_t *keys;
    unsigned long int count;
    unsigned long int i;
    char *filter = NULL;
    char *rdn_val;
    const char *rdn_attr;
    char *safe_rdn;
    errno_t ret;
    int hret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return NULL;
    }

    hret = hash_keys(table, &count, &keys);
    if (hret != HASH_SUCCESS) {
        ret = ENOMEM;
        goto done;
    }

    talloc_steal(tmp_ctx, keys);

    filter = talloc_strdup(tmp_ctx, "");
    if (filter == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < count; i++) {
        ret = rdn_fn(tmp_ctx, map, sysdb, keys[i].str, &rdn_val, &rdn_attr);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get member %s [%d]: %s\n",
                  keys[i].str, ret, sss_strerror(ret));
            goto done;
        }

        ret = sss_filter_sanitize(tmp_ctx, rdn_val, &safe_rdn);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to sanitize DN "
                  "[%d]: %s\n", ret, sss_strerror(ret));
            goto done;
        }

        filter = talloc_asprintf_append(filter, "(%s=%s)", rdn_attr, safe_rdn);
        if (filter == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    /* objectClass is always first */
    filter = talloc_asprintf(filter, "(&(objectClass=%s)(|%s))",
                             map[0].name, filter);
    if (filter == NULL) {
        ret = ENOMEM;
        goto done;
    }

    talloc_steal(mem_ctx, filter);

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    if (ret != EOK) {
        return NULL;
    }

    return filter;
}

char *
ipa_sudo_conv_cmdgroup_filter(TALLOC_CTX *mem_ctx,
                              struct ipa_sudo_conv *conv,
                              int cmd_threshold)
{
    if (ipa_sudo_cmdgroups_exceed_threshold(conv, cmd_threshold)) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Command threshold [%d] exceeded, retrieving all sudo command "
              "groups\n", cmd_threshold);
        return talloc_asprintf(mem_ctx, "(objectClass=%s)",
                               conv->map_cmdgroup->name);
    } else {
        return build_filter(mem_ctx, conv->dom->sysdb, conv->cmdgroups,
                            conv->map_cmdgroup, get_sudo_cmdgroup_rdn);
    }
}

char *
ipa_sudo_conv_cmd_filter(TALLOC_CTX *mem_ctx,
                         struct ipa_sudo_conv *conv,
                         int cmd_threshold)
{
    if (ipa_sudo_cmdgroups_exceed_threshold(conv, cmd_threshold)) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Command threshold [%d] exceeded, retrieving all sudo commands\n",
              cmd_threshold);
        return talloc_asprintf(mem_ctx, "(objectClass=%s)",
                               conv->map_cmd->name);
    } else {
        return build_filter(mem_ctx, conv->dom->sysdb, conv->cmds,
                            conv->map_cmd, get_sudo_cmd_rdn);
    }
}

struct ipa_sudo_conv_result_ctx {
    struct ipa_sudo_conv *conv;
    struct sysdb_attrs **rules;
    size_t num_rules;
    errno_t ret;
};

static const char *
convert_host(TALLOC_CTX *mem_ctx,
             struct ipa_sudo_conv *conv,
             const char *value,
             bool *skip_entry)
{
    char *rdn;
    const char *group;
    errno_t ret;

    *skip_entry = false;

    ret = ipa_get_rdn(mem_ctx, conv->dom->sysdb, value, &rdn,
                      MATCHRDN_HOST(conv->map_host));
    if (ret == EOK) {
        return rdn;
    } else if (ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_get_rdn() failed on value %s [%d]: %s\n",
              value, ret, sss_strerror(ret));
        return NULL;
    }

    ret = ipa_get_rdn(mem_ctx, conv->dom->sysdb, value, &rdn,
                      MATCHRDN_HOSTGROUP(conv->map_hostgroup));
    if (ret == ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected DN %s: Skipping\n", value);
        *skip_entry = true;
        return NULL;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "ipa_get_rdn() failed on value %s [%d]: %s\n",
              value, ret, sss_strerror(ret));
        return NULL;
    }

    group = talloc_asprintf(mem_ctx, "+%s", rdn);
    talloc_free(rdn);

    return group;
}

static const char *
convert_user(TALLOC_CTX *mem_ctx,
             struct ipa_sudo_conv *conv,
             const char *value,
             bool *skip_entry)
{
    char *rdn;
    const char *group;
    errno_t ret;

    *skip_entry = false;

    ret = ipa_get_rdn(mem_ctx, conv->dom->sysdb, value, &rdn,
                      MATCHRDN_USER(conv->map_user));
    if (ret == EOK) {
        return rdn;
    } else if (ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_get_rdn() failed on value %s [%d]: %s\n",
              value, ret, sss_strerror(ret));
        return NULL;
    }

    ret = ipa_get_rdn(mem_ctx, conv->dom->sysdb, value, &rdn,
                      MATCHRDN_GROUP(conv->map_group));
    if (ret == ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected DN %s: Skipping\n", value);
        *skip_entry = true;
        return NULL;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "ipa_get_rdn() failed on value %s [%d]: %s\n",
              value, ret, sss_strerror(ret));
        return NULL;
    }

    group = talloc_asprintf(mem_ctx, "%%%s", rdn);
    talloc_free(rdn);

    return group;
}

static const char *
convert_user_fqdn(TALLOC_CTX *mem_ctx,
                  struct ipa_sudo_conv *conv,
                  const char *value,
                  bool *skip_entry)
{
    const char *shortname = NULL;
    char *fqdn = NULL;

    *skip_entry = false;

    shortname = convert_user(mem_ctx, conv, value, skip_entry);
    if (shortname == NULL) {
        return NULL;
    }

    fqdn = sss_create_internal_fqname(mem_ctx, shortname, conv->dom->name);
    talloc_free(discard_const(shortname));
    return fqdn;
}

static const char *
convert_ext_user(TALLOC_CTX *mem_ctx,
                 struct ipa_sudo_conv *conv,
                 const char *value,
                 bool *skip_entry)
{
    /* If value is already fully qualified, return it as it is */
    if (strrchr(value, '@') != NULL) {
        return talloc_strdup(mem_ctx, value);
    }
    return sss_create_internal_fqname(mem_ctx, value, conv->dom->name);
}

static const char *
convert_group(TALLOC_CTX *mem_ctx,
              struct ipa_sudo_conv *conv,
              const char *value,
              bool *skip_entry)
{
    char *rdn;
    errno_t ret;

    *skip_entry = false;

    ret = ipa_get_rdn(mem_ctx, conv->dom->sysdb, value, &rdn,
                      MATCHRDN_GROUP(conv->map_group));
    if (ret == ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected DN %s: Skipping\n", value);
        *skip_entry = true;
        return NULL;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "ipa_get_rdn() failed on value %s [%d]: %s\n",
              value, ret, sss_strerror(ret));
        return NULL;
    }

    return rdn;
}

static const char *
convert_group_fqdn(TALLOC_CTX *mem_ctx,
                   struct ipa_sudo_conv *conv,
                   const char *value,
                   bool *skip_entry)
{
    const char *shortname = NULL;
    char *fqdn = NULL;

    *skip_entry = false;

    shortname = convert_group(mem_ctx, conv, value, skip_entry);
    if (shortname == NULL) {
        return NULL;
    }

    fqdn = sss_create_internal_fqname(mem_ctx, shortname, conv->dom->name);
    talloc_free(discard_const(shortname));
    return fqdn;
}

static const char *
convert_runasextusergroup(TALLOC_CTX *mem_ctx,
                          struct ipa_sudo_conv *conv,
                          const char *value,
                          bool *skip_entry)
{
    if (value == NULL)
        return NULL;

    if (value[0] == '%')
        return talloc_strdup(mem_ctx, value);

    return talloc_asprintf(mem_ctx, "%%%s", value);
}

static const char *
convert_cat(TALLOC_CTX *mem_ctx,
            struct ipa_sudo_conv *conv,
            const char *value,
            bool *skip_entry)
{

    *skip_entry = false;

    if (strcmp(value, "all") == 0) {
        return talloc_strdup(mem_ctx, "ALL");
    }

    return value;
}

static errno_t
convert_attributes(struct ipa_sudo_conv *conv,
                   struct ipa_sudo_rule *rule,
                   struct sysdb_attrs *attrs)
{
    TALLOC_CTX *tmp_ctx;
    const char **values;
    const char *value;
    errno_t ret;
    int i, j;
    bool skip_entry;
    static struct {
        const char *ipa;
        const char *sudo;
        const char *(*conv_fn)(TALLOC_CTX *mem_ctx,
                               struct ipa_sudo_conv *conv,
                               const char *value,
                               bool *skip_entry);
    } table[] = {{SYSDB_NAME,                            SYSDB_SUDO_CACHE_AT_CN         , NULL},
                 {SYSDB_IPA_SUDORULE_HOST,               SYSDB_SUDO_CACHE_AT_HOST       , convert_host},
                 {SYSDB_IPA_SUDORULE_USER,               SYSDB_SUDO_CACHE_AT_USER       , convert_user_fqdn},
                 {SYSDB_IPA_SUDORULE_RUNASUSER,          SYSDB_SUDO_CACHE_AT_RUNASUSER  , convert_user_fqdn},
                 {SYSDB_IPA_SUDORULE_RUNASGROUP,         SYSDB_SUDO_CACHE_AT_RUNASGROUP , convert_group_fqdn},
                 {SYSDB_IPA_SUDORULE_OPTION,             SYSDB_SUDO_CACHE_AT_OPTION     , NULL},
                 {SYSDB_IPA_SUDORULE_NOTAFTER,           SYSDB_SUDO_CACHE_AT_NOTAFTER   , NULL},
                 {SYSDB_IPA_SUDORULE_NOTBEFORE,          SYSDB_SUDO_CACHE_AT_NOTBEFORE  , NULL},
                 {SYSDB_IPA_SUDORULE_SUDOORDER,          SYSDB_SUDO_CACHE_AT_ORDER      , NULL},
                 {SYSDB_IPA_SUDORULE_CMDCATEGORY,        SYSDB_SUDO_CACHE_AT_COMMAND    , convert_cat},
                 {SYSDB_IPA_SUDORULE_HOSTCATEGORY,       SYSDB_SUDO_CACHE_AT_HOST       , convert_cat},
                 {SYSDB_IPA_SUDORULE_USERCATEGORY,       SYSDB_SUDO_CACHE_AT_USER       , convert_cat},
                 {SYSDB_IPA_SUDORULE_RUNASUSERCATEGORY,  SYSDB_SUDO_CACHE_AT_RUNASUSER  , convert_cat},
                 {SYSDB_IPA_SUDORULE_RUNASGROUPCATEGORY, SYSDB_SUDO_CACHE_AT_RUNASGROUP , convert_cat},
                 {SYSDB_IPA_SUDORULE_RUNASEXTUSER,       SYSDB_SUDO_CACHE_AT_RUNASUSER  , NULL},
                 {SYSDB_IPA_SUDORULE_RUNASEXTGROUP,      SYSDB_SUDO_CACHE_AT_RUNASGROUP , NULL},
                 {SYSDB_IPA_SUDORULE_RUNASEXTUSERGROUP,  SYSDB_SUDO_CACHE_AT_RUNASUSER  , convert_runasextusergroup},
                 {SYSDB_IPA_SUDORULE_EXTUSER,            SYSDB_SUDO_CACHE_AT_USER       , convert_ext_user},
                 {SYSDB_IPA_SUDORULE_ALLOWCMD,           SYSDB_IPA_SUDORULE_ORIGCMD     , NULL},
                 {SYSDB_IPA_SUDORULE_DENYCMD,            SYSDB_IPA_SUDORULE_ORIGCMD     , NULL},
                 {NULL, NULL, NULL}};

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    for (i = 0; table[i].ipa != NULL; i++) {
        ret = sysdb_attrs_get_string_array(rule->attrs, table[i].ipa,
                                           tmp_ctx, &values);
        if (ret == ENOENT) {
            continue;
        } else if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to read attribute "
                  "%s [%d]: %s\n", table[i].ipa, ret, sss_strerror(ret));
            goto done;
        }

        for (j = 0; values[j] != NULL; j++) {
            if (table[i].conv_fn != NULL) {
                value = table[i].conv_fn(tmp_ctx, conv, values[j], &skip_entry);
                if (value == NULL) {
                    if (skip_entry) {
                        continue;
                    } else {
                        ret = ENOMEM;
                        goto done;
                    }
                }
            } else {
                value = values[j];
            }

            ret = sysdb_attrs_add_string_safe(attrs, table[i].sudo, value);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Unable to add attribute "
                      "%s [%d]: %s\n", table[i].sudo, ret, sss_strerror(ret));
                goto done;
            }
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static const char **
combine_cmdgroups(TALLOC_CTX *mem_ctx,
                  struct ipa_sudo_conv *conv,
                  struct ipa_sudo_dn_list *list)
{
    TALLOC_CTX *tmp_ctx;
    struct ipa_sudo_cmdgroup *cmdgroup;
    struct ipa_sudo_dn_list *listitem;
    const char **values = NULL;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return NULL;
    }

    values = talloc_zero_array(tmp_ctx, const char *, 1);
    if (values == NULL) {
        talloc_free(tmp_ctx);
        return NULL;
    }

    DLIST_FOR_EACH(listitem, list) {
        cmdgroup = ipa_sudo_conv_lookup(conv->cmdgroups, listitem->dn);
        if (cmdgroup == NULL) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "ipa_sudo_conv_lookup failed for DN:%s\n", listitem->dn);
            continue;
        }

        ret = add_strings_lists(mem_ctx, values, cmdgroup->expanded,
                                false, &values);
        if (ret != EOK) {
            talloc_free(tmp_ctx);
            return NULL;
        }
    }

    talloc_steal(mem_ctx, values);
    talloc_free(tmp_ctx);

    return values;
}

static const char **
combine_cmds(TALLOC_CTX *mem_ctx,
             struct ipa_sudo_conv *conv,
             struct ipa_sudo_dn_list *list)
{
    struct ipa_sudo_dn_list *listitem;
    const char **values;
    const char *command;
    size_t count;
    size_t i;

    count = ipa_sudo_dn_list_count(list);

    values = talloc_zero_array(mem_ctx, const char *, count + 1);
    if (values == NULL) {
        return NULL;
    }

    i = 0;
    DLIST_FOR_EACH(listitem, list) {
        command = ipa_sudo_conv_lookup(conv->cmds, listitem->dn);
        if (command == NULL) {
            continue;
        }

        values[i] = command;
        i++;
    }

    return values;
}

static errno_t
build_sudocommand(struct ipa_sudo_conv *conv,
                  struct ipa_sudo_rulemember *mlist,
                  struct sysdb_attrs *attrs,
                  char prefix)
{
    TALLOC_CTX *tmp_ctx;
    const char **cmds[2];
    const char *command;
    errno_t ret;
    int i, j;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    cmds[0] = combine_cmdgroups(tmp_ctx, conv, mlist->cmdgroups);
    if (cmds[0] == NULL) {
        ret = ENOMEM;
        goto done;
    }

    cmds[1] = combine_cmds(tmp_ctx, conv, mlist->cmds);
    if (cmds[1] == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < 2; i++) {
        for (j = 0; cmds[i][j] != NULL; j++) {
            if (prefix == '\0') {
                command = cmds[i][j];
            } else {
                command = talloc_asprintf(tmp_ctx, "%c%s", prefix, cmds[i][j]);
                if (command == NULL) {
                    ret = ENOMEM;
                    goto done;
                }
            }

            ret = sysdb_attrs_add_string_safe(attrs,
                        SYSDB_SUDO_CACHE_AT_COMMAND, command);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Unable to add attribute "
                      "%s [%d]: %s\n", SYSDB_SUDO_CACHE_AT_COMMAND,
                      ret, sss_strerror(ret));
                goto done;
            }
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
convert_sudocommand(struct ipa_sudo_conv *conv,
                    struct ipa_sudo_rule *rule,
                    struct sysdb_attrs *attrs)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = build_sudocommand(conv, &rule->allow, attrs, '\0');
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to build allow commands "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    ret = build_sudocommand(conv, &rule->deny, attrs, '!');
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to build deny commands "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static bool
rules_iterator(hash_entry_t *item,
               void *user_data)
{
    struct ipa_sudo_conv_result_ctx *ctx = user_data;
    struct ipa_sudo_rule *rule = item->value.ptr;
    struct sysdb_attrs *attrs;

    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: ctx is NULL\n");
        return false;
    }

    if (rule == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: rule is NULL\n");
        ctx->ret = ERR_INTERNAL;
        return false;
    }

    attrs = sysdb_new_attrs(ctx->rules);
    if (attrs == NULL) {
        ctx->ret = ENOMEM;
        return false;
    }

    ctx->ret = convert_attributes(ctx->conv, rule, attrs);
    if (ctx->ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to convert attributes [%d]: %s\n",
              ctx->ret, sss_strerror(ctx->ret));
        talloc_free(attrs);
        return false;
    }

    ctx->ret = convert_sudocommand(ctx->conv, rule, attrs);
    if (ctx->ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to build sudoCommand [%d]: %s\n",
              ctx->ret, sss_strerror(ctx->ret));
        talloc_free(attrs);
        return false;
    }

    ctx->rules[ctx->num_rules] = attrs;
    ctx->num_rules++;

    return true;
}

static bool
cmdgroups_iterator(hash_entry_t *item,
                   void *user_data)
{
    struct ipa_sudo_conv_result_ctx *ctx = user_data;
    struct ipa_sudo_cmdgroup *cmdgroup = item->value.ptr;
    const char **values;

    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: ctx is NULL\n");
        return false;
    }

    if (cmdgroup == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: rule is NULL\n");
        ctx->ret = ERR_INTERNAL;
        return false;
    }

    values = combine_cmds(cmdgroup, ctx->conv, cmdgroup->cmds);
    if (values == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to expand commands\n");
        ctx->ret = ENOMEM;
        return false;
    }

    cmdgroup->expanded = values;
    ctx->ret = EOK;

    return true;
}

errno_t
ipa_sudo_conv_result(TALLOC_CTX *mem_ctx,
                     struct ipa_sudo_conv *conv,
                     struct sysdb_attrs ***_rules,
                     size_t *_num_rules)
{
    struct ipa_sudo_conv_result_ctx ctx;
    struct sysdb_attrs **rules;
    unsigned long num_rules;
    int hret;

    num_rules = hash_count(conv->rules);
    if (num_rules == 0) {
        *_rules = NULL;
        *_num_rules = 0;
        return EOK;
    }

    ctx.conv = conv;
    ctx.rules = NULL;
    ctx.num_rules = 0;

    /* If there are no cmdgroups the iterator is not called and ctx.ret is
     * uninitialized. Since it is ok that there are no cmdgroups initializing
     * ctx.ret to EOK. */
    ctx.ret = EOK;

    /* Expand commands in command groups. */
    hret = hash_iterate(conv->cmdgroups, cmdgroups_iterator, &ctx);
    if (hret != HASH_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to iterate over command groups "
              "[%d]\n", hret);
        return EIO;
    }

    if (ctx.ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to expand command groups "
              "[%d]: %s\n", ctx.ret, sss_strerror(ctx.ret));
        return ctx.ret;
    }

    /* Convert rules. */
    rules = talloc_zero_array(mem_ctx, struct sysdb_attrs *, num_rules);
    if (rules == NULL) {
        return ENOMEM;
    }

    ctx.rules = rules;
    ctx.num_rules = 0;

    hret = hash_iterate(conv->rules, rules_iterator, &ctx);
    if (hret != HASH_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to iterate over rules [%d]\n", hret);
        return EIO;
    }

    if (ctx.ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to convert rules [%d]: %s\n",
              ctx.ret, sss_strerror(ctx.ret));
        talloc_free(rules);
        return ctx.ret;
    }

    *_rules = ctx.rules;
    *_num_rules = ctx.num_rules;

    return EOK;
}
