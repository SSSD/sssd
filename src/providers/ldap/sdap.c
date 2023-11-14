/*
    SSSD

    LDAP Helper routines

    Copyright (C) Simo Sorce <ssorce@redhat.com>

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
#include "util/crypto/sss_crypto.h"
#include "confdb/confdb.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap.h"
#include "providers/ldap/sdap_range.h"
#include "util/probes.h"

/* =Retrieve-Options====================================================== */

errno_t sdap_copy_map_entry(const struct sdap_attr_map *src_map,
                            struct sdap_attr_map *dst_map,
                            int entry_index)
{
    if (src_map[entry_index].name != NULL) {
        dst_map[entry_index].name = talloc_strdup(dst_map,
                                                  src_map[entry_index].name);
        if (dst_map[entry_index].name == NULL) {
            return ENOMEM;
        }
    } else {
        dst_map->name = NULL;
    }

    return EOK;
}

int sdap_copy_map(TALLOC_CTX *memctx,
                 struct sdap_attr_map *src_map,
                 int num_entries,
                 struct sdap_attr_map **_map)
{
    struct sdap_attr_map *map;
    int i;

    map = talloc_array(memctx, struct sdap_attr_map, num_entries + 1);
    if (!map) {
        return ENOMEM;
    }

    for (i = 0; i < num_entries; i++) {
        map[i].opt_name = talloc_strdup(map, src_map[i].opt_name);
        map[i].sys_name = talloc_strdup(map, src_map[i].sys_name);
        if (map[i].opt_name == NULL || map[i].sys_name == NULL) {
            return ENOMEM;
        }

        if (src_map[i].def_name != NULL) {
            map[i].def_name = talloc_strdup(map, src_map[i].def_name);
            map[i].name = talloc_strdup(map, src_map[i].def_name);
            if (map[i].def_name == NULL || map[i].name == NULL) {
                return ENOMEM;
            }
        } else {
            map[i].def_name = NULL;
            map[i].name = NULL;
        }

        DEBUG(SSSDBG_TRACE_FUNC, "Option %s has%s value %s\n",
              map[i].opt_name, map[i].name ? "" : " no",
              map[i].name ? map[i].name : "");
    }

    /* Include the sentinel */
    memset(&map[num_entries], 0, sizeof(struct sdap_attr_map));

    *_map = map;
    return EOK;
}

static errno_t split_extra_attr(TALLOC_CTX *mem_ctx,
                                const char *conf_attr,
                                char **_sysdb_attr,
                                char **_ldap_attr)
{
    char *ldap_attr;
    char *sysdb_attr;
    char *sep;

    sep = strchr(conf_attr, ':');
    if (sep == NULL) {
        sysdb_attr = talloc_strdup(mem_ctx, conf_attr);
        ldap_attr = talloc_strdup(mem_ctx, conf_attr);
    } else {
        if (sep == conf_attr || *(sep + 1) == '\0') {
            return ERR_INVALID_EXTRA_ATTR;
        }

        sysdb_attr = talloc_strndup(mem_ctx, conf_attr,
                                    sep - conf_attr);
        ldap_attr = talloc_strdup(mem_ctx, sep+1);
    }

    if (sysdb_attr == NULL || ldap_attr == NULL) {
        return ENOMEM;
    }

    *_sysdb_attr = sysdb_attr;
    *_ldap_attr = ldap_attr;
    return EOK;
}

enum duplicate_t {
    NOT_FOUND = 0,
    ALREADY_IN_MAP, /* nothing to add */
    CONFLICT_WITH_MAP /* attempt to redefine attribute */
};

static enum duplicate_t check_duplicate(struct sdap_attr_map *map,
                                        int num_entries,
                                        const char *sysdb_attr,
                                        const char *ldap_attr)
{
    int i;

    for (i = 0; i < num_entries; i++) {
        if (strcmp(map[i].sys_name, sysdb_attr) == 0) {
            if (map[i].name != NULL && strcmp(map[i].name, ldap_attr) == 0) {
                return ALREADY_IN_MAP;
            } else {
                return CONFLICT_WITH_MAP;
            }
        }
    }

    return NOT_FOUND;
}

int sdap_extend_map(TALLOC_CTX *memctx,
                    struct sdap_attr_map *src_map,
                    size_t num_entries,
                    char **extra_attrs,
                    struct sdap_attr_map **_map,
                    size_t *_new_size)
{
    struct sdap_attr_map *map;
    size_t nextra = 0;
    size_t i;
    char *ldap_attr;
    char *sysdb_attr;
    errno_t ret;

    *_map = src_map;
    if (extra_attrs == NULL) {
        DEBUG(SSSDBG_FUNC_DATA, "No extra attributes\n");
        *_new_size = num_entries;
        return EOK;
    }

    for (nextra = 0; extra_attrs[nextra]; nextra++) ;
    DEBUG(SSSDBG_FUNC_DATA, "%zu extra attributes\n", nextra);

    map = talloc_realloc(memctx, src_map, struct sdap_attr_map,
                         num_entries + nextra + 1);
    if (map == NULL) {
        return ENOMEM;
    }
    *_map = map;

    for (i = 0; *extra_attrs != NULL; extra_attrs++) {
        ret = split_extra_attr(map, *extra_attrs, &sysdb_attr, &ldap_attr);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Cannot split %s\n", *extra_attrs);
            continue;
        }

        ret = check_duplicate(map, num_entries, sysdb_attr, ldap_attr);
        if (ret == ALREADY_IN_MAP) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "Attribute %s (%s in LDAP) is already in map.\n",
                  sysdb_attr, ldap_attr);
            continue;
        } else if (ret == CONFLICT_WITH_MAP) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Attribute %s (%s in LDAP) is already used by SSSD, please "
                  "choose a different cache name\n", sysdb_attr, ldap_attr);
            return ERR_DUP_EXTRA_ATTR;
        }

        map[num_entries+i].name = ldap_attr;
        map[num_entries+i].sys_name = sysdb_attr;
        map[num_entries+i].opt_name = talloc_strdup(map,
                                                map[num_entries+i].name);
        map[num_entries+i].def_name = talloc_strdup(map,
                                                map[num_entries+i].name);
        if (map[num_entries+i].opt_name == NULL ||
            map[num_entries+i].sys_name == NULL ||
            map[num_entries+i].name == NULL ||
            map[num_entries+i].def_name == NULL) {
            return ENOMEM;
        }
        DEBUG(SSSDBG_TRACE_FUNC, "Extending map with %s\n", *extra_attrs);

        /* index must be incremented only for appended entry. */
        i++;
    }

    nextra = i;

    /* Sentinel */
    memset(&map[num_entries+nextra], 0, sizeof(struct sdap_attr_map));

    *_new_size = num_entries + nextra;
    return EOK;
}

int sdap_extend_map_with_list(TALLOC_CTX *mem_ctx,
                              const struct sdap_options *opts,
                              int extra_attr_index,
                              struct sdap_attr_map *src_map,
                              size_t num_entries,
                              struct sdap_attr_map **_map,
                              size_t *_new_size)
{
    const char *extra_attrs;
    char **extra_attrs_list;
    errno_t ret;

    *_map = src_map;
    extra_attrs = dp_opt_get_string(opts->basic, extra_attr_index);
    if (extra_attrs == NULL) {
        *_new_size = num_entries;
        return EOK;
    }

    /* split server parm into a list */
    ret = split_on_separator(mem_ctx, extra_attrs, ',', true, true,
                             &extra_attrs_list, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to parse server list!\n");
        return ret;
    }


    ret = sdap_extend_map(mem_ctx, src_map,
                          num_entries, extra_attrs_list,
                          _map, _new_size);
    talloc_free(extra_attrs_list);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

static void sdap_inherit_basic_options(char **inherit_opt_list,
                                       struct dp_option *parent_opts,
                                       struct dp_option *subdom_opts)
{
    int inherit_options[] = {
        SDAP_SEARCH_TIMEOUT,
        SDAP_NETWORK_TIMEOUT,
        SDAP_OPT_TIMEOUT,
        SDAP_OFFLINE_TIMEOUT,
        SDAP_ENUM_REFRESH_TIMEOUT,
        SDAP_ENUM_REFRESH_OFFSET,
        SDAP_PURGE_CACHE_TIMEOUT,
        SDAP_PURGE_CACHE_OFFSET,
        SDAP_KRB5_KEYTAB,
        SDAP_KRB5_TICKET_LIFETIME,
        SDAP_ENUM_SEARCH_TIMEOUT,
        SDAP_EXPIRE_TIMEOUT,
        SDAP_EXPIRE_OFFSET,
        SDAP_IDLE_TIMEOUT,
        SDAP_AD_USE_TOKENGROUPS,
        SDAP_OPTS_BASIC     /* sentinel */
    };
    int i;

    for (i = 0; inherit_options[i] != SDAP_OPTS_BASIC; i++) {
        dp_option_inherit_match(inherit_opt_list,
                                inherit_options[i],
                                parent_opts,
                                subdom_opts);
    }
}

static void sdap_inherit_user_options(char **inherit_opt_list,
                                      struct sdap_attr_map *parent_user_map,
                                      struct sdap_attr_map *child_user_map)
{
    int inherit_options[] = {
        SDAP_AT_USER_PRINC,
        SDAP_OPTS_USER          /* sentinel */
    };
    int i;
    int opt_index;
    bool inherit_option;

    for (i = 0; inherit_options[i] != SDAP_OPTS_USER; i++) {
        opt_index = inherit_options[i];

        inherit_option = string_in_list(parent_user_map[opt_index].opt_name,
                                        inherit_opt_list,
                                        false);
        if (inherit_option == false) {
            continue;
        }

        sdap_copy_map_entry(parent_user_map, child_user_map, opt_index);
    }
}

void sdap_inherit_options(char **inherit_opt_list,
                          struct sdap_options *parent_sdap_opts,
                          struct sdap_options *child_sdap_opts)
{
    sdap_inherit_basic_options(inherit_opt_list,
                               parent_sdap_opts->basic,
                               child_sdap_opts->basic);

    sdap_inherit_user_options(inherit_opt_list,
                              parent_sdap_opts->user_map,
                              child_sdap_opts->user_map);
}

int sdap_get_map(TALLOC_CTX *memctx,
                 struct confdb_ctx *cdb,
                 const char *conf_path,
                 struct sdap_attr_map *def_map,
                 int num_entries,
                 struct sdap_attr_map **_map)
{
    struct sdap_attr_map *map;
    char *name;
    int i, ret;

    map = talloc_zero_array(memctx, struct sdap_attr_map, num_entries + 1);
    if (!map) {
        return ENOMEM;
    }

    for (i = 0; i < num_entries; i++) {

        map[i].opt_name = def_map[i].opt_name;
        map[i].def_name = def_map[i].def_name;
        map[i].sys_name = def_map[i].sys_name;

        ret = confdb_get_string(cdb, map, conf_path,
                                map[i].opt_name,
                                map[i].def_name,
                                &name);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to retrieve value for %s\n", map[i].opt_name);
            talloc_zfree(map);
            return EINVAL;
        }

        if (name) {
            ret = sss_filter_sanitize(map, name, &map[i].name);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Could not sanitize attribute [%s]\n", name);
                talloc_zfree(map);
                return EINVAL;
            }
            talloc_zfree(name);
        } else {
            map[i].name = NULL;
        }

        if (map[i].def_name && !map[i].name) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to process value for %s\n", map[i].opt_name);
            talloc_zfree(map);
            return EINVAL;
        }

        DEBUG(SSSDBG_TRACE_FUNC, "Option %s has%s value %s\n",
              map[i].opt_name, map[i].name ? "" : " no",
              map[i].name ? map[i].name : "");
    }

    *_map = map;
    return EOK;
}

/* =Parse-msg============================================================= */

static bool objectclass_matched(struct sdap_attr_map *map,
                                const char *objcl, int len);
int sdap_parse_entry(TALLOC_CTX *memctx,
                     struct sdap_handle *sh, struct sdap_msg *sm,
                     struct sdap_attr_map *map, int attrs_num,
                     struct sysdb_attrs **_attrs,
                     bool disable_range_retrieval)
{
    struct sysdb_attrs *attrs;
    BerElement *ber = NULL;
    struct berval **vals;
    struct ldb_val v;
    char *str;
    int lerrno;
    int i, ret, ai;
    int base_attr_idx = 0;
    const char *name = NULL;
    bool store;
    bool base64;
    char *base_attr;
    uint32_t range_offset;
    TALLOC_CTX *tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    lerrno = 0;
    ret = ldap_set_option(sh->ldap, LDAP_OPT_RESULT_CODE, &lerrno);
    if (ret != LDAP_OPT_SUCCESS) {
        DEBUG(SSSDBG_MINOR_FAILURE, "ldap_set_option failed [%s], ignored.\n",
              sss_ldap_err2string(ret));
    }

    attrs = sysdb_new_attrs(tmp_ctx);
    if (!attrs) {
        ret = ENOMEM;
        goto done;
    }

    str = ldap_get_dn(sh->ldap, sm->msg);
    if (!str) {
        ldap_get_option(sh->ldap, LDAP_OPT_RESULT_CODE, &lerrno);
        DEBUG(SSSDBG_CRIT_FAILURE, "ldap_get_dn failed: %d(%s)\n",
              lerrno, sss_ldap_err2string(lerrno));
        ret = EIO;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "OriginalDN: [%s].\n", str);
    PROBE(SDAP_PARSE_ENTRY, "OriginalDN", str, strlen(str));
    ret = sysdb_attrs_add_string(attrs, SYSDB_ORIG_DN, str);
    ldap_memfree(str);
    if (ret) goto done;

    if (map) {
        vals = ldap_get_values_len(sh->ldap, sm->msg, "objectClass");
        if (!vals) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unknown entry type, no objectClasses found!\n");
            ret = EINVAL;
            goto done;
        }

        for (i = 0; vals[i]; i++) {
            if (objectclass_matched(map, vals[i]->bv_val, vals[i]->bv_len)) {
                /* ok it's an entry of the right type */
                break;
            }
        }
        if (!vals[i]) {
            DEBUG(SSSDBG_CRIT_FAILURE, "objectClass not matching: %s\n",
                  map[0].name);
            ldap_value_free_len(vals);
            ret = EINVAL;
            goto done;
        }
        ldap_value_free_len(vals);
    }

    str = ldap_first_attribute(sh->ldap, sm->msg, &ber);
    if (!str) {
        ldap_get_option(sh->ldap, LDAP_OPT_RESULT_CODE, &lerrno);
        DEBUG(lerrno == LDAP_SUCCESS
              ? SSSDBG_TRACE_LIBS
              : SSSDBG_MINOR_FAILURE,
              "Entry has no attributes [%d(%s)]!?\n",
               lerrno, sss_ldap_err2string(lerrno));
        if (map) {
            ret = EINVAL;
            goto done;
        }
    }
    while (str) {
        base64 = false;

        ret = sdap_parse_range(tmp_ctx, str, &base_attr, &range_offset,
                               disable_range_retrieval);
        switch(ret) {
        case EAGAIN:
            /* This attribute contained range values and needs more to
             * be retrieved
             */
            /* TODO: return the set of attributes that need additional retrieval
             * For now, we'll continue below and treat it as regular values.
             */
            /* FALLTHROUGH */
        case ECANCELED:
            /* FALLTHROUGH */
        case EOK:
            break;
        default:
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Could not determine if attribute [%s] was ranged\n", str);
            goto done;
        }

        if (ret == ECANCELED) {
            store = false;
        } else if (map) {
            for (i = 1; i < attrs_num; i++) {
                /* check if this attr is valid with the chosen schema */
                if (!map[i].name) continue;
                /* check if it is an attr we are interested in */
                if (strcasecmp(base_attr, map[i].name) == 0) break;
            }
            /* interesting attr */
            if (i < attrs_num) {
                store = true;
                name = map[i].sys_name;
                base_attr_idx = i;
                if (strcmp(name, SYSDB_SSH_PUBKEY) == 0) {
                    base64 = true;
                }
            } else {
                store = false;
            }
        } else {
            name = base_attr;
            store = true;
        }

        if (store) {
            vals = ldap_get_values_len(sh->ldap, sm->msg, str);
            if (!vals) {
                ldap_get_option(sh->ldap, LDAP_OPT_RESULT_CODE, &lerrno);
                if (lerrno != LDAP_SUCCESS) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "ldap_get_values_len() failed: %d(%s)\n",
                          lerrno, sss_ldap_err2string(lerrno));
                    ret = EIO;
                    goto done;
                }

                DEBUG(SSSDBG_TRACE_LIBS,
                      "Attribute [%s] has no values, skipping.\n", str);

            } else {
                if (!vals[0]) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Missing value after ldap_get_values() ??\n");
                    ldap_value_free_len(vals);
                    ret = EINVAL;
                    goto done;
                }
                for (i = 0; vals[i]; i++) {
                    if (vals[i]->bv_len == 0) {
                        DEBUG(SSSDBG_TRACE_LIBS,
                              "Value of attribute [%s] is empty. "
                               "Skipping this value.\n", str);
                        continue;
                    }
                    if (base64) {
                        v.data = (uint8_t *) sss_base64_encode(attrs,
                                 (uint8_t *) vals[i]->bv_val, vals[i]->bv_len);
                        if (!v.data) {
                            ldap_value_free_len(vals);
                            ret = ENOMEM;
                            goto done;
                        }
                        v.length = strlen((const char *)v.data);
                    } else {
                        v.data = (uint8_t *)vals[i]->bv_val;
                        v.length = vals[i]->bv_len;
                    }
                    PROBE(SDAP_PARSE_ENTRY, str, v.data, v.length);

                    if (map) {
                        /* The same LDAP attr might be used for more sysdb
                         * attrs in case there is a map. Find all that match
                         * and copy the value
                         */
                        for (ai = base_attr_idx; ai < attrs_num; ai++) {
                            /* check if this attr is valid with the chosen
                             * schema */
                            if (!map[ai].name) continue;

                            /* check if it is an attr we are interested in */
                            if (strcasecmp(base_attr, map[ai].name) == 0) {
                                ret = sysdb_attrs_add_val(attrs,
                                                          map[ai].sys_name,
                                                          &v);
                                if (ret) {
                                    ldap_value_free_len(vals);
                                    goto done;
                                }
                            }
                        }
                    } else {
                        /* No map, just store the attribute */
                        ret = sysdb_attrs_add_val(attrs, name, &v);
                        if (ret) {
                            ldap_value_free_len(vals);
                            goto done;
                        }
                    }
                }
                ldap_value_free_len(vals);
            }
        }

        ldap_memfree(str);
        str = ldap_next_attribute(sh->ldap, sm->msg, ber);
    }
    ber_free(ber, 0);
    ber = NULL;

    ldap_get_option(sh->ldap, LDAP_OPT_RESULT_CODE, &lerrno);
    if (lerrno) {
        DEBUG(SSSDBG_CRIT_FAILURE, "ldap_get_option() failed: %d(%s)\n",
              lerrno, sss_ldap_err2string(lerrno));
        ret = EIO;
        goto done;
    }

    PROBE(SDAP_PARSE_ENTRY_DONE);
    *_attrs = talloc_steal(memctx, attrs);
    ret = EOK;

done:
    if (ber) ber_free(ber, 0);
    talloc_free(tmp_ctx);
    return ret;
}

static bool objectclass_matched(struct sdap_attr_map *map,
                                const char *objcl, int len)
{
    if (len == 0) {
        len = strlen(objcl) + 1;
    }

    if (strncasecmp(map[SDAP_OC_GROUP].name, objcl, len) == 0) {
        return true;
    }

    if (map[SDAP_OC_GROUP_ALT].name != NULL
        && strncasecmp(map[SDAP_OC_GROUP_ALT].name, objcl, len) == 0) {
        return true;
    }

    return false;
}

/* Parses an LDAPDerefRes into sdap_deref_attrs structure */
errno_t sdap_parse_deref(TALLOC_CTX *mem_ctx,
                         struct sdap_attr_map_info *minfo,
                         size_t num_maps,
                         LDAPDerefRes *dref,
                         struct sdap_deref_attrs ***_deref_res)
{
    TALLOC_CTX *tmp_ctx;
    LDAPDerefVal *dval;
    const char *orig_dn;
    const char **ocs;
    struct sdap_attr_map *map;
    int num_attrs = 0;
    int ret, i, a, mi;
    const char *name;
    size_t len;
    struct sdap_deref_attrs **res;

    if (!dref || !minfo) return EINVAL;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    res = talloc_array(tmp_ctx, struct sdap_deref_attrs *, num_maps);
    if (!res) {
        ret = ENOMEM;
        goto done;
    }

    for (i=0; i < num_maps; i++) {
        res[i] = talloc_zero(res, struct sdap_deref_attrs);
        if (!res[i]) {
            ret = ENOMEM;
            goto done;
        }

        res[i]->map = minfo[i].map;
    }

    if (!dref->derefVal.bv_val) {
        DEBUG(SSSDBG_OP_FAILURE, "Entry has no DN?\n");
        ret = EINVAL;
        goto done;
    }

    orig_dn = dref->derefVal.bv_val;
    DEBUG(SSSDBG_TRACE_LIBS,
          "Dereferenced DN: %s\n", orig_dn);

    if (!dref->attrVals) {
        DEBUG(SSSDBG_FUNC_DATA,
              "Dereferenced entry [%s] has no attributes, skipping\n",
              orig_dn);
        *_deref_res = NULL;
        ret = EOK;
        goto done;
    }

    ocs = NULL;
    for (dval = dref->attrVals; dval != NULL; dval = dval->next) {
        if (strcasecmp("objectClass", dval->type) == 0) {
            if (dval->vals == NULL) {
                DEBUG(SSSDBG_CONF_SETTINGS,
                      "No value for objectClass, skipping\n");
                continue;
            }

            for(len=0; dval->vals[len].bv_val; len++);

            ocs = talloc_array(tmp_ctx, const char *, len+1);
            if (!ocs) {
                ret = ENOMEM;
                goto done;
            }

            for (i=0; i<len; i++) {
                DEBUG(SSSDBG_TRACE_ALL, "Dereferenced objectClass value: %s\n",
                          dval->vals[i].bv_val);
                ocs[i] = talloc_strdup(ocs, dval->vals[i].bv_val);
                if (!ocs[i]) {
                    ret = ENOMEM;
                    goto done;
                }
            }
            ocs[i] = NULL;
            break;
        }
    }
    if (!ocs) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unknown entry type, no objectClasses found!\n");
        ret = EINVAL;
        goto done;
    }

    for (mi = 0; mi < num_maps; mi++) {
        map = NULL;

        for (i=0; ocs[i]; i++) {
            /* the objectclass is always the first name in the map */
            if (objectclass_matched(minfo[mi].map, ocs[i], 0)) {
                DEBUG(SSSDBG_TRACE_ALL,
                      "Found map for objectclass '%s'\n", ocs[i]);
                map = minfo[mi].map;
                num_attrs = minfo[mi].num_attrs;
                break;
            }
        }
        if (!map) continue;

        res[mi]->attrs = sysdb_new_attrs(res[mi]);
        if (!res[mi]->attrs) {
            ret = ENOMEM;
            goto done;
        }

        ret = sysdb_attrs_add_string(res[mi]->attrs, SYSDB_ORIG_DN,
                                     orig_dn);
        if (ret) {
            goto done;
        }

        /* The dereference control seems to return the DN from the dereference
         * attribute (e.g. member) so we can use it as key for the hash table
         * later. */
        ret = sysdb_attrs_add_string(res[mi]->attrs,
                                     SYSDB_DN_FOR_MEMBER_HASH_TABLE, orig_dn);
        if (ret) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_add_string failed.\n");
            goto done;
        }

        for (dval = dref->attrVals; dval != NULL; dval = dval->next) {
            DEBUG(SSSDBG_TRACE_INTERNAL,
                  "Dereferenced attribute: %s\n", dval->type);

            for (a = 1; a < num_attrs; a++) {
                /* check if this attr is valid with the chosen schema */
                if (!map[a].name) continue;
                /* check if it is an attr we are interested in */
                if (strcasecmp(dval->type, map[a].name) == 0) break;
            }

            /* interesting attr */
            if (a < num_attrs) {
                name = map[a].sys_name;
            } else {
                continue;
            }

            if (dval->vals == NULL) {
                DEBUG(SSSDBG_CONF_SETTINGS,
                      "No value for attribute %s, skipping\n", name);
                continue;
            }

            for (i=0; dval->vals[i].bv_val; i++) {
                DEBUG(SSSDBG_TRACE_ALL, "Dereferenced attribute value: %s\n",
                          dval->vals[i].bv_val);
                ret = sysdb_attrs_add_mem(res[mi]->attrs, name,
                                          dval->vals[i].bv_val,
                                          dval->vals[i].bv_len);
                if (ret) goto done;
            }
        }
    }


    *_deref_res = talloc_steal(mem_ctx, res);
    ret = EOK;
done:
    talloc_zfree(tmp_ctx);
    return ret;
}

static void sss_ldap_debug(const char *buf)
{
    sss_debug_fn(__FILE__, __LINE__, __FUNCTION__, SSSDBG_TRACE_ALL,
                "libldap: %s", buf);
}

void setup_ldap_debug(struct dp_option *basic_opts)
{
    int ret;
    int ldap_debug_level;

    ldap_debug_level = dp_opt_get_int(basic_opts, SDAP_LIBRARY_DEBUG_LEVEL);
    if (ldap_debug_level == 0) {
        return;
    }

    DEBUG(SSSDBG_CONF_SETTINGS, "Setting LDAP library debug level [%d].\n",
                                ldap_debug_level);

    ret = ber_set_option(NULL, LBER_OPT_DEBUG_LEVEL, &ldap_debug_level);
    if (ret != LBER_OPT_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to set LBER_OPT_DEBUG_LEVEL, ignored .\n");
    }

    ret = ber_set_option(NULL,  LBER_OPT_LOG_PRINT_FN, sss_ldap_debug);
    if (ret != LBER_OPT_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to set LBER_OPT_LOG_PRINT_FN, ignored .\n");
    }

    ret = ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, &ldap_debug_level);
    if (ret != LDAP_OPT_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to set LDAP_OPT_DEBUG_LEVEL, ignored .\n");
    }
}

errno_t setup_tls_config(struct dp_option *basic_opts)
{
    int ret;
    int ldap_opt_x_tls_require_cert;
    const char *tls_opt;
    tls_opt = dp_opt_get_string(basic_opts, SDAP_TLS_REQCERT);
    if (tls_opt) {
        if (strcasecmp(tls_opt, "never") == 0) {
            ldap_opt_x_tls_require_cert = LDAP_OPT_X_TLS_NEVER;
        }
        else if (strcasecmp(tls_opt, "allow") == 0) {
            ldap_opt_x_tls_require_cert = LDAP_OPT_X_TLS_ALLOW;
        }
        else if (strcasecmp(tls_opt, "try") == 0) {
            ldap_opt_x_tls_require_cert = LDAP_OPT_X_TLS_TRY;
        }
        else if (strcasecmp(tls_opt, "demand") == 0) {
            ldap_opt_x_tls_require_cert = LDAP_OPT_X_TLS_DEMAND;
        }
        else if (strcasecmp(tls_opt, "hard") == 0) {
            ldap_opt_x_tls_require_cert = LDAP_OPT_X_TLS_HARD;
        }
        else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unknown value for tls_reqcert '%s'.\n", tls_opt);
            return EINVAL;
        }
        /* LDAP_OPT_X_TLS_REQUIRE_CERT has to be set as a global option,
         * because the SSL/TLS context is initialized from this value. */
        ret = ldap_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT,
                              &ldap_opt_x_tls_require_cert);
        if (ret != LDAP_OPT_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "ldap_set_option(req_cert) failed: %s\n",
                  sss_ldap_err2string(ret));
            return EIO;
        }
    }

    tls_opt = dp_opt_get_string(basic_opts, SDAP_TLS_CACERT);
    if (tls_opt) {
        ret = ldap_set_option(NULL, LDAP_OPT_X_TLS_CACERTFILE, tls_opt);
        if (ret != LDAP_OPT_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "ldap_set_option(cacertfile) failed: %s\n",
                  sss_ldap_err2string(ret));
            return EIO;
        }
    }

    tls_opt = dp_opt_get_string(basic_opts, SDAP_TLS_CACERTDIR);
    if (tls_opt) {
        ret = ldap_set_option(NULL, LDAP_OPT_X_TLS_CACERTDIR, tls_opt);
        if (ret != LDAP_OPT_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "ldap_set_option(cacertdir) failed: %s\n",
                  sss_ldap_err2string(ret));
            return EIO;
        }
    }

    tls_opt = dp_opt_get_string(basic_opts, SDAP_TLS_CERT);
    if (tls_opt) {
        ret = ldap_set_option(NULL, LDAP_OPT_X_TLS_CERTFILE, tls_opt);
        if (ret != LDAP_OPT_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "ldap_set_option(certfile) failed: %s\n",
                  sss_ldap_err2string(ret));
            return EIO;
        }
    }

    tls_opt = dp_opt_get_string(basic_opts, SDAP_TLS_KEY);
    if (tls_opt) {
        ret = ldap_set_option(NULL, LDAP_OPT_X_TLS_KEYFILE, tls_opt);
        if (ret != LDAP_OPT_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "ldap_set_option(keyfile) failed: %s\n",
                  sss_ldap_err2string(ret));
            return EIO;
        }
    }

    tls_opt = dp_opt_get_string(basic_opts, SDAP_TLS_CIPHER_SUITE);
    if (tls_opt) {
        ret = ldap_set_option(NULL, LDAP_OPT_X_TLS_CIPHER_SUITE, tls_opt);
        if (ret != LDAP_OPT_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "ldap_set_option(cipher) failed: %s\n",
                  sss_ldap_err2string(ret));
            return EIO;
        }
    }

    return EOK;
}

bool sdap_sasl_mech_needs_kinit(const char *sasl_mech)
{
    if (strcasecmp(sasl_mech, "GSSAPI") == 0
            || strcasecmp(sasl_mech, "GSS-SPNEGO") == 0) {
        return true;
    }

    return false;
}

bool sdap_check_sup_list(struct sup_list *l, const char *val)
{
    int i;

    if (!val) {
        return false;
    }

    for (i = 0; i < l->num_vals; i++) {
        if (strcasecmp(val, (char *)l->vals[i])) {
            continue;
        }
        return true;
    }

    return false;
}

static int sdap_init_sup_list(TALLOC_CTX *memctx,
                              struct sup_list *list,
                              int num, struct ldb_val *vals)
{
    int i;

    list->vals = talloc_array(memctx, char *, num);
    if (!list->vals) {
        return ENOMEM;
    }

    for (i = 0; i < num; i++) {
        list->vals[i] = talloc_strndup(list->vals,
                                       (char *)vals[i].data, vals[i].length);
        if (!list->vals[i]) {
            return ENOMEM;
        }
    }

    list->num_vals = num;

    return EOK;
}

int sdap_set_rootdse_supported_lists(struct sysdb_attrs *rootdse,
                                     struct sdap_handle *sh)
{
    struct ldb_message_element *el = NULL;
    int ret;
    int i;

    for (i = 0; i < rootdse->num; i++) {
        el = &rootdse->a[i];
        if (strcasecmp(el->name, "supportedControl") == 0) {

            ret = sdap_init_sup_list(sh, &sh->supported_controls,
                                     el->num_values, el->values);
            if (ret) {
                return ret;
            }
        } else if (strcasecmp(el->name, "supportedExtension") == 0) {

            ret = sdap_init_sup_list(sh, &sh->supported_extensions,
                                     el->num_values, el->values);
            if (ret) {
                return ret;
            }
        } else if (strcasecmp(el->name, "supportedSASLMechanisms") == 0) {

            ret = sdap_init_sup_list(sh, &sh->supported_saslmechs,
                                     el->num_values, el->values);
            if (ret) {
                return ret;
            }
        }
    }

    return EOK;

}

static char *get_single_value_as_string(TALLOC_CTX *mem_ctx,
                                        struct ldb_message_element *el)
{
    char *str = NULL;

    if (el->num_values == 0) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Missing value.\n");
    } else if (el->num_values == 1) {
        str = talloc_strndup(mem_ctx, (char *) el->values[0].data,
                             el->values[0].length);
        if (str == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strndup failed.\n");
        }
    } else {
        DEBUG(SSSDBG_MINOR_FAILURE, "More than one value found.\n");
    }

    return str;
}

static char *get_naming_context(TALLOC_CTX *mem_ctx,
                                struct sysdb_attrs *rootdse)
{
    struct ldb_message_element *nc = NULL;
    struct ldb_message_element *dnc = NULL;
    int i;
    char *naming_context = NULL;

    for (i = 0; i < rootdse->num; i++) {
        if (strcasecmp(rootdse->a[i].name,
                       SDAP_ROOTDSE_ATTR_NAMING_CONTEXTS) == 0) {
            nc = &rootdse->a[i];
        } else if (strcasecmp(rootdse->a[i].name,
                              SDAP_ROOTDSE_ATTR_DEFAULT_NAMING_CONTEXT) == 0) {
            dnc = &rootdse->a[i];
        }
    }

    if (dnc == NULL && nc == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "No attributes [%s] or [%s] found in rootDSE.\n",
                  SDAP_ROOTDSE_ATTR_NAMING_CONTEXTS,
                  SDAP_ROOTDSE_ATTR_DEFAULT_NAMING_CONTEXT);
    } else {
        if (dnc != NULL) {
            DEBUG(SSSDBG_FUNC_DATA,
                  "Using value from [%s] as naming context.\n",
                      SDAP_ROOTDSE_ATTR_DEFAULT_NAMING_CONTEXT);
            naming_context = get_single_value_as_string(mem_ctx, dnc);
        }

        if (naming_context == NULL && nc != NULL) {
            DEBUG(SSSDBG_FUNC_DATA,
                  "Using value from [%s] as naming context.\n",
                      SDAP_ROOTDSE_ATTR_NAMING_CONTEXTS);
            naming_context = get_single_value_as_string(mem_ctx, nc);
        }
    }

    /* Some directory servers such as Novell eDirectory will return
     * a zero-length namingContexts value in some situations. In this
     * case, we should return it as NULL so things fail gracefully.
     */
    if (naming_context && naming_context[0] == '\0') {
        talloc_zfree(naming_context);
    }

    return naming_context;
}

errno_t
sdap_create_search_base(TALLOC_CTX *mem_ctx,
                        struct ldb_context *ldb,
                        const char *unparsed_base,
                        int scope,
                        const char *filter,
                        struct sdap_search_base **_base)
{
    struct sdap_search_base *base;
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    struct ldb_dn *ldn;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        ret = ENOMEM;
        goto done;
    }

    base = talloc_zero(tmp_ctx, struct sdap_search_base);
    if (base == NULL) {
        ret = ENOMEM;
        goto done;
    }

    base->basedn = talloc_strdup(base, unparsed_base);
    if (base->basedn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Validate the basedn */
    ldn = ldb_dn_new(base, ldb, unparsed_base);
    if (!ldn) {
        ret = ENOMEM;
        goto done;
    }

    if (!ldb_dn_validate(ldn)) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid base DN [%s]\n", unparsed_base);
        ret = EINVAL;
        goto done;
    }

    base->ldb = ldb;
    base->ldb_basedn = ldn;
    base->scope = scope;
    base->filter = filter;

    *_base = talloc_steal(mem_ctx, base);
    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t sdap_set_search_base(struct sdap_options *opts,
                                    struct sdap_domain *sdom,
                                    enum sdap_basic_opt class,
                                    char *naming_context)
{
    errno_t ret;
    struct sdap_search_base ***bases;

    switch(class) {
    case SDAP_SEARCH_BASE:
        bases = &sdom->search_bases;
        break;
    case SDAP_USER_SEARCH_BASE:
        bases = &sdom->user_search_bases;
        break;
    case SDAP_GROUP_SEARCH_BASE:
        bases = &sdom->group_search_bases;
        break;
    case SDAP_NETGROUP_SEARCH_BASE:
        bases = &sdom->netgroup_search_bases;
        break;
    case SDAP_HOST_SEARCH_BASE:
        bases = &sdom->host_search_bases;
        break;
    case SDAP_SUDO_SEARCH_BASE:
        bases = &sdom->sudo_search_bases;
        break;
    case SDAP_SERVICE_SEARCH_BASE:
        bases = &sdom->service_search_bases;
        break;
    case SDAP_AUTOFS_SEARCH_BASE:
        bases = &sdom->autofs_search_bases;
        break;
    case SDAP_IPHOST_SEARCH_BASE:
        bases = &sdom->iphost_search_bases;
        break;
    case SDAP_IPNETWORK_SEARCH_BASE:
        bases = &sdom->ipnetwork_search_bases;
        break;
    default:
        return EINVAL;
    }

    DEBUG(SSSDBG_CONF_SETTINGS,
          "Setting option [%s] to [%s].\n",
            opts->basic[class].opt_name, naming_context);

    ret = dp_opt_set_string(opts->basic, class, naming_context);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "dp_opt_set_string failed.\n");
        goto done;
    }

    ret = sdap_parse_search_base(opts, sysdb_ctx_get_ldb(sdom->dom->sysdb),
                                 opts->basic, class, bases);
    if (ret != EOK) goto done;

    ret = EOK;
done:
    return ret;
}

errno_t sdap_set_config_options_with_rootdse(struct sysdb_attrs *rootdse,
                                             struct sdap_options *opts,
                                             struct sdap_domain *sdom)
{
    int ret;
    char *naming_context = NULL;

    if (!sdom->search_bases
            || !sdom->user_search_bases
            || !sdom->group_search_bases
            || !sdom->netgroup_search_bases
            || !sdom->host_search_bases
            || !sdom->sudo_search_bases
            || !sdom->iphost_search_bases
            || !sdom->ipnetwork_search_bases
            || !sdom->autofs_search_bases) {
        naming_context = get_naming_context(opts->basic, rootdse);
        if (naming_context == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "get_naming_context failed.\n");

            /* This has to be non-fatal, since some servers offer
             * multiple namingContexts entries. We will just
             * add NULL checks for the search bases in the lookups.
             */
            ret = EOK;
            goto done;
        }
    }

    /* Default */
    if (!sdom->search_bases) {
        ret = sdap_set_search_base(opts, sdom,
                                   SDAP_SEARCH_BASE,
                                   naming_context);
        if (ret != EOK) goto done;
    }

    /* Users */
    if (!sdom->user_search_bases) {
        ret = sdap_set_search_base(opts, sdom,
                                   SDAP_USER_SEARCH_BASE,
                                   naming_context);
        if (ret != EOK) goto done;
    }

    /* Groups */
    if (!sdom->group_search_bases) {
        ret = sdap_set_search_base(opts, sdom,
                                   SDAP_GROUP_SEARCH_BASE,
                                   naming_context);
        if (ret != EOK) goto done;
    }

    /* Netgroups */
    if (!sdom->netgroup_search_bases) {
        ret = sdap_set_search_base(opts, sdom,
                                   SDAP_NETGROUP_SEARCH_BASE,
                                   naming_context);
        if (ret != EOK) goto done;
    }

    /* Hosts */
    if (!sdom->host_search_bases) {
        ret = sdap_set_search_base(opts, sdom,
                                   SDAP_HOST_SEARCH_BASE,
                                   naming_context);
        if (ret != EOK) goto done;
    }

    /* Sudo */
    if (!sdom->sudo_search_bases) {
       ret = sdap_set_search_base(opts, sdom,
                                   SDAP_SUDO_SEARCH_BASE,
                                   naming_context);
        if (ret != EOK) goto done;
    }

    /* Services */
    if (!sdom->service_search_bases) {
       ret = sdap_set_search_base(opts, sdom,
                                  SDAP_SERVICE_SEARCH_BASE,
                                  naming_context);
        if (ret != EOK) goto done;
    }

    /* autofs */
    if (!sdom->autofs_search_bases) {
       ret = sdap_set_search_base(opts, sdom,
                                  SDAP_AUTOFS_SEARCH_BASE,
                                  naming_context);
        if (ret != EOK) goto done;
    }

    /* IP host */
    if (!sdom->iphost_search_bases) {
        ret = sdap_set_search_base(opts, sdom,
                                   SDAP_IPHOST_SEARCH_BASE,
                                   naming_context);
        if (ret != EOK) goto done;
    }

    /* IP network */
    if (!sdom->ipnetwork_search_bases) {
        ret = sdap_set_search_base(opts, sdom,
                                   SDAP_IPNETWORK_SEARCH_BASE,
                                   naming_context);
        if (ret != EOK) goto done;
    }

    ret = EOK;

done:
    talloc_free(naming_context);
    return ret;
}

int sdap_get_server_opts_from_rootdse(TALLOC_CTX *memctx,
                                      const char *server,
                                      struct sysdb_attrs *rootdse,
                                      struct sdap_options *opts,
                                      struct sdap_server_opts **srv_opts)
{
    struct sdap_server_opts *so;
    struct {
        const char *last_name;
        const char *entry_name;
    } usn_attrs[] = { { SDAP_IPA_LAST_USN, SDAP_IPA_USN },
                      { SDAP_AD_LAST_USN, SDAP_AD_USN },
                      { NULL, NULL } };
    const char *last_usn_name;
    const char *last_usn_value;
    const char *entry_usn_name;
    const char *schema_nc = NULL;
    char *endptr = NULL;
    int ret;
    int i;
    uint32_t dc_level;

    so = talloc_zero(memctx, struct sdap_server_opts);
    if (!so) {
        return ENOMEM;
    }
    so->server_id = talloc_strdup(so, server);
    if (!so->server_id) {
        talloc_zfree(so);
        return ENOMEM;
    }

    last_usn_name = opts->gen_map[SDAP_AT_LAST_USN].name;
    entry_usn_name = opts->gen_map[SDAP_AT_ENTRY_USN].name;
    if (rootdse) {
        if (last_usn_name) {
            ret = sysdb_attrs_get_string(rootdse,
                                          last_usn_name, &last_usn_value);
            if (ret != EOK) {
                switch (ret) {
                case ENOENT:
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "%s configured but not found in rootdse!\n",
                              opts->gen_map[SDAP_AT_LAST_USN].opt_name);
                    break;
                case ERANGE:
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Multiple values of %s found in rootdse!\n",
                              opts->gen_map[SDAP_AT_LAST_USN].opt_name);
                    break;
                default:
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Unknown error (%d) checking rootdse!\n", ret);
                }
            } else {
                if (!entry_usn_name) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "%s found in rootdse but %s is not set!\n",
                              last_usn_name,
                              opts->gen_map[SDAP_AT_ENTRY_USN].opt_name);
                } else {
                    so->supports_usn = true;
                    errno = 0;
                    so->last_usn = strtoul(last_usn_value, &endptr, 10);
                    if (errno || !endptr || *endptr || (endptr == last_usn_value)) {
                        DEBUG(SSSDBG_MINOR_FAILURE,
                              "USN is not valid (value: %s)\n", last_usn_value);
                        so->last_usn = 0;
                    } else {
                        DEBUG(SSSDBG_TRACE_ALL,
                              "USN value: %s (int: %lu)\n", last_usn_value, so->last_usn);
                    }
                }
            }
        } else {
            /* no usn option configure, let's try to autodetect. */
            for (i = 0; usn_attrs[i].last_name; i++) {
                ret = sysdb_attrs_get_string(rootdse,
                                             usn_attrs[i].last_name,
                                             &last_usn_value);
                if (ret == EOK) {
                    /* Fixate discovered configuration */
                    opts->gen_map[SDAP_AT_LAST_USN].name =
                        talloc_strdup(opts->gen_map, usn_attrs[i].last_name);
                    opts->gen_map[SDAP_AT_ENTRY_USN].name =
                        talloc_strdup(opts->gen_map, usn_attrs[i].entry_name);
                    so->supports_usn = true;
                    errno = 0;
                    so->last_usn = strtoul(last_usn_value, &endptr, 10);
                    if (errno || !endptr || *endptr || (endptr == last_usn_value)) {
                        DEBUG(SSSDBG_MINOR_FAILURE,
                              "USN is not valid (value: %s)\n", last_usn_value);
                        so->last_usn = 0;
                    } else {
                        DEBUG(SSSDBG_TRACE_ALL,
                              "USN value: %s (int: %lu)\n", last_usn_value, so->last_usn);
                    }
                    last_usn_name = usn_attrs[i].last_name;
                    break;
                }
            }
        }

        /* Detect Active Directory version if available */
        ret = sysdb_attrs_get_uint32_t(rootdse,
                                       SDAP_ROOTDSE_ATTR_AD_VERSION,
                                       &dc_level);
        if (ret == EOK) {
            /* Validate that the DC level matches an expected value */
            switch(dc_level) {
            case DS_BEHAVIOR_WIN2000:
            case DS_BEHAVIOR_WIN2003:
            case DS_BEHAVIOR_WIN2008:
            case DS_BEHAVIOR_WIN2008R2:
            case DS_BEHAVIOR_WIN2012:
            case DS_BEHAVIOR_WIN2012R2:
            case DS_BEHAVIOR_WIN2016:
                opts->dc_functional_level = dc_level;
                DEBUG(SSSDBG_CONF_SETTINGS,
                      "Setting AD compatibility level to [%d]\n",
                       opts->dc_functional_level);
                break;
            default:
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Received invalid value [%d] for AD compatibility level. "
                      "Using the lowest-common compatibility level\n",
                      dc_level);
                opts->dc_functional_level = DS_BEHAVIOR_WIN2003;
            }
        } else if (ret != ENOENT) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Error detecting Active Directory compatibility level "
                   "(%s). Continuing without AD performance enhancements\n",
                   strerror(ret));
        }

        ret = sysdb_attrs_get_string(rootdse,
                                     SDAP_ROOTDSE_ATTR_AD_SCHEMA_NC,
                                     &schema_nc);
        if (ret == EOK) {
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "Will look for schema at [%s]\n", schema_nc);
            opts->schema_basedn = talloc_strdup(opts, schema_nc);
        }
    }

    if (!last_usn_name) {
        DEBUG(SSSDBG_FUNC_DATA,
              "No known USN scheme is supported by this server!\n");
        if (!entry_usn_name) {
            DEBUG(SSSDBG_FUNC_DATA,
                  "Will use modification timestamp as usn!\n");
            opts->gen_map[SDAP_AT_ENTRY_USN].name =
                talloc_strdup(opts->gen_map, "modifyTimestamp");
        }
    }

    if (!opts->user_map[SDAP_AT_USER_USN].name) {
        opts->user_map[SDAP_AT_USER_USN].name =
                    talloc_strdup(opts->user_map,
                                  opts->gen_map[SDAP_AT_ENTRY_USN].name);
    }
    if (!opts->group_map[SDAP_AT_GROUP_USN].name) {
        opts->group_map[SDAP_AT_GROUP_USN].name =
                    talloc_strdup(opts->group_map,
                                  opts->gen_map[SDAP_AT_ENTRY_USN].name);
    }
    if (!opts->service_map[SDAP_AT_SERVICE_USN].name) {
        opts->service_map[SDAP_AT_SERVICE_USN].name =
                    talloc_strdup(opts->service_map,
                                  opts->gen_map[SDAP_AT_ENTRY_USN].name);
    }
    if (opts->sudorule_map &&
        !opts->sudorule_map[SDAP_AT_SUDO_USN].name) {
        opts->sudorule_map[SDAP_AT_SUDO_USN].name =
                    talloc_strdup(opts->sudorule_map,
                                  opts->gen_map[SDAP_AT_ENTRY_USN].name);
    }
    if (opts->iphost_map &&
        !opts->iphost_map[SDAP_AT_IPHOST_USN].name) {
        opts->iphost_map[SDAP_AT_IPHOST_USN].name =
                    talloc_strdup(opts->iphost_map,
                                  opts->gen_map[SDAP_AT_ENTRY_USN].name);
    }
    if (opts->ipnetwork_map &&
        !opts->ipnetwork_map[SDAP_AT_IPNETWORK_USN].name) {
        opts->ipnetwork_map[SDAP_AT_IPNETWORK_USN].name =
                    talloc_strdup(opts->ipnetwork_map,
                                  opts->gen_map[SDAP_AT_ENTRY_USN].name);
    }

    *srv_opts = so;
    return EOK;
}

void sdap_steal_server_opts(struct sdap_id_ctx *id_ctx,
                            struct sdap_server_opts **srv_opts)
{
    if (!id_ctx || !srv_opts || !*srv_opts) {
        return;
    }

    if (!id_ctx->srv_opts) {
        id_ctx->srv_opts = talloc_move(id_ctx, srv_opts);
        return;
    }

    /* discard if same as previous so we do not reset max usn values
     * unnecessarily, only update last_usn. */
    if (strcmp(id_ctx->srv_opts->server_id, (*srv_opts)->server_id) == 0) {
        id_ctx->srv_opts->last_usn = (*srv_opts)->last_usn;
        talloc_zfree(*srv_opts);
        return;
    }

    talloc_zfree(id_ctx->srv_opts);
    id_ctx->srv_opts = talloc_move(id_ctx, srv_opts);
}

static bool attr_is_filtered(const char *attr, const char **filter)
{
    int i;

    if (filter) {
        i = 0;
        while (filter[i]) {
            if (filter[i] == attr ||
                strcasecmp(filter[i], attr) == 0) {
                return true;
            }
            i++;
        }
    }

    return false;
}

int build_attrs_from_map(TALLOC_CTX *memctx,
                         struct sdap_attr_map *map,
                         size_t size,
                         const char **filter,
                         const char ***_attrs,
                         size_t *attr_count)
{
    errno_t ret;
    const char **attrs;
    int i, j;
    TALLOC_CTX *tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    /* Assume that all entries in the map have values */
    attrs = talloc_zero_array(tmp_ctx, const char *, size + 1);
    if (!attrs) {
        ret = ENOMEM;
        goto done;
    }

    /* first attribute is "objectclass" not the specific one */
    attrs[0] = talloc_strdup(memctx, "objectClass");
    if (!attrs[0]) return ENOMEM;

    /* add the others */
    for (i = j = 1; i < size; i++) {
        if (map[i].name && !attr_is_filtered(map[i].name, filter)) {
            attrs[j] = map[i].name;
            j++;
        }
    }
    attrs[j] = NULL;

    /* Trim down the used memory if some attributes were NULL */
    attrs = talloc_realloc(tmp_ctx, attrs, const char *, j + 1);
    if (!attrs) {
        ret = ENOMEM;
        goto done;
    }

    *_attrs = talloc_steal(memctx, attrs);
    if (attr_count) *attr_count = j;

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

int sdap_control_create(struct sdap_handle *sh, const char *oid, int iscritical,
                        struct berval *value, int dupval, LDAPControl **ctrlp)
{
    int ret;

    if (sdap_is_control_supported(sh, oid)) {
        ret = sss_ldap_control_create(oid, iscritical, value, dupval, ctrlp);
        if (ret != LDAP_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "sss_ldap_control_create failed [%d][%s].\n",
                      ret, sss_ldap_err2string(ret));
        }
    } else {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Server does not support the requested control [%s].\n", oid);
        ret = LDAP_NOT_SUPPORTED;
    }

    return ret;
}

int sdap_replace_id(struct sysdb_attrs *entry, const char *attr, id_t val)
{
    char *str;
    errno_t ret;
    struct ldb_message_element *el;

    ret = sysdb_attrs_get_el_ext(entry, attr, false, &el);
    if (ret == ENOENT) {
        return sysdb_attrs_add_uint32(entry, attr, val);
    } else if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot get attribute [%s]\n", attr);
        return ret;
    }

    if (el->num_values != 1) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Expected 1 value for %s, got %d\n", attr, el->num_values);
        return EINVAL;
    }

    str = talloc_asprintf(entry, "%llu", (unsigned long long) val);
    if (!str) {
        return ENOMEM;
    }

    el->values[0].data = (uint8_t *) str;
    el->values[0].length = strlen(str);

    return EOK;
}

static errno_t sdap_get_rdn_multi(TALLOC_CTX *mem_ctx, const char *dn,
                                  const char *name, char **_val)
{
    int ret;
    size_t c;
    LDAPDN ldapdn = NULL;

    ret = ldap_str2dn(dn, &ldapdn, LDAP_DN_FORMAT_LDAPV3);
    if (ret != LDAP_SUCCESS || ldapdn == NULL || ldapdn[0] == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to parse DN [%s].\n", dn);
        ret = EINVAL;
        goto done;
    }

    ret = ENOENT;
    for (c = 0; ldapdn[0][c] != NULL; c++) {
        if (strncasecmp(name, ldapdn[0][c]->la_attr.bv_val,
                        ldapdn[0][c]->la_attr.bv_len) == 0) {
            *_val = talloc_strndup(mem_ctx, ldapdn[0][c]->la_value.bv_val,
                                   ldapdn[0][c]->la_value.bv_len);
            if (*_val == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "Failed to copy AVA value.\n");
                ret = ENOMEM;
                goto done;
            }
            ret = EOK;
            break;
        }
    }

done:
    ldap_dnfree(ldapdn);

    return ret;
}

errno_t sdap_get_primary_name(const char *attr_name,
                              struct sysdb_attrs *attrs,
                              const char **_primary_name)
{
    errno_t ret;
    const char *orig_name = NULL;
    char *rdn_val = NULL;
    struct ldb_message_element *sysdb_name_el;
    struct ldb_message_element *orig_dn_el;
    size_t i;
    TALLOC_CTX *tmp_ctx = NULL;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ret = sysdb_attrs_get_el(attrs,
                             SYSDB_NAME,
                             &sysdb_name_el);
    if (ret != EOK || sysdb_name_el->num_values == 0) {
        ret = EINVAL;
        goto done;
    }

    if (sysdb_name_el->num_values == 1) {
        /* Entry contains only one name. Just return that */
        orig_name = (const char *)sysdb_name_el->values[0].data;
        ret = EOK;
        goto done;
    }

    /* Multiple values for name. Check whether one matches the RDN */

    ret = sysdb_attrs_get_el(attrs, SYSDB_ORIG_DN, &orig_dn_el);
    if (ret) {
        goto done;
    }
    if (orig_dn_el->num_values == 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Original DN is not available.\n");
        ret = EINVAL;
        goto done;
    } else if (orig_dn_el->num_values == 1) {
        ret = sdap_get_rdn_multi(tmp_ctx,
                                 (const char *) orig_dn_el->values[0].data,
                                 attr_name, &rdn_val);
        if (ret == ENOENT) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "The entry has multiple names and the RDN attribute does "
                  "not match. Will use the first value [%s] as fallback.\n",
                  (const char *)sysdb_name_el->values[0].data);
            orig_name = (const char *)sysdb_name_el->values[0].data;
            ret = EOK;
            goto done;
        } else if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not get rdn from [%s]\n",
                      (const char *) orig_dn_el->values[0].data);
            goto done;
        }
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE, "Should not have more than one origDN\n");
        ret = EINVAL;
        goto done;
    }

    for (i = 0; i < sysdb_name_el->num_values; i++) {
        if (strcasecmp(rdn_val,
                       (const char *)sysdb_name_el->values[i].data) == 0) {
            /* This name matches the RDN. Use it */
            break;
        }
    }
    if (i < sysdb_name_el->num_values) {
        /* Match was found */
        orig_name = (const char *)sysdb_name_el->values[i].data;
    } else {
        /* If we can't match the name to the RDN, we just have to
         * throw up our hands. There's no deterministic way to
         * decide which name is correct.
         */
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Can't match the name to the RDN\n");
        ret = EINVAL;
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not determine primary name: [%d][%s]\n",
                  ret, strerror(ret));
    }
    talloc_free(tmp_ctx);

    DEBUG(SSSDBG_TRACE_FUNC, "Processing object %s\n", orig_name);

    *_primary_name = orig_name;

    return ret;
}

static errno_t
sdap_get_primary_fqdn(TALLOC_CTX *mem_ctx,
                      struct sdap_idmap_ctx *idmap_ctx,
                      const char *attr_name,
                      const char *sid_attr_name,
                      struct sysdb_attrs *attrs,
                      struct sss_domain_info *dom,
                      const char **_primary_fqdn)
{
    errno_t ret;
    const char *shortname = NULL;
    const char *primary_fqdn = NULL;
    TALLOC_CTX *tmp_ctx;
    char *sid_str = NULL;
    struct sss_domain_info *subdomain = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sdap_get_primary_name(attr_name, attrs, &shortname);
    if (ret != EOK) {
        goto done;
    }

    /* In AD scenarion, the object can be from subdomain - identify it by SID */
    if (sid_attr_name != NULL) {
        ret = sdap_attrs_get_sid_str(tmp_ctx,
                                     idmap_ctx,
                                     attrs,
                                     sid_attr_name,
                                     &sid_str);

        if (ret == EOK) {
            DEBUG(SSSDBG_TRACE_INTERNAL, "Group has objectSID [%s]\n", sid_str);
            subdomain = find_domain_by_sid(dom, sid_str);
            talloc_free(sid_str);
            if (subdomain != NULL) {
                dom = subdomain;
            }
        }
        DEBUG(SSSDBG_TRACE_INTERNAL, "Group has name [%s]\n", dom->name);
    }

    primary_fqdn = sss_create_internal_fqname(tmp_ctx, shortname, dom->name);
    if (primary_fqdn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;
    *_primary_fqdn = talloc_steal(mem_ctx, primary_fqdn);
done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sdap_get_user_primary_name(TALLOC_CTX *memctx,
                                   struct sdap_options *opts,
                                   struct sysdb_attrs *attrs,
                                   struct sss_domain_info *dom,
                                   const char **_user_name)
{
    return sdap_get_primary_fqdn(memctx,
                                 opts->idmap_ctx,
                                 opts->user_map[SDAP_AT_USER_NAME].name,
                                 opts->group_map[SDAP_AT_USER_OBJECTSID].name,
                                 attrs, dom, _user_name);
}

errno_t sdap_get_group_primary_name(TALLOC_CTX *memctx,
                                    struct sdap_options *opts,
                                    struct sysdb_attrs *attrs,
                                    struct sss_domain_info *dom,
                                    const char **_group_name)
{
    return sdap_get_primary_fqdn(memctx,
                                 opts->idmap_ctx,
                                 opts->group_map[SDAP_AT_GROUP_NAME].name,
                                 opts->group_map[SDAP_AT_GROUP_OBJECTSID].name,
                                 attrs, dom, _group_name);
}

errno_t sdap_get_netgroup_primary_name(struct sdap_options *opts,
                                       struct sysdb_attrs *attrs,
                                       const char **_netgroup_name)
{
    return sdap_get_primary_name(opts->netgroup_map[SDAP_AT_NETGROUP_NAME].name,
                                 attrs, _netgroup_name);
}

static errno_t
_sdap_get_primary_name_list(struct sss_domain_info *domain,
                            TALLOC_CTX *mem_ctx,
                            struct sysdb_attrs **attr_list,
                            size_t attr_count,
                            const char *ldap_attr,
                            bool qualify_names,
                            const char *sid_attr,
                            struct sdap_idmap_ctx *idmap_ctx,
                            char ***name_list)
{
    errno_t ret;
    size_t i, j;
    char **list;
    const char *name;

    /* Assume that every entry has a primary name */
    list = talloc_array(mem_ctx, char *, attr_count+1);
    if (!list) {
        return ENOMEM;
    }

    j = 0;
    for (i = 0; i < attr_count; i++) {
        if (qualify_names == false) {
            ret = sdap_get_primary_name(ldap_attr, attr_list[i], &name);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Could not determine primary name\n");
                /* Skip and continue. Don't advance 'j' */
                continue;
            }
            list[j] = talloc_strdup(list, name);
        } else {
            ret = sdap_get_primary_fqdn(mem_ctx,
                                        idmap_ctx,
                                        ldap_attr,
                                        sid_attr,
                                        attr_list[i],
                                        domain,
                                        &name);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Could not determine primary fqdn name\n");
                /* Skip and continue. Don't advance 'j' */
                continue;
            }
            list[j] = talloc_strdup(list, name);
        }
        if (!list[j]) {
            ret = ENOMEM;
            goto done;
        }

        j++;
    }

    /* NULL-terminate the list */
    list[j] = NULL;

    *name_list = list;

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(list);
    }
    return ret;
}

errno_t sdap_get_primary_name_list(struct sss_domain_info *domain,
                                   TALLOC_CTX *mem_ctx,
                                   struct sysdb_attrs **attr_list,
                                   size_t attr_count,
                                   const char *ldap_attr,
                                   char ***name_list)
{
    return _sdap_get_primary_name_list(domain, mem_ctx, attr_list, attr_count,
                                       ldap_attr, false, NULL, NULL, name_list);
}

errno_t sdap_get_primary_fqdn_list(struct sss_domain_info *domain,
                                   TALLOC_CTX *mem_ctx,
                                   struct sysdb_attrs **attr_list,
                                   size_t attr_count,
                                   const char *ldap_attr,
                                   const char *sid_attr,
                                   struct sdap_idmap_ctx *idmap_ctx,
                                   char ***name_list)
{
    return _sdap_get_primary_name_list(domain, mem_ctx, attr_list, attr_count,
                                       ldap_attr, true, sid_attr, idmap_ctx, name_list);
}


char *sdap_make_oc_list(TALLOC_CTX *mem_ctx, struct sdap_attr_map *map)
{
    if (map[SDAP_OC_GROUP_ALT].name == NULL) {
        return talloc_asprintf(mem_ctx, "objectClass=%s",
                               map[SDAP_OC_GROUP].name);
    } else {
        return talloc_asprintf(mem_ctx,
                               "|(objectClass=%s)(objectClass=%s)",
                               map[SDAP_OC_GROUP].name,
                               map[SDAP_OC_GROUP_ALT].name);
    }
}

struct sss_domain_info *sdap_get_object_domain(struct sdap_options *opts,
                                               struct sysdb_attrs *obj,
                                               struct sss_domain_info *dom)
{
    errno_t ret;
    const char *original_dn = NULL;
    struct sdap_domain *sdmatch = NULL;

    ret = sysdb_attrs_get_string(obj, SYSDB_ORIG_DN, &original_dn);
    if (ret) {
        DEBUG(SSSDBG_FUNC_DATA,
              "The group has no original DN, assuming our domain\n");
        return dom;
    }

    sdmatch = sdap_domain_get_by_dn(opts, original_dn);
    if (sdmatch == NULL) {
        DEBUG(SSSDBG_FUNC_DATA,
              "The original DN of the group cannot "
              "be related to any search base\n");
        return dom;
    }

    return sdmatch->dom;
}

bool sdap_object_in_domain(struct sdap_options *opts,
                           struct sysdb_attrs *obj,
                           struct sss_domain_info *dom)
{
    struct sss_domain_info *obj_dom;

    obj_dom = sdap_get_object_domain(opts, obj, dom);
    if (obj_dom == NULL) {
        return false;
    }

    return (obj_dom == dom);
}

size_t sdap_steal_objects_in_dom(struct sdap_options *opts,
                                 struct sysdb_attrs **dom_objects,
                                 size_t offset,
                                 struct sss_domain_info *dom,
                                 struct sysdb_attrs **all_objects,
                                 size_t count,
                                 bool filter)
{
    size_t copied = 0;

    /* Own objects from all_objects by dom_objects in case they belong
     * to domain dom.
     *
     * Don't copy objects from other domains in case
     * the search was for parent domain but a child domain would match,
     * too, such as:
     *  dc=example,dc=com
     *  dc=child,dc=example,dc=com
     * while searching for an object from dc=example.
     */
    for (size_t i = 0; i < count; i++) {
        if (filter &&
                sdap_object_in_domain(opts, all_objects[i], dom) == false) {
            continue;
        }

        dom_objects[offset + copied] =
            talloc_steal(dom_objects, all_objects[i]);
        copied++;
    }

    return copied;
}

void sdap_domain_copy_search_bases(struct sdap_domain *to,
                                   struct sdap_domain *from)
{
    to->search_bases = from->search_bases;
    to->user_search_bases = from->user_search_bases;
    to->group_search_bases = from->group_search_bases;
    to->netgroup_search_bases = from->netgroup_search_bases;
    to->sudo_search_bases = from->sudo_search_bases;
    to->service_search_bases = from->service_search_bases;
    to->iphost_search_bases = from->iphost_search_bases;
    to->ipnetwork_search_bases = from->ipnetwork_search_bases;
    to->autofs_search_bases = from->autofs_search_bases;
}
