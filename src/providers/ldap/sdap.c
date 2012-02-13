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

/* =Retrieve-Options====================================================== */

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

    map = talloc_array(memctx, struct sdap_attr_map, num_entries);
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
            DEBUG(0, ("Failed to retrieve value for %s\n", map[i].opt_name));
            talloc_zfree(map);
            return EINVAL;
        }

        if (name) {
            ret = sss_filter_sanitize(map, name, &map[i].name);
            if (ret != EOK) {
                DEBUG(1, ("Could not sanitize attribute [%s]\n", name));
                talloc_zfree(map);
                return EINVAL;
            }
            talloc_zfree(name);
        } else {
            map[i].name = NULL;
        }

        if (map[i].def_name && !map[i].name) {
            DEBUG(0, ("Failed to retrieve value for %s\n", map[i].opt_name));
            if (ret != EOK) {
                talloc_zfree(map);
                return EINVAL;
            }
        }

        DEBUG(5, ("Option %s has value %s\n", map[i].opt_name, map[i].name));
    }

    *_map = map;
    return EOK;
}

/* =Parse-msg============================================================= */

int sdap_parse_entry(TALLOC_CTX *memctx,
                     struct sdap_handle *sh, struct sdap_msg *sm,
                     struct sdap_attr_map *map, int attrs_num,
                     struct sysdb_attrs **_attrs, char **_dn)
{
    struct sysdb_attrs *attrs;
    BerElement *ber = NULL;
    struct berval **vals;
    struct ldb_val v;
    char *str;
    int lerrno;
    int a, i, ret;
    const char *name;
    bool store;
    bool base64;

    lerrno = 0;
    ret = ldap_set_option(sh->ldap, LDAP_OPT_RESULT_CODE, &lerrno);
    if (ret != LDAP_OPT_SUCCESS) {
        DEBUG(1, ("ldap_set_option failed [%s], ignored.\n",
                  sss_ldap_err2string(ret)));
    }

    attrs = sysdb_new_attrs(memctx);
    if (!attrs) return ENOMEM;

    str = ldap_get_dn(sh->ldap, sm->msg);
    if (!str) {
        ldap_get_option(sh->ldap, LDAP_OPT_RESULT_CODE, &lerrno);
        DEBUG(1, ("ldap_get_dn failed: %d(%s)\n",
                  lerrno, sss_ldap_err2string(lerrno)));
        ret = EIO;
        goto fail;
    }

    DEBUG(9, ("OriginalDN: [%s].\n", str));
    ret = sysdb_attrs_add_string(attrs, SYSDB_ORIG_DN, str);
    if (ret) goto fail;
    if (_dn) {
        *_dn = talloc_strdup(memctx, str);
        if (!*_dn) {
            ret = ENOMEM;
            ldap_memfree(str);
            goto fail;
        }
    }
    ldap_memfree(str);

    if (map) {
        vals = ldap_get_values_len(sh->ldap, sm->msg, "objectClass");
        if (!vals) {
            DEBUG(1, ("Unknown entry type, no objectClasses found!\n"));
            ret = EINVAL;
            goto fail;
        }

        for (i = 0; vals[i]; i++) {
            /* the objectclass is always the first name in the map */
            if (strncasecmp(map[0].name,
                            vals[i]->bv_val, vals[i]->bv_len) == 0) {
                /* ok it's an entry of the right type */
                break;
            }
        }
        if (!vals[i]) {
            DEBUG(1, ("objectClass not matching: %s\n",
                      map[0].name));
            ldap_value_free_len(vals);
            ret = EINVAL;
            goto fail;
        }
        ldap_value_free_len(vals);
    }

    str = ldap_first_attribute(sh->ldap, sm->msg, &ber);
    if (!str) {
        ldap_get_option(sh->ldap, LDAP_OPT_RESULT_CODE, &lerrno);
        DEBUG(1, ("Entry has no attributes [%d(%s)]!?\n",
                  lerrno, sss_ldap_err2string(lerrno)));
        if (map) {
            ret = EINVAL;
            goto fail;
        }
    }
    while (str) {
        base64 = false;
        if (map) {
            for (a = 1; a < attrs_num; a++) {
                /* check if this attr is valid with the chosen schema */
                if (!map[a].name) continue;
                /* check if it is an attr we are interested in */
                if (strcasecmp(str, map[a].name) == 0) break;
            }
            /* interesting attr */
            if (a < attrs_num) {
                store = true;
                name = map[a].sys_name;
                if (strcmp(name, SYSDB_SSH_PUBKEY) == 0) {
                    base64 = true;
                }
            } else {
                store = false;
                name = NULL;
            }
        } else {
            name = str;
            store = true;
        }

        if (strstr(str, ";range=") != NULL) {
            DEBUG(1, ("Attribute [%s] has range sub-attribute "
                      "which is currently not supported, skipping.\n", str));
            store = false;
        }

        if (store) {
            vals = ldap_get_values_len(sh->ldap, sm->msg, str);
            if (!vals) {
                ldap_get_option(sh->ldap, LDAP_OPT_RESULT_CODE, &lerrno);
                if (lerrno != LDAP_SUCCESS) {
                    DEBUG(1, ("LDAP Library error: %d(%s)",
                              lerrno, sss_ldap_err2string(lerrno)));
                    ret = EIO;
                    goto fail;
                }

                DEBUG(5, ("Attribute [%s] has no values, skipping.\n", str));

            } else {
                if (!vals[0]) {
                    DEBUG(1, ("Missing value after ldap_get_values() ??\n"));
                    ret = EINVAL;
                    goto fail;
                }
                for (i = 0; vals[i]; i++) {
                    if (base64) {
                        v.data = (uint8_t *)sss_base64_encode(attrs,
                                (uint8_t *)vals[i]->bv_val, vals[i]->bv_len);
                        if (!v.data) {
                            ret = ENOMEM;
                            goto fail;
                        }
                        v.length = strlen((const char *)v.data);
                    } else {
                        v.data = (uint8_t *)vals[i]->bv_val;
                        v.length = vals[i]->bv_len;
                    }

                    ret = sysdb_attrs_add_val(attrs, name, &v);
                    if (ret) goto fail;
                }
                ldap_value_free_len(vals);
            }
        }

        ldap_memfree(str);
        str = ldap_next_attribute(sh->ldap, sm->msg, ber);
    }
    ber_free(ber, 0);

    ldap_get_option(sh->ldap, LDAP_OPT_RESULT_CODE, &lerrno);
    if (lerrno) {
        DEBUG(1, ("LDAP Library error: %d(%s)",
                  lerrno, sss_ldap_err2string(lerrno)));
        ret = EIO;
        goto fail;
    }

    *_attrs = attrs;
    return EOK;

fail:
    if (ber) ber_free(ber, 0);
    talloc_free(attrs);
    return ret;
}

/* This function converts an ldap message into a sysdb_attrs structure.
 * It converts only known user attributes, the rest are ignored.
 * If the entry is not that of an user an error is returned.
 * The original DN is stored as an attribute named originalDN */

int sdap_parse_user(TALLOC_CTX *memctx, struct sdap_options *opts,
                    struct sdap_handle *sh, struct sdap_msg *sm,
                    struct sysdb_attrs **_attrs, char **_dn)
{

    return sdap_parse_entry(memctx, sh, sm, opts->user_map,
                            SDAP_OPTS_USER, _attrs, _dn);
}

/* This function converts an ldap message into a sysdb_attrs structure.
 * It converts only known group attributes, the rest are ignored.
 * If the entry is not that of an user an error is returned.
 * The original DN is stored as an attribute named originalDN */

int sdap_parse_group(TALLOC_CTX *memctx, struct sdap_options *opts,
                     struct sdap_handle *sh, struct sdap_msg *sm,
                     struct sysdb_attrs **_attrs, char **_dn)
{

    return sdap_parse_entry(memctx, sh, sm, opts->group_map,
                            SDAP_OPTS_GROUP, _attrs, _dn);
}

/* Parses an LDAPDerefRes into sdap_deref_attrs structure */
errno_t sdap_parse_deref(TALLOC_CTX *mem_ctx,
                         struct sdap_attr_map_info *minfo,
                         size_t num_maps,
                         LDAPDerefRes *dref,
                         struct sdap_deref_attrs ***_res)
{
    TALLOC_CTX *tmp_ctx;
    LDAPDerefVal *dval;
    const char *orig_dn;
    const char **ocs;
    struct sdap_attr_map *map;
    int num_attrs;
    struct ldb_val v;
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
        DEBUG(2, ("Entry has no DN?\n"));
        ret = EINVAL;
        goto done;
    }

    orig_dn = dref->derefVal.bv_val;
    DEBUG(SSSDBG_TRACE_LIBS,
          ("Dereferenced DN: %s\n", orig_dn));

    if (!dref->attrVals) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("Dereferenced entry [%s] has no attributes\n",
              orig_dn));
        ret = EINVAL;
        goto done;
    }

    ocs = NULL;
    for (dval = dref->attrVals; dval != NULL; dval = dval->next) {
        if (strcasecmp("objectClass", dval->type) == 0) {
            if (dval->vals == NULL) {
                DEBUG(4, ("No value for objectClass, skipping\n"));
                continue;
            }

            for(len=0; dval->vals[len].bv_val; len++);

            ocs = talloc_array(tmp_ctx, const char *, len+1);
            if (!ocs) {
                ret = ENOMEM;
                goto done;
            }

            for (i=0; i<len; i++) {
                DEBUG(9, ("Dereferenced objectClass value: %s\n",
                          dval->vals[i].bv_val));
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
        DEBUG(1, ("Unknown entry type, no objectClasses found!\n"));
        ret = EINVAL;
        goto done;
    }

    for (mi = 0; mi < num_maps; mi++) {
        map = NULL;

        for (i=0; ocs[i]; i++) {
            /* the objectclass is always the first name in the map */
            if (strcasecmp(minfo[mi].map[0].name, ocs[i]) == 0) {
                DEBUG(9, ("Found map for objectclass '%s'\n", ocs[i]));
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

        for (dval = dref->attrVals; dval != NULL; dval = dval->next) {
            DEBUG(8, ("Dereferenced attribute: %s\n", dval->type));

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
                DEBUG(4, ("No value for attribute %s, skipping\n", name));
                continue;
            }

            for (i=0; dval->vals[i].bv_val; i++) {
                DEBUG(9, ("Dereferenced attribute value: %s\n",
                          dval->vals[i].bv_val));
                v.data = (uint8_t *) dval->vals[i].bv_val;
                v.length = dval->vals[i].bv_len;

                ret = sysdb_attrs_add_val(res[mi]->attrs, name, &v);
                if (ret) goto done;
            }
        }
    }


    *_res = talloc_steal(mem_ctx, res);
    ret = EOK;
done:
    talloc_zfree(tmp_ctx);
    return ret;
}

/* =Get-DN-from-message=================================================== */

int sdap_get_msg_dn(TALLOC_CTX *memctx, struct sdap_handle *sh,
                    struct sdap_msg *sm, char **_dn)
{
    char *str;
    int lerrno;
    int ret;

    lerrno = 0;
    ret = ldap_set_option(sh->ldap, LDAP_OPT_RESULT_CODE, &lerrno);
    if (ret != LDAP_OPT_SUCCESS) {
        DEBUG(1, ("ldap_set_option failed [%s], ignored.\n",
                  sss_ldap_err2string(ret)));
    }

    str = ldap_get_dn(sh->ldap, sm->msg);
    if (!str) {
        ldap_get_option(sh->ldap, LDAP_OPT_RESULT_CODE, &lerrno);
        DEBUG(1, ("ldap_get_dn failed: %d(%s)\n",
                  lerrno, sss_ldap_err2string(lerrno)));
        return EIO;
    }

    *_dn = talloc_strdup(memctx, str);
    ldap_memfree(str);
    if (!*_dn) return ENOMEM;

    return EOK;
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
            DEBUG(1, ("Unknown value for tls_reqcert.\n"));
            return EINVAL;
        }
        /* LDAP_OPT_X_TLS_REQUIRE_CERT has to be set as a global option,
         * because the SSL/TLS context is initialized from this value. */
        ret = ldap_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT,
                              &ldap_opt_x_tls_require_cert);
        if (ret != LDAP_OPT_SUCCESS) {
            DEBUG(1, ("ldap_set_option failed: %s\n", sss_ldap_err2string(ret)));
            return EIO;
        }
    }

    tls_opt = dp_opt_get_string(basic_opts, SDAP_TLS_CACERT);
    if (tls_opt) {
        ret = ldap_set_option(NULL, LDAP_OPT_X_TLS_CACERTFILE, tls_opt);
        if (ret != LDAP_OPT_SUCCESS) {
            DEBUG(1, ("ldap_set_option failed: %s\n", sss_ldap_err2string(ret)));
            return EIO;
        }
    }

    tls_opt = dp_opt_get_string(basic_opts, SDAP_TLS_CACERTDIR);
    if (tls_opt) {
        ret = ldap_set_option(NULL, LDAP_OPT_X_TLS_CACERTDIR, tls_opt);
        if (ret != LDAP_OPT_SUCCESS) {
            DEBUG(1, ("ldap_set_option failed: %s\n", sss_ldap_err2string(ret)));
            return EIO;
        }
    }

    tls_opt = dp_opt_get_string(basic_opts, SDAP_TLS_CERT);
    if (tls_opt) {
        ret = ldap_set_option(NULL, LDAP_OPT_X_TLS_CERTFILE, tls_opt);
        if (ret != LDAP_OPT_SUCCESS) {
            DEBUG(1, ("ldap_set_option failed: %s\n", sss_ldap_err2string(ret)));
            return EIO;
        }
    }

    tls_opt = dp_opt_get_string(basic_opts, SDAP_TLS_KEY);
    if (tls_opt) {
        ret = ldap_set_option(NULL, LDAP_OPT_X_TLS_KEYFILE, tls_opt);
        if (ret != LDAP_OPT_SUCCESS) {
            DEBUG(1, ("ldap_set_option failed: %s\n", sss_ldap_err2string(ret)));
            return EIO;
        }
    }

    tls_opt = dp_opt_get_string(basic_opts, SDAP_TLS_CIPHER_SUITE);
    if (tls_opt) {
        ret = ldap_set_option(NULL, LDAP_OPT_X_TLS_CIPHER_SUITE, tls_opt);
        if (ret != LDAP_OPT_SUCCESS) {
            DEBUG(1, ("ldap_set_option failed: %s\n", sss_ldap_err2string(ret)));
            return EIO;
        }
    }

    return EOK;
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
        DEBUG(3, ("Missing value.\n"));
    } else if (el->num_values == 1) {
        str = talloc_strndup(mem_ctx, (char *) el->values[0].data,
                             el->values[0].length);
        if (str == NULL) {
            DEBUG(1, ("talloc_strndup failed.\n"));
        }
    } else {
        DEBUG(3, ("More than one value found.\n"));
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
        DEBUG(3, ("No attributes [%s] or [%s] found in rootDSE.\n",
                  SDAP_ROOTDSE_ATTR_NAMING_CONTEXTS,
                  SDAP_ROOTDSE_ATTR_DEFAULT_NAMING_CONTEXT));
    } else {
        if (dnc != NULL) {
            DEBUG(5, ("Using value from [%s] as naming context.\n",
                      SDAP_ROOTDSE_ATTR_DEFAULT_NAMING_CONTEXT));
            naming_context = get_single_value_as_string(mem_ctx, dnc);
        }

        if (naming_context == NULL && nc != NULL) {
            DEBUG(5, ("Using value from [%s] as naming context.\n",
                      SDAP_ROOTDSE_ATTR_NAMING_CONTEXTS));
            naming_context = get_single_value_as_string(mem_ctx, nc);
        }
    }

    return naming_context;
}

static errno_t sdap_set_search_base(struct sdap_options *opts,
                                    enum sdap_basic_opt class,
                                    char *naming_context)
{
    errno_t ret;
    struct sdap_search_base ***bases;

    switch(class) {
    case SDAP_SEARCH_BASE:
        bases = &opts->search_bases;
        break;
    case SDAP_USER_SEARCH_BASE:
        bases = &opts->user_search_bases;
        break;
    case SDAP_GROUP_SEARCH_BASE:
        bases = &opts->group_search_bases;
        break;
    case SDAP_NETGROUP_SEARCH_BASE:
        bases = &opts->netgroup_search_bases;
        break;
    case SDAP_SUDO_SEARCH_BASE:
        bases = &opts->sudo_search_bases;
        break;
    case SDAP_SERVICE_SEARCH_BASE:
        bases = &opts->service_search_bases;
        break;
    case SDAP_AUTOFS_SEARCH_BASE:
        bases = &opts->autofs_search_bases;
        break;
    default:
        return EINVAL;
    }

    DEBUG(SSSDBG_CONF_SETTINGS,
          ("Setting option [%s] to [%s].\n",
            opts->basic[class].opt_name, naming_context));

    ret = dp_opt_set_string(opts->basic, class, naming_context);
    if (ret != EOK) {
        DEBUG(1, ("dp_opt_set_string failed.\n"));
        goto done;
    }

    ret = sdap_parse_search_base(opts, opts->basic, class, bases);
    if (ret != EOK) goto done;

    ret = EOK;
done:
    return ret;
}

errno_t sdap_set_config_options_with_rootdse(struct sysdb_attrs *rootdse,
                                             struct sdap_options *opts)
{
    int ret;
    char *naming_context = NULL;

    if (!opts->search_bases
            ||!opts->user_search_bases
            || !opts->group_search_bases
            || !opts->netgroup_search_bases
            || !opts->sudo_search_bases
            || !opts->autofs_search_bases) {
        naming_context = get_naming_context(opts->basic, rootdse);
        if (naming_context == NULL) {
            DEBUG(1, ("get_naming_context failed.\n"));

            /* This has to be non-fatal, since some servers offer
             * multiple namingContexts entries. We will just
             * add NULL checks for the search bases in the lookups.
             */
            ret = EOK;
            goto done;
        }
    }

    /* Default */
    if (!opts->search_bases) {
        ret = sdap_set_search_base(opts,
                                   SDAP_SEARCH_BASE,
                                   naming_context);
        if (ret != EOK) goto done;
    }

    /* Users */
    if (!opts->user_search_bases) {
        ret = sdap_set_search_base(opts,
                                   SDAP_USER_SEARCH_BASE,
                                   naming_context);
        if (ret != EOK) goto done;
    }

    /* Groups */
    if (!opts->group_search_bases) {
        ret = sdap_set_search_base(opts,
                                   SDAP_GROUP_SEARCH_BASE,
                                   naming_context);
        if (ret != EOK) goto done;
    }

    /* Netgroups */
    if (!opts->netgroup_search_bases) {
        ret = sdap_set_search_base(opts,
                                   SDAP_NETGROUP_SEARCH_BASE,
                                   naming_context);
        if (ret != EOK) goto done;
    }

    /* Sudo */
    if (!opts->sudo_search_bases) {
       ret = sdap_set_search_base(opts,
                                   SDAP_SUDO_SEARCH_BASE,
                                   naming_context);
        if (ret != EOK) goto done;
    }

    /* Services */
    if (!opts->service_search_bases) {
       ret = sdap_set_search_base(opts,
                                  SDAP_SERVICE_SEARCH_BASE,
                                  naming_context);
        if (ret != EOK) goto done;
    }

    /* autofs */
    if (!opts->autofs_search_bases) {
       ret = sdap_set_search_base(opts,
                                  SDAP_AUTOFS_SEARCH_BASE,
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
    char *endptr = NULL;
    int ret;
    int i;

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
                    DEBUG(1, ("%s configured but not found in rootdse!\n",
                              opts->gen_map[SDAP_AT_LAST_USN].opt_name));
                    break;
                case ERANGE:
                    DEBUG(1, ("Multiple values of %s found in rootdse!\n",
                              opts->gen_map[SDAP_AT_LAST_USN].opt_name));
                    break;
                default:
                    DEBUG(1, ("Unkown error (%d) checking rootdse!\n", ret));
                }
            } else {
                if (!entry_usn_name) {
                    DEBUG(1, ("%s found in rootdse but %s is not set!\n",
                              last_usn_name,
                              opts->gen_map[SDAP_AT_ENTRY_USN].opt_name));
                } else {
                    so->supports_usn = true;
                    so->last_usn = strtoul(last_usn_value, &endptr, 10);
                    if (endptr != NULL && (*endptr != '\0' || endptr == last_usn_value)) {
                        DEBUG(3, ("USN is not valid (value: %s)\n", last_usn_value));
                        so->last_usn = 0;
                    } else {
                        DEBUG(9, ("USN value: %s (int: %lu)\n", last_usn_value, so->last_usn));
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
                    so->last_usn = strtoul(last_usn_value, &endptr, 10);
                    if (endptr != NULL && (*endptr != '\0' || endptr == last_usn_value)) {
                        DEBUG(3, ("USN is not valid (value: %s)\n", last_usn_value));
                        so->last_usn = 0;
                    } else {
                        DEBUG(9, ("USN value: %s (int: %lu)\n", last_usn_value, so->last_usn));
                    }
                    last_usn_name = usn_attrs[i].last_name;
                    break;
                }
            }
        }
    }

    if (!last_usn_name) {
        DEBUG(5, ("No known USN scheme is supported by this server!\n"));
        if (!entry_usn_name) {
            DEBUG(5, ("Will use modification timestamp as usn!\n"));
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
     * unnecessarily */
    if (strcmp(id_ctx->srv_opts->server_id, (*srv_opts)->server_id) == 0) {
        talloc_zfree(*srv_opts);
        return;
    }

    talloc_zfree(id_ctx->srv_opts);
    id_ctx->srv_opts = talloc_move(id_ctx, srv_opts);
}


int build_attrs_from_map(TALLOC_CTX *memctx,
                         struct sdap_attr_map *map,
                         size_t size, const char ***_attrs)
{
    const char **attrs;
    int i, j;

    attrs = talloc_array(memctx, const char *, size + 1);
    if (!attrs) return ENOMEM;

    /* first attribute is "objectclass" not the specifc one */
    attrs[0] = talloc_strdup(memctx, "objectClass");
    if (!attrs[0]) return ENOMEM;

    /* add the others */
    for (i = j = 1; i < size; i++) {
        if (map[i].name) {
            attrs[j] = map[i].name;
            j++;
        }
    }
    attrs[j] = NULL;

    *_attrs = attrs;

    return EOK;
}

int sdap_control_create(struct sdap_handle *sh, const char *oid, int iscritical,
                        struct berval *value, int dupval, LDAPControl **ctrlp)
{
    int ret;

    if (sdap_is_control_supported(sh, oid)) {
        ret = sss_ldap_control_create(oid, iscritical, value, dupval, ctrlp);
        if (ret != LDAP_SUCCESS) {
            DEBUG(1, ("sss_ldap_control_create failed [%d][%s].\n",
                      ret, sss_ldap_err2string(ret)));
        }
    } else {
        DEBUG(3, ("Server does not support the requested control [%s].\n", oid));
        ret = LDAP_NOT_SUPPORTED;
    }

    return ret;
}
