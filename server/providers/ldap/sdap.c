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

#define LDAP_DEPRECATED 1
#include "util/util.h"
#include "confdb/confdb.h"
#include "providers/ldap/sdap.h"

/* =Retrieve-Options====================================================== */

int sdap_get_map(TALLOC_CTX *memctx,
                 struct confdb_ctx *cdb,
                 const char *conf_path,
                 struct sdap_id_map *def_map,
                 int num_entries,
                 struct sdap_id_map **_map)
{
    struct sdap_id_map *map;
    int i, ret;

    map = talloc_array(memctx, struct sdap_id_map, num_entries);
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
                                &map[i].name);
        if ((ret != EOK) || (map[i].def_name && !map[i].name)) {
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

static int sdap_parse_entry(TALLOC_CTX *memctx,
                            struct sdap_handle *sh, struct sdap_msg *sm,
                            struct sdap_id_map *map, int attrs_num,
                            struct sysdb_attrs **_attrs, char **_dn)
{
    struct sysdb_attrs *attrs;
    BerElement *ber = NULL;
    char **vals;
    char *str;
    int lerrno;
    int a, i, ret;

    lerrno = 0;
    ldap_set_option(sh->ldap, LDAP_OPT_RESULT_CODE, &lerrno);

    attrs = sysdb_new_attrs(memctx);
    if (!attrs) return ENOMEM;

    str = ldap_get_dn(sh->ldap, sm->msg);
    if (!str) {
        ldap_get_option(sh->ldap, LDAP_OPT_RESULT_CODE, &lerrno);
        DEBUG(1, ("ldap_get_dn failed: %d(%s)\n",
                  lerrno, ldap_err2string(lerrno)));
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

    vals = ldap_get_values(sh->ldap, sm->msg, "objectClass");
    if (!vals) {
        DEBUG(1, ("Unknown entry type, no objectClasses found!\n"));
        ret = EINVAL;
        goto fail;
    }

    for (i = 0; vals[i]; i++) {
        /* the objectclass is always the first name in the map */
        if (strcasecmp(vals[i], map[0].name) == 0) {
            /* ok it's a user */
            break;
        }
    }
    if (!vals[i]) {
        DEBUG(1, ("Not a user entry, objectClass not matching: %s\n",
                  map[0].name));
        ldap_value_free(vals);
        ret = EINVAL;
        goto fail;
    }
    ldap_value_free(vals);

    str = ldap_first_attribute(sh->ldap, sm->msg, &ber);
    if (!str) {
        ldap_get_option(sh->ldap, LDAP_OPT_RESULT_CODE, &lerrno);
        DEBUG(1, ("Entry has no attributes [%d(%s)]!?\n",
                  lerrno, ldap_err2string(lerrno)));
        ret = EINVAL;
        goto fail;
    }
    while (str) {
        for (a = 1; a < attrs_num; a++) {
            /* check if this attr is valid with the chosen schema */
            if (!map[a].name) continue;
            /* check if it is an attr we are interested in */
            if (strcasecmp(str, map[a].name) == 0) break;
        }
        if (a < attrs_num) {
            /* interesting attr */

            vals = ldap_get_values(sh->ldap, sm->msg, str);
            if (!vals) {
                ldap_get_option(sh->ldap, LDAP_OPT_RESULT_CODE, &lerrno);
                DEBUG(1, ("LDAP Library error: %d(%s)",
                          lerrno, ldap_err2string(lerrno)));
                ret = EIO;
                goto fail;
            }
            if (!vals[0]) {
                DEBUG(1, ("Missing value after ldap_get_values() ??\n"));
                ret = EINVAL;
                goto fail;
            }
            for (i = 0; vals[i]; i++) {
                ret = sysdb_attrs_add_string(attrs, map[a].sys_name, vals[i]);
                if (ret) goto fail;
            }
            ldap_value_free(vals);
        }

        ldap_memfree(str);
        str = ldap_next_attribute(sh->ldap, sm->msg, ber);
    }
    ber_free(ber, 0);

    ldap_get_option(sh->ldap, LDAP_OPT_RESULT_CODE, &lerrno);
    if (lerrno) {
        DEBUG(1, ("LDAP Library error: %d(%s)",
                  lerrno, ldap_err2string(lerrno)));
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

int sdap_parse_generic_entry(TALLOC_CTX *memctx,
                                    struct sdap_handle *sh,
                                    struct sdap_msg *sm,
                                    struct sysdb_attrs **_attrs)
{
    struct sysdb_attrs *attrs;
    BerElement *ber = NULL;
    struct berval **vals;
    struct ldb_val v;
    char *str;
    int lerrno;
    int i;
    int ret;

    lerrno = 0;
    ldap_set_option(sh->ldap, LDAP_OPT_RESULT_CODE, &lerrno);

    attrs = sysdb_new_attrs(memctx);
    if (!attrs) return ENOMEM;

    str = ldap_get_dn(sh->ldap, sm->msg);
    if (!str) {
        ldap_get_option(sh->ldap, LDAP_OPT_RESULT_CODE, &lerrno);
        DEBUG(1, ("ldap_get_dn failed: %d(%s)\n",
                  lerrno, ldap_err2string(lerrno)));
        ret = EIO;
        goto fail;
    }

    DEBUG(9, ("OriginalDN: [%s].\n", str));
    ret = sysdb_attrs_add_string(attrs, SYSDB_ORIG_DN, str);
    if (ret) goto fail;
    ldap_memfree(str);

    str = ldap_first_attribute(sh->ldap, sm->msg, &ber);
    if (!str) {
        ldap_get_option(sh->ldap, LDAP_OPT_RESULT_CODE, &lerrno);
        DEBUG(9, ("Entry has no attributes [%d(%s)]!?\n",
                  lerrno, ldap_err2string(lerrno)));
    }
    while (str) {
        vals = ldap_get_values_len(sh->ldap, sm->msg, str);
        if (!vals) {
            ldap_get_option(sh->ldap, LDAP_OPT_RESULT_CODE, &lerrno);
            DEBUG(1, ("LDAP Library error: %d(%s)",
                      lerrno, ldap_err2string(lerrno)));
            ret = EIO;
            goto fail;
        }
        if (!vals[0]) {
            DEBUG(1, ("Missing value after ldap_get_values() ??\n"));
            ret = EINVAL;
            goto fail;
        }
        for (i = 0; vals[i]; i++) {
            v.data = (uint8_t *) vals[i]->bv_val;
            v.length = vals[i]->bv_len;

            ret = sysdb_attrs_add_val(attrs, str, &v);
            if (ret) goto fail;
        }
        ldap_value_free_len(vals);

        ldap_memfree(str);
        str = ldap_next_attribute(sh->ldap, sm->msg, ber);
    }
    ber_free(ber, 0);

    ldap_get_option(sh->ldap, LDAP_OPT_RESULT_CODE, &lerrno);
    if (lerrno) {
        DEBUG(1, ("LDAP Library error: %d(%s)",
                  lerrno, ldap_err2string(lerrno)));
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

/* =Get-DN-from-message=================================================== */

int sdap_get_msg_dn(TALLOC_CTX *memctx, struct sdap_handle *sh,
                    struct sdap_msg *sm, char **_dn)
{
    char *str;
    int lerrno;

    lerrno = 0;
    ldap_set_option(sh->ldap, LDAP_OPT_RESULT_CODE, &lerrno);

    str = ldap_get_dn(sh->ldap, sm->msg);
    if (!str) {
        ldap_get_option(sh->ldap, LDAP_OPT_RESULT_CODE, &lerrno);
        DEBUG(1, ("ldap_get_dn failed: %d(%s)\n",
                  lerrno, ldap_err2string(lerrno)));
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
            DEBUG(1, ("ldap_set_option failed: %s\n", ldap_err2string(ret)));
            return EIO;
        }
    }

    tls_opt = dp_opt_get_string(basic_opts, SDAP_TLS_CACERT);
    if (tls_opt) {
        ret = ldap_set_option(NULL, LDAP_OPT_X_TLS_CACERTFILE, tls_opt);
        if (ret != LDAP_OPT_SUCCESS) {
            DEBUG(1, ("ldap_set_option failed: %s\n", ldap_err2string(ret)));
            return EIO;
        }
    }

    tls_opt = dp_opt_get_string(basic_opts, SDAP_TLS_CACERTDIR);
    if (tls_opt) {
        ret = ldap_set_option(NULL, LDAP_OPT_X_TLS_CACERTDIR, tls_opt);
        if (ret != LDAP_OPT_SUCCESS) {
            DEBUG(1, ("ldap_set_option failed: %s\n", ldap_err2string(ret)));
            return EIO;
        }
    }

    return EOK;
}
