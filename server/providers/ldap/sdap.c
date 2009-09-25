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
#include <ldap.h>
#include "util/util.h"
#include "confdb/confdb.h"
#include "providers/ldap/sdap.h"

#define NULL_STRING { .string = NULL }
#define NULL_BLOB { .blob = { NULL, 0 } }
#define NULL_NUMBER { .number = 0 }
#define BOOL_FALSE { .boolean = false }
#define BOOL_TRUE { .boolean = true }

struct sdap_gen_opts default_basic_opts[] = {
    { "ldap_uri", SDAP_STRING, { "ldap://localhost" }, NULL_STRING },
    { "ldap_default_bind_dn", SDAP_STRING, NULL_STRING, NULL_STRING },
    { "ldap_default_authtok_type", SDAP_STRING, NULL_STRING, NULL_STRING},
    { "ldap_default_authtok", SDAP_BLOB, NULL_BLOB, NULL_BLOB },
    { "ldap_network_timeout", SDAP_NUMBER, { .number = 5 }, NULL_NUMBER },
    { "ldap_opt_timeout", SDAP_NUMBER, { .number = 5 }, NULL_NUMBER },
    { "ldap_tls_reqcert", SDAP_STRING, { "hard" }, NULL_STRING },
    { "ldap_user_search_base", SDAP_STRING, { "ou=People,dc=example,dc=com" }, NULL_STRING },
    { "ldap_user_search_scope", SDAP_STRING, { "sub" }, NULL_STRING },
    { "ldap_user_search_filter", SDAP_STRING, NULL_STRING, NULL_STRING },
    { "ldap_group_search_base", SDAP_STRING, { "ou=Group,dc=example,dc=com" }, NULL_STRING },
    { "ldap_group_search_scope", SDAP_STRING, { "sub" }, NULL_STRING },
    { "ldap_group_search_filter", SDAP_STRING, NULL_STRING, NULL_STRING },
    { "ldap_schema", SDAP_STRING, { "rfc2307" }, NULL_STRING },
    { "ldap_offline_timeout", SDAP_NUMBER, { .number = 60 }, NULL_NUMBER },
    { "ldap_force_upper_case_realm", SDAP_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "ldap_enumeration_refresh_timeout", SDAP_NUMBER, { .number = 300 }, NULL_NUMBER },
    { "ldap_stale_time", SDAP_NUMBER, { .number = 1800 }, NULL_NUMBER },
    { "ldap_tls_cacert", SDAP_STRING, NULL_STRING, NULL_STRING },
    { "ldap_tls_cacertdir", SDAP_STRING, NULL_STRING, NULL_STRING }
};

struct sdap_id_map rfc2307_user_map[] = {
    { "ldap_user_object_class", "posixAccount", SYSDB_USER_CLASS, NULL },
    { "ldap_user_name", "uid", SYSDB_NAME, NULL },
    { "ldap_user_pwd", "userPassword", SYSDB_PWD, NULL },
    { "ldap_user_uid_number", "uidNumber", SYSDB_UIDNUM, NULL },
    { "ldap_user_gid_number", "gidNumber", SYSDB_GIDNUM, NULL },
    { "ldap_user_gecos", "gecos", SYSDB_GECOS, NULL },
    { "ldap_user_home_directory", "homeDirectory", SYSDB_HOMEDIR, NULL },
    { "ldap_user_shell", "loginShell", SYSDB_SHELL, NULL },
    { "ldap_user_principal", "krbPrincipalName", SYSDB_UPN, NULL },
    { "ldap_user_fullname", "cn", SYSDB_FULLNAME, NULL },
    { "ldap_user_member_of", NULL, SYSDB_MEMBEROF, NULL },
    { "ldap_user_uuid", NULL, SYSDB_UUID, NULL },
    { "ldap_user_modify_timestamp", "modifyTimestamp", SYSDB_ORIG_MODSTAMP, NULL }
};

struct sdap_id_map rfc2307_group_map[] = {
    { "ldap_group_object_class", "posixGroup", SYSDB_GROUP_CLASS, NULL },
    { "ldap_group_name", "cn", SYSDB_NAME, NULL },
    { "ldap_group_pwd", "userPassword", SYSDB_PWD, NULL },
    { "ldap_group_gid_number", "gidNumber", SYSDB_GIDNUM, NULL },
    { "ldap_group_member", "memberuid", SYSDB_MEMBER, NULL },
    { "ldap_group_uuid", NULL, SYSDB_UUID, NULL },
    { "ldap_group_modify_timestamp", "modifyTimestamp", SYSDB_ORIG_MODSTAMP, NULL }
};

struct sdap_id_map rfc2307bis_user_map[] = {
    { "ldap_user_object_class", "posixAccount", SYSDB_USER_CLASS, NULL },
    { "ldap_user_name", "uid", SYSDB_NAME, NULL },
    { "ldap_user_pwd", "userPassword", SYSDB_PWD, NULL },
    { "ldap_user_uid_number", "uidNumber", SYSDB_UIDNUM, NULL },
    { "ldap_user_gid_number", "gidNumber", SYSDB_GIDNUM, NULL },
    { "ldap_user_gecos", "gecos", SYSDB_GECOS, NULL },
    { "ldap_user_home_directory", "homeDirectory", SYSDB_HOMEDIR, NULL },
    { "ldap_user_shell", "loginShell", SYSDB_SHELL, NULL },
    { "ldap_user_principal", "krbPrincipalName", SYSDB_UPN, NULL },
    { "ldap_user_fullname", "cn", SYSDB_FULLNAME, NULL },
    { "ldap_user_member_of", "memberOf", SYSDB_MEMBEROF, NULL },
    /* FIXME: this is 389ds specific */
    { "ldap_user_uuid", "nsUniqueId", SYSDB_UUID, NULL },
    { "ldap_user_modify_timestamp", "modifyTimestamp", SYSDB_ORIG_MODSTAMP, NULL }
};

struct sdap_id_map rfc2307bis_group_map[] = {
    { "ldap_group_object_class", "posixGroup", SYSDB_GROUP_CLASS, NULL },
    { "ldap_group_name", "cn", SYSDB_NAME, NULL },
    { "ldap_group_pwd", "userPassword", SYSDB_PWD, NULL },
    { "ldap_group_gid_number", "gidNumber", SYSDB_GIDNUM, NULL },
    { "ldap_group_member", "member", SYSDB_MEMBER, NULL },
    /* FIXME: this is 389ds specific */
    { "ldap_group_uuid", "nsUniqueId", SYSDB_UUID, NULL },
    { "ldap_group_modify_timestamp", "modifyTimestamp", SYSDB_ORIG_MODSTAMP, NULL }
};

/* =Retrieve-Options====================================================== */

int sdap_get_options(TALLOC_CTX *memctx,
                     struct confdb_ctx *cdb,
                     const char *conf_path,
                     struct sdap_options **_opts)
{
    struct sdap_id_map *default_user_map;
    struct sdap_id_map *default_group_map;
    struct sdap_options *opts;
    char *schema;
    int i, ret;

    opts = talloc_zero(memctx, struct sdap_options);
    if (!opts) return ENOMEM;

    opts->basic = talloc_array(opts, struct sdap_gen_opts, SDAP_OPTS_BASIC);
    if (!opts) return ENOMEM;

    opts->user_map = talloc_array(opts, struct sdap_id_map, SDAP_OPTS_USER);
    if (!opts) return ENOMEM;

    opts->group_map = talloc_array(opts, struct sdap_id_map, SDAP_OPTS_GROUP);
    if (!opts) return ENOMEM;

    for (i = 0; i < SDAP_OPTS_BASIC; i++) {
        char *tmp;

        opts->basic[i].opt_name = default_basic_opts[i].opt_name;
        opts->basic[i].type = default_basic_opts[i].type;
        opts->basic[i].def_val = default_basic_opts[i].def_val;
        ret = EOK;

        switch (default_basic_opts[i].type) {
        case SDAP_STRING:
            ret = confdb_get_string(cdb, opts, conf_path,
                                    opts->basic[i].opt_name,
                                    opts->basic[i].def_val.cstring,
                                    &opts->basic[i].val.string);
            if (ret != EOK ||
                ((opts->basic[i].def_val.string != NULL) &&
                 (opts->basic[i].val.string == NULL))) {
                DEBUG(0, ("Failed to retrieve value for option (%s)\n",
                          opts->basic[i].opt_name));
                if (ret == EOK) ret = EINVAL;
                goto done;
            }
            DEBUG(6, ("Option %s has value %s\n",
                  opts->basic[i].opt_name, opts->basic[i].val.cstring));
            break;

        case SDAP_BLOB:
            ret = confdb_get_string(cdb, opts, conf_path,
                                    opts->basic[i].opt_name,
                                    NULL, &tmp);
            if (ret != EOK) {
                DEBUG(0, ("Failed to retrieve value for option (%s)\n",
                          opts->basic[i].opt_name));
                goto done;
            }

            if (tmp) {
                opts->basic[i].val.blob.data = (uint8_t *)tmp;
                opts->basic[i].val.blob.length = strlen(tmp);
            } else {
                opts->basic[i].val.blob.data = NULL;
                opts->basic[i].val.blob.length = 0;
            }

            DEBUG(6, ("Option %s has %s value\n",
                      opts->basic[i].opt_name,
                      opts->basic[i].val.blob.length?"a":"no"));
            break;

        case SDAP_NUMBER:
            ret = confdb_get_int(cdb, opts, conf_path,
                                 opts->basic[i].opt_name,
                                 opts->basic[i].def_val.number,
                                 &opts->basic[i].val.number);
            if (ret != EOK) {
                DEBUG(0, ("Failed to retrieve value for option (%s)\n",
                          opts->basic[i].opt_name));
                goto done;
            }
            DEBUG(6, ("Option %s has value %d\n",
                  opts->basic[i].opt_name, opts->basic[i].val.number));
            break;

        case SDAP_BOOL:
            ret = confdb_get_bool(cdb, opts, conf_path,
                                  opts->basic[i].opt_name,
                                  opts->basic[i].def_val.boolean,
                                  &opts->basic[i].val.boolean);
            if (ret != EOK) {
                DEBUG(0, ("Failed to retrieve value for option (%s)\n",
                          opts->basic[i].opt_name));
                goto done;
            }
            DEBUG(6, ("Option %s is %s\n",
                      opts->basic[i].opt_name,
                      opts->basic[i].val.boolean?"TRUE":"FALSE"));
            break;
        }
    }

    /* schema type */
    schema = sdap_go_get_string(opts->basic, SDAP_SCHEMA);
    if (strcasecmp(schema, "rfc2307") == 0) {
        opts->schema_type = SDAP_SCHEMA_RFC2307;
        default_user_map = rfc2307_user_map;
        default_group_map = rfc2307_group_map;
    } else
    if (strcasecmp(schema, "rfc2307bis") == 0) {
        opts->schema_type = SDAP_SCHEMA_RFC2307BIS;
        default_user_map = rfc2307bis_user_map;
        default_group_map = rfc2307bis_group_map;
    } else {
        DEBUG(0, ("Unrecognized schema type: %s\n", schema));
        ret = EINVAL;
        goto done;
    }

    for (i = 0; i < SDAP_OPTS_USER; i++) {

        opts->user_map[i].opt_name = default_user_map[i].opt_name;
        opts->user_map[i].def_name = default_user_map[i].def_name;
        opts->user_map[i].sys_name = default_user_map[i].sys_name;

        ret = confdb_get_string(cdb, opts, conf_path,
                                opts->user_map[i].opt_name,
                                opts->user_map[i].def_name,
                                &opts->user_map[i].name);
        if (ret != EOK ||
            (opts->user_map[i].def_name && !opts->user_map[i].name)) {
            DEBUG(0, ("Failed to retrieve a value (%s)\n",
                      opts->user_map[i].opt_name));
            if (ret != EOK) ret = EINVAL;
            goto done;
        }

        DEBUG(5, ("Option %s has value %s\n",
                  opts->user_map[i].opt_name, opts->user_map[i].name));
    }

    for (i = 0; i < SDAP_OPTS_GROUP; i++) {

        opts->group_map[i].opt_name = default_group_map[i].opt_name;
        opts->group_map[i].def_name = default_group_map[i].def_name;
        opts->group_map[i].sys_name = default_group_map[i].sys_name;

        ret = confdb_get_string(cdb, opts, conf_path,
                                opts->group_map[i].opt_name,
                                opts->group_map[i].def_name,
                                &opts->group_map[i].name);
        if (ret != EOK ||
            (opts->group_map[i].def_name && !opts->group_map[i].name)) {
            DEBUG(0, ("Failed to retrieve a value (%s)\n",
                      opts->group_map[i].opt_name));
            if (ret != EOK) ret = EINVAL;
            goto done;
        }

        DEBUG(5, ("Option %s has value %s\n",
                  opts->group_map[i].opt_name, opts->group_map[i].name));
    }

    ret = EOK;
    *_opts = opts;

done:
    if (ret != EOK) talloc_zfree(opts);
    return ret;
}

/* =Basic-Option-Helpers================================================== */

static const char *sdap_type_to_string(enum sdap_type type)
{
    switch (type) {
    case SDAP_STRING:
        return "String";
    case SDAP_BLOB:
        return "Blob";
    case SDAP_NUMBER:
        return "Number";
    case SDAP_BOOL:
        return "Boolean";
    }
    return NULL;
}

const char *_sdap_go_get_cstring(struct sdap_gen_opts *opts,
                                 int id, const char *location)
{
    if (opts[id].type != SDAP_STRING) {
        DEBUG(0, ("[%s] Requested type 'String' for option '%s'"
                  " but value is of type '%s'!\n",
                  location, opts[id].opt_name,
                  sdap_type_to_string(opts[id].type)));
        return NULL;
    }
    return opts[id].val.cstring;
}

char *_sdap_go_get_string(struct sdap_gen_opts *opts,
                          int id, const char *location)
{
    if (opts[id].type != SDAP_STRING) {
        DEBUG(0, ("[%s] Requested type 'String' for option '%s'"
                  " but value is of type '%s'!\n",
                  location, opts[id].opt_name,
                  sdap_type_to_string(opts[id].type)));
        return NULL;
    }
    return opts[id].val.string;
}

struct sdap_blob _sdap_go_get_blob(struct sdap_gen_opts *opts,
                                   int id, const char *location)
{
    struct sdap_blob null_blob = { NULL, 0 };
    if (opts[id].type != SDAP_BLOB) {
        DEBUG(0, ("[%s] Requested type 'Blob' for option '%s'"
                  " but value is of type '%s'!\n",
                  location, opts[id].opt_name,
                  sdap_type_to_string(opts[id].type)));
        return null_blob;
    }
    return opts[id].val.blob;
}

int _sdap_go_get_int(struct sdap_gen_opts *opts,
                     int id, const char *location)
{
    if (opts[id].type != SDAP_NUMBER) {
        DEBUG(0, ("[%s] Requested type 'Number' for option '%s'"
                  " but value is of type '%s'!\n",
                  location, opts[id].opt_name,
                  sdap_type_to_string(opts[id].type)));
        return 0;
    }
    return opts[id].val.number;
}

bool _sdap_go_get_bool(struct sdap_gen_opts *opts,
                       int id, const char *location)
{
    if (opts[id].type != SDAP_BOOL) {
        DEBUG(0, ("[%s] Requested type 'Boolean' for option '%s'"
                  " but value is of type '%s'!\n",
                  location, opts[id].opt_name,
                  sdap_type_to_string(opts[id].type)));
        return false;
    }
    return opts[id].val.boolean;
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

errno_t setup_tls_config(struct sdap_gen_opts *basic_opts)
{
    int ret;
    int ldap_opt_x_tls_require_cert;
    const char *tls_opt;
    tls_opt = sdap_go_get_string(basic_opts, SDAP_TLS_REQCERT);
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

    tls_opt = sdap_go_get_string(basic_opts, SDAP_TLS_CACERT);
    if (tls_opt) {
        ret = ldap_set_option(NULL, LDAP_OPT_X_TLS_CACERTFILE, tls_opt);
        if (ret != LDAP_OPT_SUCCESS) {
            DEBUG(1, ("ldap_set_option failed: %s\n", ldap_err2string(ret)));
            return EIO;
        }
    }

    tls_opt = sdap_go_get_string(basic_opts, SDAP_TLS_CACERTDIR);
    if (tls_opt) {
        ret = ldap_set_option(NULL, LDAP_OPT_X_TLS_CACERTDIR, tls_opt);
        if (ret != LDAP_OPT_SUCCESS) {
            DEBUG(1, ("ldap_set_option failed: %s\n", ldap_err2string(ret)));
            return EIO;
        }
    }

    return EOK;
}
