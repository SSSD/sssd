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

struct sdap_gen_opts default_basic_opts[] = {
    { "ldapUri", "ldap://localhost", NULL },
    { "defaultBindDn", NULL, NULL },
    { "defaultAuthtokType", NULL, NULL },
    { "defaultAuthtok", NULL, NULL },
    { "network_timeout", "5", NULL },
    { "opt_timeout", "5", NULL },
    { "tls_reqcert", "hard", NULL },
    { "userSearchBase", "dc=example,dc=com", NULL },
    { "userSearchScope", "sub", NULL },
    { "userSearchFilter", NULL, NULL },
    { "groupSearchBase", "dc=example,dc=com", NULL },
    { "groupSearchScope", "sub", NULL },
    { "groupSearchFilter", NULL, NULL },
    { "ldapSchema", "rfc2307", NULL },
    { "offline_timeout", "5", NULL }
};

struct sdap_id_map default_user_map[] = {
    { "userObjectClass", "posixAccount", SYSDB_USER_CLASS, NULL },
    { "userName", "uid", SYSDB_NAME, NULL },
    { "userPwd", "userPassword", SYSDB_PWD, NULL },
    { "userUidNumber", "uidNumber", SYSDB_UIDNUM, NULL },
    { "userGidNumber", "gidNumber", SYSDB_GIDNUM, NULL },
    { "userGecos", "gecos", SYSDB_GECOS, NULL },
    { "userHomeDirectory", "homeDirectory", SYSDB_HOMEDIR, NULL },
    { "userShell", "loginShell", SYSDB_SHELL, NULL },
    { "userUUID", "nsUniqueId", SYSDB_UUID, NULL },
    { "userPrincipal", "krbPrincipalName", SYSDB_UPN, NULL },
    { "userFullname", "cn", SYSDB_FULLNAME, NULL },
    { "userMemberOf", "memberOf", SYSDB_MEMBEROF, NULL }
};

struct sdap_id_map default_group_map[] = {
    { "groupObjectClass", "posixGroup", SYSDB_GROUP_CLASS, NULL },
    { "groupName", "cn", SYSDB_NAME, NULL },
    { "groupPwd", "userPassword", SYSDB_PWD, NULL },
    { "groupGidNumber", "gidNumber", SYSDB_GIDNUM, NULL },
    { "groupMember", "memberuid", SYSDB_LEGACY_MEMBER, NULL },
    { "groupUUID", "nsUniqueId", SYSDB_UUID, NULL }
};

/* =Retrieve-Options====================================================== */

int sdap_get_options(TALLOC_CTX *memctx,
                     struct confdb_ctx *cdb,
                     const char *conf_path,
                     struct sdap_options **_opts)
{
    struct sdap_options *opts;
    int i, ret;

    opts = talloc(memctx, struct sdap_options);
    if (!opts) return ENOMEM;

    opts->basic = talloc_array(opts, struct sdap_gen_opts, SDAP_OPTS_BASIC);
    if (!opts) return ENOMEM;

    opts->user_map = talloc_array(opts, struct sdap_id_map, SDAP_OPTS_USER);
    if (!opts) return ENOMEM;

    opts->group_map = talloc_array(opts, struct sdap_id_map, SDAP_OPTS_GROUP);
    if (!opts) return ENOMEM;

    for (i = 0; i < SDAP_OPTS_BASIC; i++) {

        opts->basic[i].opt_name = default_basic_opts[i].opt_name;
        opts->basic[i].def_value = default_basic_opts[i].def_value;

        ret = confdb_get_string(cdb, opts, conf_path,
                                opts->basic[i].opt_name,
                                opts->basic[i].def_value,
                                &opts->basic[i].value);
        if (ret != EOK ||
            (opts->basic[i].def_value && !opts->basic[i].value)) {
            DEBUG(0, ("Failed to retrieve a value (%s)\n",
                      opts->basic[i].opt_name));
            if (ret != EOK) ret = EINVAL;
            goto done;
        }

        DEBUG(5, ("Option %s has value %s\n",
                  opts->basic[i].opt_name, opts->basic[i].value));
    }

    /* re-read special options that are easier to be consumed after they are
     * transformed */

/* TODO: better to have a blob object than a string here */
    ret = confdb_get_string(cdb, opts, conf_path,
                            "defaultAuthtok", NULL,
                            &opts->default_authtok);
    if (ret != EOK) goto done;
    if (opts->default_authtok) {
        opts->default_authtok_size = strlen(opts->default_authtok);
    }

    ret = confdb_get_int(cdb, opts, conf_path,
                         "network_timeout", 5,
                         &opts->network_timeout);
    if (ret != EOK) goto done;

    ret = confdb_get_int(cdb, opts, conf_path,
                         "opt_timeout", 5,
                         &opts->opt_timeout);
    if (ret != EOK) goto done;

    ret = confdb_get_int(cdb, opts, conf_path,
                         "offline_timeout", 60,
                         &opts->offline_timeout);
    if (ret != EOK) goto done;

    /* schema type */
    if (strcasecmp(opts->basic[SDAP_SCHEMA].value, "rfc2307") == 0) {
        opts->schema_type = SDAP_SCHEMA_RFC2307;
    } else
    if (strcasecmp(opts->basic[SDAP_SCHEMA].value, "rfc2307bis") == 0) {
        opts->schema_type = SDAP_SCHEMA_RFC2307BIS;
    } else {
        DEBUG(0, ("Unrecognized schema type: %s\n",
                  opts->basic[SDAP_SCHEMA].value));
        ret = EINVAL;
        goto done;
    }


/* FIXME: make defaults per schema type memberUid vs member, etc... */
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

