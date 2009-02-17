/*
   SSSD

   NSS Configuratoin DB

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2008

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

#define _GNU_SOURCE
#include "config.h"
#include <string.h>
#include <errno.h>
#include "ldb.h"
#include "ldb_errors.h"
#include "util/util.h"
#include "confdb/confdb.h"
#define CONFDB_VERSION "0.1"
#define CONFDB_DOMAIN_BASEDN "cn=domains,cn=config"
#define CONFDB_DOMAIN_ATTR "cn"

#define CONFDB_ZERO_CHECK_OR_JUMP(var, ret, err, label) do { \
    if (!var) { \
        ret = err; \
        goto label; \
    } \
} while(0)

struct confdb_ctx {
    struct ldb_context *ldb;
};

static char *prepend_cn(char *str, int *slen, const char *comp, int clen)
{
    char *ret;

    ret = talloc_realloc(NULL, str, char, *slen + 4 + clen + 1);
    if (!ret)
        return NULL;

    /* move current string to the end */
    memmove(&ret[clen +4], ret, *slen+1); /* includes termination */
    memcpy(ret, "cn=", 3);
    memcpy(&ret[3], comp, clen);
    ret[clen+3] = ',';

    *slen = *slen + 4 + clen;

    return ret;
}

static int parse_section(TALLOC_CTX *mem_ctx, const char *section,
                         char **sec_dn, const char **rdn_name)
{
    TALLOC_CTX *tmp_ctx;
    char *dn;
    char *p;
    const char *s;
    int l, ret;

    /* section must be a non null string and must not start with '/' */
    if (!section || !*section || *section == '/') return EINVAL;

    tmp_ctx = talloc_new(mem_ctx);
    if (!tmp_ctx) return ENOMEM;

    s = section;
    l = 0;
    while ((p = strchrnul(s, '/'))) {
        if (l == 0) {
            dn = talloc_asprintf(tmp_ctx, "cn=%s", s);
            l = 3 + (p-s);
            dn[l] = '\0';
        } else {
            dn = prepend_cn(dn, &l, s, p-s);
        }
        if (!dn) {
            ret = ENOMEM;
            goto done;
        }
        if (*p == '\0') {
            if (rdn_name) *rdn_name = s;
            break; /* reached end */
        }
        s = p+1;
        if (*s == '\0') { /* a section cannot end in '.' */
            ret = EINVAL;
            goto done;
        }
    }

    *sec_dn = talloc_steal(mem_ctx, dn);
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

int confdb_add_param(struct confdb_ctx *cdb,
                     bool replace,
                     const char *section,
                     const char *attribute,
                     const char **values)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_message *msg;
    struct ldb_result *res;
    struct ldb_dn *dn;
    char *secdn;
    const char *rdn_name;
    int ret, i;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx)
        return ENOMEM;

    ret = parse_section(tmp_ctx, section, &secdn, &rdn_name);
    if (ret != EOK) {
        goto done;
    }

    dn = ldb_dn_new(tmp_ctx, cdb->ldb, secdn);
    CONFDB_ZERO_CHECK_OR_JUMP(dn, ret, EIO, done);

    ret = ldb_search(cdb->ldb, tmp_ctx, &res,
                     dn, LDB_SCOPE_BASE, NULL, NULL);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    msg = ldb_msg_new(tmp_ctx);
    CONFDB_ZERO_CHECK_OR_JUMP(msg, ret, ENOMEM, done);

    msg->dn = talloc_steal(msg, dn);
    CONFDB_ZERO_CHECK_OR_JUMP(msg->dn, ret, ENOMEM, done);

    if (res->count == 0) { /* add a new message */
        errno = 0;

        /* cn first */
        ret = ldb_msg_add_string(msg, "cn", rdn_name);
        if (ret != LDB_SUCCESS) {
            if (errno) ret = errno;
            else ret = EIO;
            goto done;
        }

        /* now the requested attribute */
        for (i = 0; values[i]; i++) {
            ret = ldb_msg_add_string(msg, attribute, values[i]);
            if (ret != LDB_SUCCESS) {
                if (errno) ret = errno;
                else ret = EIO;
                goto done;
            }
        }

        ret = ldb_add(cdb->ldb, msg);
        if (ret != LDB_SUCCESS) {
            ret = EIO;
            goto done;
        }

    } else {
        int optype;
        errno = 0;

        /* mark this as a replacement */
        if (replace) optype = LDB_FLAG_MOD_REPLACE;
        else optype = LDB_FLAG_MOD_ADD;
        ret = ldb_msg_add_empty(msg, attribute, optype, NULL);
        if (ret != LDB_SUCCESS) {
            if (errno) ret = errno;
            else ret = EIO;
            goto done;
        }

        /* now the requested attribute */
        for (i = 0; values[i]; i++) {
            ret = ldb_msg_add_string(msg, attribute, values[i]);
            if (ret != LDB_SUCCESS) {
                if (errno) ret = errno;
                else ret = EIO;
                goto done;
            }
        }

        ret = ldb_modify(cdb->ldb, msg);
        if (ret != LDB_SUCCESS) {
            ret = EIO;
            goto done;
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

int confdb_get_param(struct confdb_ctx *cdb,
                     TALLOC_CTX *mem_ctx,
                     const char *section,
                     const char *attribute,
                     char ***values)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;
    struct ldb_dn *dn;
    char *secdn;
    const char *attrs[] = { attribute, NULL };
    char **vals;
    struct ldb_message_element *el;
    int ret, i;

    tmp_ctx = talloc_new(mem_ctx);
    if (!tmp_ctx)
        return ENOMEM;

    ret = parse_section(tmp_ctx, section, &secdn, NULL);
    if (ret != EOK) {
        goto done;
    }

    dn = ldb_dn_new(tmp_ctx, cdb->ldb, secdn);
    if (!dn) {
        ret = EIO;
        goto done;
    }

    ret = ldb_search(cdb->ldb, tmp_ctx, &res,
                     dn, LDB_SCOPE_BASE, attrs, NULL);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }
    if (res->count > 1) {
        ret = EIO;
        goto done;
    }

    vals = talloc_zero(mem_ctx, char *);
    ret = EOK;

    if (res->count > 0) {
        el = ldb_msg_find_element(res->msgs[0], attribute);
        if (el && el->num_values > 0) {
            vals = talloc_realloc(mem_ctx, vals, char *, el->num_values +1);
            if (!vals) {
                ret = ENOMEM;
                goto done;
            }
            /* should always be strings so this should be safe */
            for (i = 0; i < el->num_values; i++) {
                struct ldb_val v = el->values[i];
                vals[i] = talloc_strndup(vals, (char *)v.data, v.length);
                if (!vals[i]) {
                    ret = ENOMEM;
                    goto done;
                }
            }
            vals[i] = NULL;
        }
    }

    *values = vals;

done:
    talloc_free(tmp_ctx);
    return ret;
}

int confdb_get_string(struct confdb_ctx *cdb, TALLOC_CTX *ctx,
                      const char *section, const char *attribute,
                      const char *defstr, char **result)
{
    char **values;
    char *restr;
    int ret;

    ret = confdb_get_param(cdb, ctx, section, attribute, &values);
    if (ret != EOK) {
        return ret;
    }

    if (values[0]) {
        if (values[1] != NULL) {
            /* too many values */
            talloc_free(values);
            return EINVAL;
        }
        restr = talloc_steal(ctx, values[0]);
    } else {
        /* Did not return a value, so use the default */

        if (defstr == NULL) { /* No default given */
            *result = NULL;
            talloc_free(values);
            return EOK;
        }

        /* Copy the default string */
        restr = talloc_strdup(ctx, defstr);
    }
    if (!restr) {
        talloc_free(values);
        DEBUG(0, ("Out of memory\n"));
        return ENOMEM;
    }

    talloc_free(values);

    *result = restr;
    return EOK;
}

int confdb_get_int(struct confdb_ctx *cdb, TALLOC_CTX *ctx,
                   const char *section, const char *attribute,
                   int defval, int *result)
{
    char **values;
    long int val;
    int ret;

    ret = confdb_get_param(cdb, ctx, section, attribute, &values);
    if (ret != EOK) {
        return ret;
    }

    if (values[0]) {
        if (values[1] != NULL) {
            /* too many values */
            talloc_free(values);
            return EINVAL;
        }

        errno = 0;
        val = strtol(values[0], NULL, 0);
        if (errno) {
            talloc_free(values);
            return errno;
        }

        if (val < INT_MIN || val > INT_MAX) {
            talloc_free(values);
            return ERANGE;
        }

    } else {
        val = defval;
    }

    talloc_free(values);

    *result = (int)val;
    return EOK;
}

static int confdb_test(struct confdb_ctx *cdb)
{
    char **values;
    int ret;

    ret = confdb_get_param(cdb, cdb,
                           "config",
                           "version",
                           &values);
    if (ret != EOK) {
        return ret;
    }

    if (values[0] == NULL) {
        /* empty database, will need to init */
        talloc_free(values);
        return ENOENT;
    }

    if (values[1] != NULL) {
        /* more than 1 value ?? */
        talloc_free(values);
        return EIO;
    }

    if (strcmp(values[0], CONFDB_VERSION) != 0) {
        /* bad version get out */
        talloc_free(values);
        return EIO;
    }

    talloc_free(values);
    return EOK;
}

static int confdb_init_db(struct confdb_ctx *cdb)
{
    const char *val[2];
    int ret;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(cdb);
    if(tmp_ctx == NULL) return ENOMEM;

    val[0] = CONFDB_VERSION;
    val[1] = NULL;

    /* Add the confdb version */
    ret = confdb_add_param(cdb,
                           false,
                           "config",
                           "version",
                            val);
    if (ret != EOK) goto done;

    /* Set up default monitored services */
    val[0] = "Local service configuration";
    ret = confdb_add_param(cdb, false, "config/services", "description", val);
    if (ret != EOK) goto done;

#if 0 /* Not yet implemented */
/* PAM */
#endif /* PAM */

/* NSS */
    /* set the sssd_nss description */
    val[0] = "NSS Responder Configuration";
    ret = confdb_add_param(cdb, false, "config/services/nss", "description", val);
    if (ret != EOK) goto done;

    /* Set the sssd_nss command path */
    val[0] = talloc_asprintf(tmp_ctx, "%s/sssd_nss", SSSD_LIBEXEC_PATH);
    ret = confdb_add_param(cdb, false, "config/services/nss", "command", val);
    if (ret != EOK) goto done;

    /* Set the sssd_nss socket path */
    val[0] = talloc_asprintf(tmp_ctx, "%s/sssd_nss", PIPE_PATH);
    ret = confdb_add_param(cdb, false, "config/services/nss", "unixSocket", val);
    if (ret != EOK) goto done;

    /* Add NSS to the list of active services */
    val[0] = "nss";
    ret = confdb_add_param(cdb, false, "config/services", "activeServices", val);
    if (ret != EOK) goto done;

/* Data Provider */
    /* Set the sssd_dp description */
    val[0] = "Data Provider Configuration";
    ret = confdb_add_param(cdb, false, "config/services/dp", "description", val);
    if (ret != EOK) goto done;

    /* Set the sssd_dp command path */
    val[0] = talloc_asprintf(tmp_ctx, "%s/sssd_dp", SSSD_LIBEXEC_PATH);
    ret = confdb_add_param(cdb, false, "config/services/dp", "command", val);
    if (ret != EOK) goto done;

    /* Add the Data Provider to the list of active services */
    val[0] = "dp";
    ret = confdb_add_param(cdb, false, "config/services", "activeServices", val);
    if (ret != EOK) goto done;

/* InfoPipe */
    /* Set the sssd_info description */
    val[0] = "InfoPipe Configuration";
    ret = confdb_add_param(cdb, false, "config/services/infp", "description", val);
    if (ret != EOK) goto done;

    /* Set the sssd_info command path */
    val[0] = talloc_asprintf(tmp_ctx, "%s/sssd_info", SSSD_LIBEXEC_PATH);
    ret = confdb_add_param(cdb, false, "config/services/infp", "command", val);
    if (ret != EOK) goto done;

    /* Add the InfoPipe to the list of active services */
    val[0] = "infp";
    ret = confdb_add_param(cdb, false, "config/services", "activeServices", val);
    if (ret != EOK) goto done;

/* PolicyKit */
    /* Set the sssd_pk description */
    val[0] = "PolicyKit Backend Configuration";
    ret = confdb_add_param(cdb, false, "config/services/spk", "description", val);
    if (ret != EOK) goto done;

    /* Set the sssd_info command path */
    val[0] = talloc_asprintf(tmp_ctx, "%s/sssd_pk", SSSD_LIBEXEC_PATH);
    ret = confdb_add_param(cdb, false, "config/services/spk", "command", val);
    if (ret != EOK) goto done;

    /* Add the InfoPipe to the list of active services */
    val[0] = "spk";
    ret = confdb_add_param(cdb, false, "config/services", "activeServices", val);
    if (ret != EOK) goto done;

/* Domains */
    val[0] = "Domains served by SSSD";
    ret = confdb_add_param(cdb, false, "config/domains", "description", val);
    if (ret != EOK) goto done;

    /* Default LOCAL domain */
    val[0] = "Reserved domain for local configurations";
    ret = confdb_add_param(cdb, false, "config/domains/LOCAL", "description", val);
    if (ret != EOK) goto done;

    val[0] = "local";
    ret = confdb_add_param(cdb, false, "config/domains/LOCAL", "provider", val);
    if (ret != EOK) goto done;

    val[0] = "cn=local,dc=sysdb";
    ret = confdb_add_param(cdb, false, "config/domains/LOCAL", "basedn", val);
    if (ret != EOK) goto done;


done:
    talloc_free(tmp_ctx);
    return ret;
}

int confdb_init(TALLOC_CTX *mem_ctx,
                struct event_context *ev,
                struct confdb_ctx **cdb_ctx,
                char *confdb_location)
{
    struct confdb_ctx *cdb;
    int ret;

    cdb = talloc_zero(mem_ctx, struct confdb_ctx);
    if (!cdb)
        return ENOMEM;

    cdb->ldb = ldb_init(cdb, ev);
    if (!cdb->ldb) {
        talloc_free(cdb);
        return EIO;
    }

    ret = ldb_connect(cdb->ldb, confdb_location, 0, NULL);
    if (ret != LDB_SUCCESS) {
        talloc_free(cdb);
        return EIO;
    }

    ret = confdb_test(cdb);
    if (ret == ENOENT) {
        ret = confdb_init_db(cdb);
    }
    if (ret != EOK) {
        talloc_free(cdb);
        return ret;
    }

    *cdb_ctx = cdb;

    return EOK;
}

int confdb_get_domains(struct confdb_ctx *cdb,
                       TALLOC_CTX *mem_ctx,
                       char ***values)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *dn;
    struct ldb_result *res;
    struct ldb_message_element *el;
    int ret, i;
    const char *attrs[] = {CONFDB_DOMAIN_ATTR, NULL};
    char **vals;
    int val_count;

    tmp_ctx = talloc_new(mem_ctx);

    dn = ldb_dn_new(tmp_ctx,cdb->ldb, CONFDB_DOMAIN_BASEDN);
    if (!dn) {
        ret = EIO;
        goto done;
    }

    ret = ldb_search(cdb->ldb, tmp_ctx, &res, dn,
                     LDB_SCOPE_ONELEVEL, attrs, NULL);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    val_count = 1;
    vals = talloc(mem_ctx, char *);
    if (!vals) {
        ret = ENOMEM;
        goto done;
    }

    i = 0;
    while (i < res->count) {
        el = ldb_msg_find_element(res->msgs[i], CONFDB_DOMAIN_ATTR);
        if (el && el->num_values > 0) {
            if (el->num_values > 1) {
                DEBUG(0, ("Error, domains should not have multivalued cn\n"));
                ret = EINVAL;
                goto done;
            }
            val_count++;
            vals = talloc_realloc(mem_ctx, vals, char *, val_count);
            if (!vals) {
                DEBUG(0, ("realloc failed\n"));
                ret = ENOMEM;
                goto done;
            }
            /* should always be strings so this should be safe */
            struct ldb_val v = el->values[0];
            vals[i] = talloc_strndup(vals, (char *)v.data, v.length);
            if (!vals[i]) {
                ret = ENOMEM;
                goto done;
            }
        }
        i++;
    }
    vals[i] = NULL;

    *values = vals;

done:
    talloc_free(tmp_ctx);
    return ret;
}
