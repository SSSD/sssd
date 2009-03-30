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
#include "ldb.h"
#include "ldb_errors.h"
#include "util/util.h"
#include "confdb/confdb.h"
#include "confdb/confdb_private.h"
#include "util/btreemap.h"
#include "db/sysdb.h"
#define CONFDB_VERSION "0.1"
#define CONFDB_DOMAIN_BASEDN "cn=domains,cn=config"
#define CONFDB_DOMAIN_ATTR "cn"
#define CONFDB_MPG "magicPrivateGroups"
#define CONFDB_FQ "useFullyQualifiedNames"

#define CONFDB_ZERO_CHECK_OR_JUMP(var, ret, err, label) do { \
    if (!var) { \
        ret = err; \
        goto label; \
    } \
} while(0)

struct confdb_ctx {
    struct tevent_context *pev;
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
    TALLOC_CTX *tmp_ctx = NULL;
    struct ldb_message *msg;
    struct ldb_result *res;
    struct ldb_dn *dn;
    char *secdn;
    const char *rdn_name;
    int ret, i;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        ret = ENOMEM;
        goto done;
    }

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
    if (ret != EOK) {
        DEBUG(1, ("Failed to add [%s] to [%s], error [%d] (%s)",
                  attribute, section, ret, strerror(ret)));
    }
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
    if (ret != EOK) {
        DEBUG(1, ("Failed to get [%s] from [%s], error [%d] (%s)",
                  attribute, section, ret, strerror(ret)));
    }
    return ret;
}

int confdb_get_string(struct confdb_ctx *cdb, TALLOC_CTX *ctx,
                      const char *section, const char *attribute,
                      const char *defstr, char **result)
{
    char **values = NULL;
    char *restr;
    int ret;

    ret = confdb_get_param(cdb, ctx, section, attribute, &values);
    if (ret != EOK) {
        goto failed;
    }

    if (values[0]) {
        if (values[1] != NULL) {
            /* too many values */
            ret = EINVAL;
            goto failed;
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
        ret = ENOMEM;
        goto failed;
    }

    talloc_free(values);

    *result = restr;
    return EOK;

failed:
    talloc_free(values);
    DEBUG(1, ("Failed to get [%s] from [%s], error [%d] (%s)",
              attribute, section, ret, strerror(ret)));
    return ret;
}

int confdb_get_int(struct confdb_ctx *cdb, TALLOC_CTX *ctx,
                   const char *section, const char *attribute,
                   int defval, int *result)
{
    char **values = NULL;
    long val;
    int ret;

    ret = confdb_get_param(cdb, ctx, section, attribute, &values);
    if (ret != EOK) {
        goto failed;
    }

    if (values[0]) {
        if (values[1] != NULL) {
            /* too many values */
            ret = EINVAL;
            goto failed;
        }

        errno = 0;
        val = strtol(values[0], NULL, 0);
        if (errno) {
            ret = errno;
            goto failed;
        }

        if (val < INT_MIN || val > INT_MAX) {
            ret = ERANGE;
            goto failed;
        }

    } else {
        val = defval;
    }

    talloc_free(values);

    *result = (int)val;
    return EOK;

failed:
    talloc_free(values);
    DEBUG(1, ("Failed to read [%s] from [%s], error [%d] (%s)",
              attribute, section, ret, strerror(ret)));
    return ret;
}

long confdb_get_long(struct confdb_ctx *cdb, TALLOC_CTX *ctx,
                     const char *section, const char *attribute,
                     long defval, long *result)
{
    char **values = NULL;
    long val;
    int ret;

    ret = confdb_get_param(cdb, ctx, section, attribute, &values);
    if (ret != EOK) {
        goto failed;
    }

    if (values[0]) {
        if (values[1] != NULL) {
            /* too many values */
            ret = EINVAL;
            goto failed;
        }

        errno = 0;
        val = strtol(values[0], NULL, 0);
        if (errno) {
            ret = errno;
            goto failed;
        }

    } else {
        val = defval;
    }

    talloc_free(values);

    *result = val;
    return EOK;

failed:
    talloc_free(values);
    DEBUG(1, ("Failed to read [%s] from [%s], error [%d] (%s)",
              attribute, section, ret, strerror(ret)));
    return ret;
}

int confdb_get_bool(struct confdb_ctx *cdb, TALLOC_CTX *ctx,
                    const char *section, const char *attribute,
                    bool defval, bool *result)
{
    char **values = NULL;
    bool val;
    int ret;

    ret = confdb_get_param(cdb, ctx, section, attribute, &values);
    if (ret != EOK) {
        goto failed;
    }

    if (values[0]) {
        if (values[1] != NULL) {
            /* too many values */
            ret = EINVAL;
            goto failed;
        }

        if (strcasecmp(values[0], "FALSE") == 0) {
            val = false;

        } else if (strcasecmp(values[0], "TRUE") == 0) {
            val = true;

        } else {

            DEBUG(2, ("Value is not a boolean!\n"));
            ret = EINVAL;
            goto failed;
        }

    } else {
        val = defval;
    }

    talloc_free(values);

    *result = val;
    return EOK;

failed:
    talloc_free(values);
    DEBUG(1, ("Failed to read [%s] from [%s], error [%d] (%s)",
              attribute, section, ret, strerror(ret)));
    return ret;
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
    const char *base_ldif;
	struct ldb_ldif *ldif;
    const char *val[2] = {NULL, NULL};
    int ret;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(cdb);
    if(tmp_ctx == NULL) return ENOMEM;

    /* cn=confdb does not exists, means db is empty, populate */
    base_ldif = CONFDB_BASE_LDIF;
    while ((ldif = ldb_ldif_read_string(cdb->ldb, &base_ldif))) {
        ret = ldb_add(cdb->ldb, ldif->msg);
        if (ret != LDB_SUCCESS) {
            DEBUG(0, ("Failed to inizialiaze DB (%d,[%s]), aborting!\n",
                      ret, ldb_errstring(cdb->ldb)));
            ret = EIO;
            goto done;
        }
        ldb_ldif_read_free(cdb->ldb, ldif);
    }

/* InfoPipe */
#ifdef HAVE_INFOPIPE
    /* Set the sssd_info description */
    val[0] = "InfoPipe Configuration";
    ret = confdb_add_param(cdb, false, "config/services/info", "description", val);
    if (ret != EOK) goto done;

    /* Set the sssd_info command path */
    val[0] = talloc_asprintf(tmp_ctx, "%s/sssd_info", SSSD_LIBEXEC_PATH);
    CONFDB_ZERO_CHECK_OR_JUMP(val[0], ret, ENOMEM, done);
    ret = confdb_add_param(cdb, false, "config/services/info", "command", val);
    if (ret != EOK) goto done;

    /* Add the InfoPipe to the list of active services */
    val[0] = "info";
    ret = confdb_add_param(cdb, false, "config/services", "activeServices", val);
    if (ret != EOK) goto done;
#endif

/* PolicyKit */
#ifdef HAVE_POLICYKIT
    /* Set the sssd_pk description */
    val[0] = "PolicyKit Backend Configuration";
    ret = confdb_add_param(cdb, false, "config/services/pk", "description", val);
    if (ret != EOK) goto done;

    /* Set the sssd_info command path */
    val[0] = talloc_asprintf(tmp_ctx, "%s/sssd_pk", SSSD_LIBEXEC_PATH);
    CONFDB_ZERO_CHECK_OR_JUMP(val[0], ret, ENOMEM, done);
    ret = confdb_add_param(cdb, false, "config/services/pk", "command", val);
    if (ret != EOK) goto done;

    /* Add the InfoPipe to the list of active services */
    val[0] = "pk";
    ret = confdb_add_param(cdb, false, "config/services", "activeServices", val);
    if (ret != EOK) goto done;
#endif

done:
    talloc_free(tmp_ctx);
    return ret;
}

int confdb_init(TALLOC_CTX *mem_ctx,
                struct tevent_context *ev,
                struct confdb_ctx **cdb_ctx,
                char *confdb_location)
{
    struct confdb_ctx *cdb;
    int ret;

    cdb = talloc_zero(mem_ctx, struct confdb_ctx);
    if (!cdb)
        return ENOMEM;

    /* Because condb calls use sync ldb calls, we create a separate event
     * context here. This will prevent the ldb sync calls to start nested
     * events.
     * NOTE: this means that we *cannot* do async calls and return in confdb
     * unless we convert all calls and hook back to the main event context.
     */

    cdb->pev = tevent_context_init(cdb);
    if (!cdb->pev) {
        talloc_free(cdb);
        return EIO;
    }

    cdb->ldb = ldb_init(cdb, cdb->pev);
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

/* domain names are case insensitive for now
 * NOTE: this function is not utf-8 safe,
 * only ASCII names for now */
static int _domain_comparator(const void *key1, const void *key2)
{
    int ret;

    ret = strcasecmp((const char *)key1, (const char *)key2);
    if (ret) {
        /* special case LOCAL to be always the first domain */
        if (strcmp(key1, "LOCAL") == 0) return -1;
        if (strcmp(key2, "LOCAL") == 0) return 1;
    }
    return ret;
}

int confdb_get_domains(struct confdb_ctx *cdb,
                       TALLOC_CTX *mem_ctx,
                       struct btreemap **domains)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *dn;
    struct ldb_result *res;
    struct btreemap *domain_map;
    struct sss_domain_info *domain;
    const char *tmp;
    int ret, i;

    tmp_ctx = talloc_new(mem_ctx);
    if (!tmp_ctx) return ENOMEM;

    dn = ldb_dn_new(tmp_ctx,cdb->ldb, CONFDB_DOMAIN_BASEDN);
    if (!dn) {
        ret = EIO;
        goto done;
    }

    ret = ldb_search(cdb->ldb, tmp_ctx, &res, dn,
                     LDB_SCOPE_ONELEVEL, NULL, NULL);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    domain_map = NULL;
    for(i = 0; i < res->count; i++) {
        /* allocate the domain on the tmp_ctx. It will be stolen
         * by btreemap_set_value
         */
        domain = talloc_zero(mem_ctx, struct sss_domain_info);

        tmp = ldb_msg_find_attr_as_string(res->msgs[i], "cn", NULL);
        if (!tmp) {
            DEBUG(0, ("Invalid configuration entry, fatal error!\n"));
            ret = EINVAL;
            goto done;
        }
        domain->name = talloc_strdup(domain, tmp);
        if (!domain->name) {
            ret = ENOMEM;
            goto done;
        }

        tmp = ldb_msg_find_attr_as_string(res->msgs[i], "provider", NULL);
        if (tmp) {
            domain->provider = talloc_strdup(domain, tmp);
            if (!domain->provider) {
                ret = ENOMEM;
                goto done;
            }
        }

        domain->timeout = ldb_msg_find_attr_as_int(res->msgs[i],
                                                   "timeout", 0);

        /* Determine if this domain can be enumerated */
        domain->enumerate = ldb_msg_find_attr_as_int(res->msgs[i],
                                                     "enumerate", 0);
        if (domain->enumerate == 0) {
            DEBUG(1, ("No enumeration for [%s]!\n", domain->name));
        }

        /* Determine if this is a legacy domain */
        if (ldb_msg_find_attr_as_bool(res->msgs[i], "legacy", 0)) {
            domain->legacy = true;
        }

        /* Determine if this is domain uses MPG */
        if (ldb_msg_find_attr_as_bool(res->msgs[i], CONFDB_MPG, 0)) {
            domain->mpg = true;
        }

        /* Determine if user/group names will be Fully Qualified
         * in NSS interfaces */
        if (ldb_msg_find_attr_as_bool(res->msgs[i], CONFDB_FQ, 0)) {
            domain->fqnames = true;
        }


        domain->id_min = ldb_msg_find_attr_as_uint(res->msgs[i],
                                                   "minId", SSSD_MIN_ID);
        domain->id_max = ldb_msg_find_attr_as_uint(res->msgs[i],
                                                   "maxId", 0);

        ret = btreemap_set_value(mem_ctx, &domain_map,
                                 domain->name, domain,
                                 _domain_comparator);
        if (ret != EOK) {
            DEBUG(1, ("Failed to store domain info for [%s]!\n", domain->name));
            talloc_free(domain_map);
            goto done;
        }
    }

    if (domain_map == NULL) {
        DEBUG(0, ("No domains configured, fatal error!\n"));
        ret = EINVAL;
    }

    *domains = domain_map;

done:
    talloc_free(tmp_ctx);
    return ret;
}

int confdb_get_domains_list(struct confdb_ctx *cdb,
                            TALLOC_CTX *mem_ctx,
                            struct btreemap **domain_map,
                            const char ***domain_names,
                            int *count)
{
    const void **names;
    int num;
    int ret;

    if (*domain_map == NULL) {
        ret = confdb_get_domains(cdb, mem_ctx, domain_map);
        if (ret != EOK) return ret;
    }

    ret = btreemap_get_keys(mem_ctx, *domain_map, &names, &num);
    if (ret != EOK) {
        DEBUG(0, ("Couldn't get domain list\n"));
        return ret;
    }

    *domain_names = (const char **)names;
    *count = num;
    return EOK;
}
