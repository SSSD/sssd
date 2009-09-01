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
#include "util/util.h"
#include "confdb/confdb.h"
#include "confdb/confdb_private.h"
#include "util/btreemap.h"
#include "db/sysdb.h"

#define CONFDB_DOMAINS_PATH "config/domains"
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

int parse_section(TALLOC_CTX *mem_ctx, const char *section,
                  char **sec_dn, const char **rdn_name)
{
    TALLOC_CTX *tmp_ctx;
    char *dn = NULL;
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

/* split a string into an allocated array of strings.
 * the separator is a string, and is case-sensitive.
 * optionally single values can be trimmed of of spaces and tabs */
static int split_on_separator(TALLOC_CTX *mem_ctx, const char *str,
                              const char *sep, bool trim, char ***_list, int *size)
{
    const char *t, *p, *n;
    size_t l, s, len;
    char **list, **r;

    if (!str || !*str || !sep || !*sep || !_list) return EINVAL;

    s = strlen(sep);
    t = str;

    list = NULL;
    l = 0;

    if (trim)
        while (*t == ' ' || *t == '\t') t++;

    while (t && (p = strstr(t, sep))) {
        len = p - t;
        n = p + s; /* save next string starting point */
        if (trim) {
            while (*t == ' ' || *t == '\t') {
                t++;
                len--;
                if (len == 0) break;
            }
            p--;
            while (len > 0 && (*p == ' ' || *p == '\t')) {
                len--;
                p--;
            }
        }

        r = talloc_realloc(mem_ctx, list, char *, l + 2);
        if (!r) {
            talloc_free(list);
            return ENOMEM;
        } else {
            list = r;
        }

        if (len == 0) {
            list[l] = talloc_strdup(list, "");
        } else {
            list[l] = talloc_strndup(list, t, len);
        }
        if (!list[l]) {
            talloc_free(list);
            return ENOMEM;
        }
        l++;

        t = n; /* move to next string */
    }

    if (t) {
        r = talloc_realloc(mem_ctx, list, char *, l + 2);
        if (!r) {
            talloc_free(list);
            return ENOMEM;
        } else {
            list = r;
        }

        if (trim) {
            len = strlen(t);
            while (*t == ' ' || *t == '\t') {
                t++;
                len--;
                if (len == 0) break;
            }
            p = t + len - 1;
            while (len > 0 && (*p == ' ' || *p == '\t')) {
                len--;
                p--;
            }

            if (len == 0) {
                list[l] = talloc_strdup(list, "");
            } else {
                list[l] = talloc_strndup(list, t, len);
            }
        } else {
            list[l] = talloc_strdup(list, t);
        }
        if (!list[l]) {
            talloc_free(list);
            return ENOMEM;
        }
        l++;
    }

    list[l] = NULL; /* terminate list */

    if (size) *size = l + 1;
    *_list = list;

    return EOK;
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

/* WARNING: Unlike other similar functions, this one does NOT take a default,
 * and returns ENOENT if the attribute was not found ! */
int confdb_get_string_as_list(struct confdb_ctx *cdb, TALLOC_CTX *ctx,
                              const char *section, const char *attribute,
                              char ***result)
{
    char **values = NULL;
    int ret;

    ret = confdb_get_param(cdb, ctx, section, attribute, &values);
    if (ret != EOK) {
        goto done;
    }

    if (values && values[0]) {
        if (values[1] != NULL) {
            /* too many values */
            ret = EINVAL;
            goto done;
        }
    } else {
        /* Did not return a value */
        ret = ENOENT;
        goto done;
    }

    ret = split_on_separator(ctx, values[0], ",", true, result, NULL);

done:
    talloc_free(values);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(2, ("Failed to get [%s] from [%s], error [%d] (%s)",
                  attribute, section, ret, strerror(ret)));
    }
    return ret;
}

int confdb_init(TALLOC_CTX *mem_ctx,
                struct tevent_context *ev,
                struct confdb_ctx **cdb_ctx,
                char *confdb_location)
{
    struct confdb_ctx *cdb;
    int ret = EOK;

    cdb = talloc_zero(mem_ctx, struct confdb_ctx);
    if (!cdb)
        return ENOMEM;

    /* Because confdb calls use sync ldb calls, we create a separate event
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

    ret = ldb_set_debug(cdb->ldb, ldb_debug_messages, NULL);
    if (ret != LDB_SUCCESS) {
        DEBUG(0,("Could not set up debug fn.\n"));
        talloc_free(cdb);
        return EIO;
    }

    ret = ldb_connect(cdb->ldb, confdb_location, 0, NULL);
    if (ret != LDB_SUCCESS) {
        talloc_free(cdb);
        return EIO;
    }

    *cdb_ctx = cdb;

    return EOK;
}

int confdb_get_domain(struct confdb_ctx *cdb,
                      TALLOC_CTX *mem_ctx,
                      const char *name,
                      struct sss_domain_info **_domain)
{
    struct sss_domain_info *domain;
    struct ldb_result *res;
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *dn;
    const char *tmp;
    int ret, val;

    tmp_ctx = talloc_new(mem_ctx);
    if (!tmp_ctx) return ENOMEM;

    dn = ldb_dn_new_fmt(tmp_ctx, cdb->ldb,
                        "cn=%s,%s", name, CONFDB_DOMAIN_BASEDN);
    if (!dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_search(cdb->ldb, tmp_ctx, &res, dn,
                     LDB_SCOPE_BASE, NULL, NULL);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    if (res->count != 1) {
        DEBUG(0, ("Unknown domain [%s]\n", name));
        ret = ENOENT;
        goto done;
    }

    domain = talloc_zero(mem_ctx, struct sss_domain_info);
    if (!domain) {
        ret = ENOMEM;
        goto done;
    }

    tmp = ldb_msg_find_attr_as_string(res->msgs[0], "cn", NULL);
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

    tmp = ldb_msg_find_attr_as_string(res->msgs[0], "provider", NULL);
    if (tmp) {
        domain->provider = talloc_strdup(domain, tmp);
        if (!domain->provider) {
            ret = ENOMEM;
            goto done;
        }
    }
    else {
        DEBUG(0, ("Domain [%s] does not specify a provider, disabling!\n",
                  domain->name));
        ret = EINVAL;
        goto done;
    }

    domain->timeout = ldb_msg_find_attr_as_int(res->msgs[0],
                                               "timeout", 0);

    /* Determine if this domain can be enumerated */

    /* TEMP: test if the old bitfield conf value is used and warn it has been
     * superceeded. */
    val = ldb_msg_find_attr_as_int(res->msgs[0], "enumerate", 0);
    if (val > 0) { /* ok there was a number in here */
        DEBUG(0, ("Warning: enumeration parameter in %s still uses integers! "
                  "Enumeration is now a boolean and takes true/false values. "
                  "Interpreting as true\n", domain->name));
        domain->enumerate = true;
    } else { /* assume the new format */
        if (ldb_msg_find_attr_as_bool(res->msgs[0], "enumerate", 0)) {
            domain->enumerate = true;
        }
    }
    if (!domain->enumerate) {
        DEBUG(1, ("No enumeration for [%s]!\n", domain->name));
    }

    /* Determine if this is a legacy domain */
    if (ldb_msg_find_attr_as_bool(res->msgs[0], "legacy", 0)) {
        domain->legacy = true;
    }

    /* Determine if this is domain uses MPG */
    if (strcasecmp(domain->provider, "local") == 0 ||
        ldb_msg_find_attr_as_bool(res->msgs[0], CONFDB_MPG, 0)) {
        domain->mpg = true;
    }

    /* Determine if user/group names will be Fully Qualified
     * in NSS interfaces */
    if (ldb_msg_find_attr_as_bool(res->msgs[0], CONFDB_FQ, 0)) {
        domain->fqnames = true;
    }

    domain->id_min = ldb_msg_find_attr_as_uint(res->msgs[0],
                                               "minId", SSSD_MIN_ID);
    domain->id_max = ldb_msg_find_attr_as_uint(res->msgs[0],
                                               "maxId", 0);

    /* Do we allow to cache credentials */
    if (ldb_msg_find_attr_as_bool(res->msgs[0], "cache-credentials", 0)) {
        domain->cache_credentials = true;
    }

    if (ldb_msg_find_attr_as_bool(res->msgs[0], "store-legacy-passwords", 0)) {
        domain->legacy_passwords = true;
    }

    *_domain = domain;
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

int confdb_get_domains(struct confdb_ctx *cdb,
                       TALLOC_CTX *mem_ctx,
                       struct sss_domain_info **domains)
{
    TALLOC_CTX *tmp_ctx;
    struct sss_domain_info *domain, *prevdom = NULL;
    struct sss_domain_info *first = NULL;
    char **domlist;
    int ret, i;

    tmp_ctx = talloc_new(mem_ctx);
    if (!tmp_ctx) return ENOMEM;

    ret = confdb_get_string_as_list(cdb, tmp_ctx,
                                    CONFDB_DOMAINS_PATH, "domains", &domlist);
    if (ret == ENOENT) {
        DEBUG(0, ("No domains configured, fatal error!\n"));
        goto done;
    }
    if (ret != EOK ) {
        DEBUG(0, ("Fatal error retrieving domains list!\n"));
        goto done;
    }

    for (i = 0; domlist[i]; i++) {
        ret = confdb_get_domain(cdb, mem_ctx, domlist[i], &domain);
        if (ret) {
            DEBUG(0, ("Error (%d [%s]) retrieving domain [%s], skipping!\n",
                      ret, strerror(ret), domlist[i]));
            ret = EOK;
            continue;
        }

        if (first == NULL) {
            first = domain;
            prevdom = first;
        } else {
            prevdom->next = domain;
            prevdom = domain;
        }
    }

    if (first == NULL) {
        DEBUG(0, ("No domains configured, fatal error!\n"));
        ret = ENOENT;
    }

    *domains = first;

done:
    talloc_free(tmp_ctx);
    return ret;
}
