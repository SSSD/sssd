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

#include "config.h"

#include <ctype.h>
#include "util/util.h"
#include "confdb/confdb.h"
#include "confdb/confdb_private.h"
#include "util/strtonum.h"
#include "db/sysdb.h"

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
        DEBUG(1, ("Failed to add [%s] to [%s], error [%d] (%s)\n",
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
        DEBUG(1, ("Failed to get [%s] from [%s], error [%d] (%s)\n",
                  attribute, section, ret, strerror(ret)));
    }
    return ret;
}

int confdb_set_bool(struct confdb_ctx *cdb,
                     const char *section,
                     const char *attribute,
                     bool val)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *dn;
    char *secdn;
    struct ldb_message *msg;
    int ret, lret;

    tmp_ctx = talloc_new(NULL);
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

    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }

    msg->dn = dn;

    lret = ldb_msg_add_empty(msg, attribute, LDB_FLAG_MOD_REPLACE, NULL);
    if (lret != LDB_SUCCESS) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("ldb_msg_add_empty failed: [%s]\n", ldb_strerror(lret)));
        ret = EIO;
        goto done;
    }

    if (val) {
        lret = ldb_msg_add_string(msg, attribute, "True");
    } else {
        lret = ldb_msg_add_string(msg, attribute, "False");
    }
    if (lret != LDB_SUCCESS) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("ldb_msg_add_string failed: [%s]\n", ldb_strerror(lret)));
        ret = EIO;
        goto done;
    }


    lret = ldb_modify(cdb->ldb, msg);
    if (lret != LDB_SUCCESS) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              ("ldb_modify failed: [%s]\n", ldb_strerror(lret)));
        ret = EIO;
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Failed to set [%s] from [%s], error [%d] (%s)\n",
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
    DEBUG(1, ("Failed to get [%s] from [%s], error [%d] (%s)\n",
              attribute, section, ret, strerror(ret)));
    return ret;
}

int confdb_get_int(struct confdb_ctx *cdb,
                   const char *section, const char *attribute,
                   int defval, int *result)
{
    char **values = NULL;
    long val;
    int ret;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto failed;
    }

    ret = confdb_get_param(cdb, tmp_ctx, section, attribute, &values);
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

    talloc_free(tmp_ctx);

    *result = (int)val;
    return EOK;

failed:
    talloc_free(tmp_ctx);
    DEBUG(1, ("Failed to read [%s] from [%s], error [%d] (%s)\n",
              attribute, section, ret, strerror(ret)));
    return ret;
}

long confdb_get_long(struct confdb_ctx *cdb,
                     const char *section, const char *attribute,
                     long defval, long *result)
{
    char **values = NULL;
    long val;
    int ret;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto failed;
    }

    ret = confdb_get_param(cdb, tmp_ctx, section, attribute, &values);
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

    talloc_free(tmp_ctx);

    *result = val;
    return EOK;

failed:
    talloc_free(tmp_ctx);
    DEBUG(1, ("Failed to read [%s] from [%s], error [%d] (%s)\n",
              attribute, section, ret, strerror(ret)));
    return ret;
}

int confdb_get_bool(struct confdb_ctx *cdb,
                    const char *section, const char *attribute,
                    bool defval, bool *result)
{
    char **values = NULL;
    bool val;
    int ret;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto failed;
    }

    ret = confdb_get_param(cdb, tmp_ctx, section, attribute, &values);
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

    talloc_free(tmp_ctx);

    *result = val;
    return EOK;

failed:
    talloc_free(tmp_ctx);
    DEBUG(1, ("Failed to read [%s] from [%s], error [%d] (%s)\n",
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

    ret = split_on_separator(ctx, values[0], ',', true, result, NULL);

done:
    talloc_free(values);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(2, ("Failed to get [%s] from [%s], error [%d] (%s)\n",
                  attribute, section, ret, strerror(ret)));
    }
    return ret;
}

int confdb_init(TALLOC_CTX *mem_ctx,
                struct confdb_ctx **cdb_ctx,
                const char *confdb_location)
{
    struct confdb_ctx *cdb;
    int ret = EOK;
    mode_t old_umask;

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

    old_umask = umask(0177);

    ret = ldb_connect(cdb->ldb, confdb_location, 0, NULL);
    umask(old_umask);
    if (ret != LDB_SUCCESS) {
        DEBUG(0, ("Unable to open config database [%s]\n",
                  confdb_location));
        talloc_free(cdb);
        return EIO;
    }

    *cdb_ctx = cdb;

    return EOK;
}

static errno_t get_entry_as_uint32(struct ldb_message *msg,
                                   uint32_t *return_value,
                                   const char *entry,
                                   uint32_t default_value)
{
    const char *tmp = NULL;
    char *endptr;
    uint32_t u32ret = 0;

    *return_value = 0;

    if (!msg || !entry) {
        return EFAULT;
    }

    tmp = ldb_msg_find_attr_as_string(msg, entry, NULL);
    if (tmp == NULL) {
        *return_value = default_value;
        return EOK;
    }

    if ((*tmp == '-') || (*tmp == '\0')) {
        return EINVAL;
    }

    u32ret = strtouint32 (tmp, &endptr, 10);
    if (errno) {
        return errno;
    }

    if (*endptr != '\0') {
        /* Not all of the string was a valid number */
        return EINVAL;
    }

    *return_value = u32ret;
    return EOK;
}

static errno_t get_entry_as_bool(struct ldb_message *msg,
                                   bool *return_value,
                                   const char *entry,
                                   bool default_value)
{
    const char *tmp = NULL;

    *return_value = 0;

    if (!msg || !entry) {
        return EFAULT;
    }

    tmp = ldb_msg_find_attr_as_string(msg, entry, NULL);
    if (tmp == NULL || *tmp == '\0') {
        *return_value = default_value;
        return EOK;
    }

    if (strcasecmp(tmp, "FALSE") == 0) {
        *return_value = 0;
    }
    else if (strcasecmp(tmp, "TRUE") == 0) {
        *return_value = 1;
    }
    else {
        return EINVAL;
    }

    return EOK;
}


/* The default UID/GID for domains is 1. This wouldn't work well with
 * the local provider */
static uint32_t confdb_get_min_id(struct sss_domain_info *domain)
{
    uint32_t defval = SSSD_MIN_ID;

    if (domain && strcasecmp(domain->provider, "local") == 0) {
        defval = SSSD_LOCAL_MINID;
    }

    return defval;
}

static int confdb_get_domain_internal(struct confdb_ctx *cdb,
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
    uint32_t entry_cache_timeout;

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
    domain->conn_name = domain->name;

    tmp = ldb_msg_find_attr_as_string(res->msgs[0],
                                      CONFDB_DOMAIN_ID_PROVIDER,
                                      NULL);
    if (tmp) {
        domain->provider = talloc_strdup(domain, tmp);
        if (!domain->provider) {
            ret = ENOMEM;
            goto done;
        }
    }
    else {
        DEBUG(0, ("Domain [%s] does not specify an ID provider, disabling!\n",
                  domain->name));
        ret = EINVAL;
        goto done;
    }

    if (strcasecmp(domain->provider, "files") == 0) {
        /* The files provider is not valid anymore */
        DEBUG(0, ("The \"files\" provider is invalid\n"));
        ret = EINVAL;
        goto done;
    }

    if (strcasecmp(domain->provider, "local") == 0) {
        /* If this is the local provider, we need to ensure that
         * no other provider was specified for other types, since
         * the local provider cannot load them.
         */
        tmp = ldb_msg_find_attr_as_string(res->msgs[0],
                                          CONFDB_DOMAIN_AUTH_PROVIDER,
                                          NULL);
        if (tmp && strcasecmp(tmp, "local") != 0) {
            DEBUG(0, ("Local ID provider does not support [%s] as an AUTH provider.\n", tmp));
            ret = EINVAL;
            goto done;
        }

        tmp = ldb_msg_find_attr_as_string(res->msgs[0],
                                          CONFDB_DOMAIN_ACCESS_PROVIDER,
                                          NULL);
        if (tmp && strcasecmp(tmp, "permit") != 0) {
            DEBUG(0, ("Local ID provider does not support [%s] as an ACCESS provider.\n", tmp));
            ret = EINVAL;
            goto done;
        }

        tmp = ldb_msg_find_attr_as_string(res->msgs[0],
                                          CONFDB_DOMAIN_CHPASS_PROVIDER,
                                          NULL);
        if (tmp && strcasecmp(tmp, "local") != 0) {
            DEBUG(0, ("Local ID provider does not support [%s] as a CHPASS provider.\n", tmp));
            ret = EINVAL;
            goto done;
        }
    }

    domain->timeout = ldb_msg_find_attr_as_int(res->msgs[0],
                                               CONFDB_DOMAIN_TIMEOUT, 0);

    /* Determine if this domain can be enumerated */

    /* TEMP: test if the old bitfield conf value is used and warn it has been
     * superceeded. */
    val = ldb_msg_find_attr_as_int(res->msgs[0], CONFDB_DOMAIN_ENUMERATE, 0);
    if (val > 0) { /* ok there was a number in here */
        DEBUG(0, ("Warning: enumeration parameter in %s still uses integers! "
                  "Enumeration is now a boolean and takes true/false values. "
                  "Interpreting as true\n", domain->name));
        domain->enumerate = true;
    } else { /* assume the new format */
        ret = get_entry_as_bool(res->msgs[0], &domain->enumerate,
                                CONFDB_DOMAIN_ENUMERATE, 0);
        if(ret != EOK) {
            DEBUG(0, ("Invalid value for %s\n", CONFDB_DOMAIN_ENUMERATE));
            goto done;
        }
    }
    if (!domain->enumerate) {
        DEBUG(SSSDBG_TRACE_FUNC, ("No enumeration for [%s]!\n", domain->name));
    }

    /* Determine if user/group names will be Fully Qualified
     * in NSS interfaces */
    ret = get_entry_as_bool(res->msgs[0], &domain->fqnames, CONFDB_DOMAIN_FQ, 0);
    if(ret != EOK) {
        DEBUG(0, ("Invalid value for %s\n", CONFDB_DOMAIN_FQ));
        goto done;
    }

    ret = get_entry_as_uint32(res->msgs[0], &domain->id_min,
                              CONFDB_DOMAIN_MINID,
                              confdb_get_min_id(domain));
    if (ret != EOK) {
        DEBUG(0, ("Invalid value for minId\n"));
        ret = EINVAL;
        goto done;
    }

    ret = get_entry_as_uint32(res->msgs[0], &domain->id_max,
                              CONFDB_DOMAIN_MAXID, 0);
    if (ret != EOK) {
        DEBUG(0, ("Invalid value for maxId\n"));
        ret = EINVAL;
        goto done;
    }

    if (domain->id_max && (domain->id_max < domain->id_min)) {
        DEBUG(0, ("Invalid domain range\n"));
        ret = EINVAL;
        goto done;
    }

    /* Do we allow to cache credentials */
    ret = get_entry_as_bool(res->msgs[0], &domain->cache_credentials,
                            CONFDB_DOMAIN_CACHE_CREDS, 0);
    if(ret != EOK) {
        DEBUG(0, ("Invalid value for %s\n", CONFDB_DOMAIN_CACHE_CREDS));
        goto done;
    }

    ret = get_entry_as_bool(res->msgs[0], &domain->legacy_passwords,
                            CONFDB_DOMAIN_LEGACY_PASS, 0);
    if(ret != EOK) {
        DEBUG(0, ("Invalid value for %s\n", CONFDB_DOMAIN_LEGACY_PASS));
        goto done;
    }

    /* Get the global entry cache timeout setting */
    ret = get_entry_as_uint32(res->msgs[0], &entry_cache_timeout,
                              CONFDB_DOMAIN_ENTRY_CACHE_TIMEOUT, 5400);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              ("Invalid value for [%s]\n",
                CONFDB_DOMAIN_ENTRY_CACHE_TIMEOUT));
        goto done;
    }

    /* Override the user cache timeout, if specified */
    ret = get_entry_as_uint32(res->msgs[0], &domain->user_timeout,
                              CONFDB_DOMAIN_USER_CACHE_TIMEOUT,
                              entry_cache_timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              ("Invalid value for [%s]\n",
               CONFDB_DOMAIN_USER_CACHE_TIMEOUT));
        goto done;
    }

    /* Override the group cache timeout, if specified */
    ret = get_entry_as_uint32(res->msgs[0], &domain->group_timeout,
                              CONFDB_DOMAIN_GROUP_CACHE_TIMEOUT,
                              entry_cache_timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              ("Invalid value for [%s]\n",
               CONFDB_DOMAIN_GROUP_CACHE_TIMEOUT));
        goto done;
    }

    /* Override the netgroup cache timeout, if specified */
    ret = get_entry_as_uint32(res->msgs[0], &domain->netgroup_timeout,
                              CONFDB_DOMAIN_NETGROUP_CACHE_TIMEOUT,
                              entry_cache_timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              ("Invalid value for [%s]\n",
               CONFDB_DOMAIN_NETGROUP_CACHE_TIMEOUT));
        goto done;
    }

    /* Override the service cache timeout, if specified */
    ret = get_entry_as_uint32(res->msgs[0], &domain->service_timeout,
                              CONFDB_DOMAIN_SERVICE_CACHE_TIMEOUT,
                              entry_cache_timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              ("Invalid value for [%s]\n",
               CONFDB_DOMAIN_SERVICE_CACHE_TIMEOUT));
        goto done;
    }

    /* Override the autofs cache timeout, if specified */
    ret = get_entry_as_uint32(res->msgs[0], &domain->autofsmap_timeout,
                              CONFDB_DOMAIN_AUTOFS_CACHE_TIMEOUT,
                              entry_cache_timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              ("Invalid value for [%s]\n",
               CONFDB_DOMAIN_AUTOFS_CACHE_TIMEOUT));
        goto done;
    }

    /* Override the sudo cache timeout, if specified */
    ret = get_entry_as_uint32(res->msgs[0], &domain->sudo_timeout,
                              CONFDB_DOMAIN_SUDO_CACHE_TIMEOUT,
                              entry_cache_timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              ("Invalid value for [%s]\n",
               CONFDB_DOMAIN_SUDO_CACHE_TIMEOUT));
        goto done;
    }

    /* Set the PAM warning time, if specified */
    val = ldb_msg_find_attr_as_int(res->msgs[0],
                                   CONFDB_DOMAIN_PWD_EXPIRATION_WARNING,
                                   -1);
    if (val > 0) {
        /* The value is in days, transform it to seconds */
        val *= 24 * 3600;
    } else {
        ret = confdb_get_int(cdb, CONFDB_PAM_CONF_ENTRY,
                             CONFDB_PAM_PWD_EXPIRATION_WARNING,
                             -1, &val);
        if (ret != EOK) {
            DEBUG(1, ("Failed to read PAM expiration warning, not fatal.\n"));
            val = -1;
        }
    }
    domain->pwd_expiration_warning = val;

    ret = get_entry_as_uint32(res->msgs[0], &domain->override_gid,
                              CONFDB_DOMAIN_OVERRIDE_GID, 0);
    if (ret != EOK) {
        DEBUG(0, ("Invalid value for [%s]\n", CONFDB_DOMAIN_OVERRIDE_GID));
        goto done;
    }

    tmp = ldb_msg_find_attr_as_string(res->msgs[0],
                                      CONFDB_NSS_OVERRIDE_HOMEDIR, NULL);
    if (tmp != NULL) {
        domain->override_homedir = talloc_strdup(domain, tmp);
        if (!domain->override_homedir) {
            ret = ENOMEM;
            goto done;
        }
    }

    tmp = ldb_msg_find_attr_as_string(res->msgs[0],
                                      CONFDB_NSS_FALLBACK_HOMEDIR, NULL);
    if (tmp != NULL) {
        domain->fallback_homedir = talloc_strdup(domain, tmp);
        if (!domain->fallback_homedir) {
            ret = ENOMEM;
            goto done;
        }
    }

    tmp = ldb_msg_find_attr_as_string(res->msgs[0],
                                      CONFDB_DOMAIN_SUBDOMAIN_HOMEDIR,
                                      CONFDB_DOMAIN_DEFAULT_SUBDOMAIN_HOMEDIR);
    if (tmp != NULL) {
        domain->subdomain_homedir = talloc_strdup(domain, tmp);
        if (!domain->subdomain_homedir) {
            ret = ENOMEM;
            goto done;
        }
    }

    tmp = ldb_msg_find_attr_as_string(res->msgs[0],
                                      CONFDB_NSS_OVERRIDE_SHELL, NULL);
    if (tmp != NULL) {
        domain->override_shell = talloc_strdup(domain, tmp);
        if (!domain->override_shell) {
            ret = ENOMEM;
            goto done;
        }
    }

    tmp = ldb_msg_find_attr_as_string(res->msgs[0],
                                      CONFDB_NSS_DEFAULT_SHELL, NULL);
    if (tmp != NULL) {
        domain->default_shell = talloc_strdup(domain, tmp);
        if (!domain->default_shell) {
            ret = ENOMEM;
            goto done;
        }
    }

    ret = get_entry_as_bool(res->msgs[0], &domain->case_sensitive,
                            CONFDB_DOMAIN_CASE_SENSITIVE, true);
    if(ret != EOK) {
        DEBUG(0, ("Invalid value for %s\n", CONFDB_DOMAIN_CASE_SENSITIVE));
        goto done;
    }
    if (domain->case_sensitive == false &&
        strcasecmp(domain->provider, "local") == 0) {
        DEBUG(SSSDBG_FATAL_FAILURE,
             ("Local ID provider does not support the case insensitive flag\n"));
        ret = EINVAL;
        goto done;
    }

    *_domain = domain;
    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

int confdb_get_domains(struct confdb_ctx *cdb,
                       struct sss_domain_info **domains)
{
    TALLOC_CTX *tmp_ctx;
    struct sss_domain_info *domain, *prevdom = NULL;
    char **domlist;
    int ret, i;

    if (cdb->doms) {
        *domains = cdb->doms;
        return EOK;
    }

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    ret = confdb_get_string_as_list(cdb, tmp_ctx,
                                    CONFDB_MONITOR_CONF_ENTRY,
                                    CONFDB_MONITOR_ACTIVE_DOMAINS,
                                    &domlist);
    if (ret == ENOENT) {
        DEBUG(0, ("No domains configured, fatal error!\n"));
        goto done;
    }
    if (ret != EOK ) {
        DEBUG(0, ("Fatal error retrieving domains list!\n"));
        goto done;
    }

    for (i = 0; domlist[i]; i++) {
        ret = confdb_get_domain_internal(cdb, cdb, domlist[i], &domain);
        if (ret) {
            DEBUG(0, ("Error (%d [%s]) retrieving domain [%s], skipping!\n",
                      ret, strerror(ret), domlist[i]));
            continue;
        }

        if (cdb->doms == NULL) {
            cdb->doms = domain;
            prevdom = cdb->doms;
        } else {
            prevdom->next = domain;
            prevdom = domain;
        }
    }

    if (cdb->doms == NULL) {
        DEBUG(0, ("No properly configured domains, fatal error!\n"));
        ret = ENOENT;
        goto done;
    }

    *domains = cdb->doms;
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

int confdb_get_domain(struct confdb_ctx *cdb,
                      const char *name,
                      struct sss_domain_info **_domain)
{
    struct sss_domain_info *dom, *doms;
    int ret;

    ret = confdb_get_domains(cdb, &doms);
    if (ret != EOK) {
        return ret;
    }

    for (dom = doms; dom; dom = dom->next) {
        if (strcasecmp(dom->name, name) == 0) {
            *_domain = dom;
            return EOK;
        }
    }

    return ENOENT;
}
