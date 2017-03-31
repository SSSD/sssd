/*
   SSSD

   SSSD Configuration DB

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

/* Warning messages */
#define SAME_DOMAINS_ERROR_MSG "Domain '%s' is the same as or differs only "\
                               "in case from domain '%s'.\n"

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
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "ldb_modify failed: [%s](%d)[%s]\n",
                  ldb_strerror(ret), ret, ldb_errstring(cdb->ldb));
            ret = EIO;
            goto done;
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to add [%s] to [%s], error [%d] (%s)\n",
                  attribute, section, ret, strerror(ret));
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
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to get [%s] from [%s], error [%d] (%s)\n",
                  attribute, section, ret, strerror(ret));
    }
    return ret;
}

int confdb_set_string(struct confdb_ctx *cdb,
                      const char *section,
                      const char *attribute,
                      const char *val)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *dn;
    char *secdn;
    struct ldb_message *msg;
    int ret, lret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

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
              "ldb_msg_add_empty failed: [%s]\n", ldb_strerror(lret));
        ret = EIO;
        goto done;
    }

    lret = ldb_msg_add_string(msg, attribute, val);
    if (lret != LDB_SUCCESS) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "ldb_msg_add_string failed: [%s]\n", ldb_strerror(lret));
        ret = EIO;
        goto done;
    }

    lret = ldb_modify(cdb->ldb, msg);
    if (lret != LDB_SUCCESS) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "ldb_modify failed: [%s](%d)[%s]\n",
              ldb_strerror(lret), lret, ldb_errstring(cdb->ldb));
        ret = EIO;
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to set [%s] from [%s], error [%d] (%s)\n",
               attribute, section, ret, strerror(ret));
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
    DEBUG(SSSDBG_CRIT_FAILURE,
          "Failed to get [%s] from [%s], error [%d] (%s)\n",
              attribute, section, ret, strerror(ret));
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
        ret = errno;
        if (ret != 0) {
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
    DEBUG(SSSDBG_CRIT_FAILURE,
          "Failed to read [%s] from [%s], error [%d] (%s)\n",
              attribute, section, ret, strerror(ret));
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
        ret = errno;
        if (ret != 0) {
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
    DEBUG(SSSDBG_CRIT_FAILURE,
          "Failed to read [%s] from [%s], error [%d] (%s)\n",
              attribute, section, ret, strerror(ret));
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

            DEBUG(SSSDBG_OP_FAILURE, "Value is not a boolean!\n");
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
    DEBUG(SSSDBG_CRIT_FAILURE,
          "Failed to read [%s] from [%s], error [%d] (%s)\n",
              attribute, section, ret, strerror(ret));
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

    ret = split_on_separator(ctx, values[0], ',', true, true, result, NULL);

done:
    talloc_free(values);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to get [%s] from [%s], error [%d] (%s)\n",
                  attribute, section, ret, strerror(ret));
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
        DEBUG(SSSDBG_FATAL_FAILURE,"Could not set up debug fn.\n");
        talloc_free(cdb);
        return EIO;
    }

    old_umask = umask(SSS_DFL_UMASK);

    ret = ldb_connect(cdb->ldb, confdb_location, 0, NULL);
    umask(old_umask);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to open config database [%s]\n",
                  confdb_location);
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

static errno_t init_cached_auth_timeout(struct confdb_ctx *cdb,
                                        struct ldb_message *msg,
                                        uint32_t *_cached_auth_timeout)
{
    int cred_expiration;
    int id_timeout;
    errno_t ret;
    uint32_t cached_auth_timeout;

    ret = get_entry_as_uint32(msg, &cached_auth_timeout,
                              CONFDB_DOMAIN_CACHED_AUTH_TIMEOUT, 0);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Invalid value for [%s]\n", CONFDB_DOMAIN_CACHED_AUTH_TIMEOUT);
        goto done;
    }

    ret = confdb_get_int(cdb, CONFDB_PAM_CONF_ENTRY,
                         CONFDB_PAM_CRED_TIMEOUT, 0, &cred_expiration);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to read expiration time of offline credentials.\n");
        goto done;
    }

    /* convert from days to seconds */
    cred_expiration *= 3600 * 24;
    if (cred_expiration != 0 &&
        cred_expiration < cached_auth_timeout) {
        cached_auth_timeout = cred_expiration;
    }

    /* Set up the PAM identity timeout */
    ret = confdb_get_int(cdb, CONFDB_PAM_CONF_ENTRY,
                         CONFDB_PAM_ID_TIMEOUT, 5,
                         &id_timeout);
    if (ret != EOK) goto done;

    if (cached_auth_timeout > id_timeout) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "cached_auth_timeout is greater than pam_id_timeout so be aware "
              "that back end could be called to handle initgroups.\n");
    }

    ret = EOK;

done:
    if (ret == EOK) {
        *_cached_auth_timeout = cached_auth_timeout;
    }
    return ret;
}

static int confdb_get_domain_section(TALLOC_CTX *mem_ctx,
                                     struct confdb_ctx *cdb,
                                     const char *section,
                                     const char *name,
                                     struct ldb_result **_res)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    struct ldb_result *res;
    struct ldb_dn *dn;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    dn = ldb_dn_new_fmt(tmp_ctx, cdb->ldb, "cn=%s,%s", name, section);
    if (dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_search(cdb->ldb, tmp_ctx, &res, dn,
                     LDB_SCOPE_BASE, NULL, NULL);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    if (res->count == 0) {
        ret = ENOENT;
        goto done;
    } else if (res->count > 1) {
        ret = E2BIG;
        goto done;
    }

    *_res = talloc_steal(mem_ctx, res);
    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

static int confdb_get_domain_internal(struct confdb_ctx *cdb,
                                      TALLOC_CTX *mem_ctx,
                                      const char *name,
                                      struct sss_domain_info **_domain)
{
    struct sss_domain_info *domain;
    struct ldb_result *res;
    TALLOC_CTX *tmp_ctx;
    const char *tmp;
    int ret, val;
    uint32_t entry_cache_timeout;
    char *default_domain;
    bool fqnames_default = false;
    int memcache_timeout;
    bool enum_default;

    tmp_ctx = talloc_new(mem_ctx);
    if (!tmp_ctx) return ENOMEM;

    ret = confdb_get_domain_section(tmp_ctx, cdb, CONFDB_DOMAIN_BASEDN,
                                    name, &res);
    if (ret == ENOENT) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unknown domain [%s]\n", name);
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Error %d: %s while retrieving %s\n",
              ret, sss_strerror(ret), name);
        goto done;
    }

    ret = confdb_get_int(cdb,
                         CONFDB_NSS_CONF_ENTRY,
                         CONFDB_MEMCACHE_TIMEOUT,
                         300, &memcache_timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Unable to get memory cache entry timeout.\n");
        goto done;
    }

    domain = talloc_zero(mem_ctx, struct sss_domain_info);
    if (!domain) {
        ret = ENOMEM;
        goto done;
    }

    tmp = ldb_msg_find_attr_as_string(res->msgs[0], "cn", NULL);
    if (!tmp) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Invalid configuration entry, fatal error!\n");
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
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Domain [%s] does not specify an ID provider, disabling!\n",
                  domain->name);
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
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Local ID provider does not support [%s] as an AUTH provider.\n", tmp);
            ret = EINVAL;
            goto done;
        }

        tmp = ldb_msg_find_attr_as_string(res->msgs[0],
                                          CONFDB_DOMAIN_ACCESS_PROVIDER,
                                          NULL);
        if (tmp && strcasecmp(tmp, "permit") != 0) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Local ID provider does not support [%s] as an ACCESS provider.\n", tmp);
            ret = EINVAL;
            goto done;
        }

        tmp = ldb_msg_find_attr_as_string(res->msgs[0],
                                          CONFDB_DOMAIN_CHPASS_PROVIDER,
                                          NULL);
        if (tmp && strcasecmp(tmp, "local") != 0) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Local ID provider does not support [%s] as a CHPASS provider.\n", tmp);
            ret = EINVAL;
            goto done;
        }

        /* The LOCAL provider use always Magic Private Groups */
        domain->mpg = true;
    }

    domain->timeout = ldb_msg_find_attr_as_int(res->msgs[0],
                                               CONFDB_DOMAIN_TIMEOUT, 0);

    /* Determine if this domain can be enumerated */

    /* TEMP: test if the old bitfield conf value is used and warn it has been
     * superceeded. */
    val = ldb_msg_find_attr_as_int(res->msgs[0], CONFDB_DOMAIN_ENUMERATE, 0);
    if (val > 0) { /* ok there was a number in here */
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Warning: enumeration parameter in %s still uses integers! "
                  "Enumeration is now a boolean and takes true/false values. "
                  "Interpreting as true\n", domain->name);
        domain->enumerate = true;
    } else { /* assume the new format */
        enum_default = strcasecmp(domain->provider, "files") == 0 ? true : false;

        ret = get_entry_as_bool(res->msgs[0], &domain->enumerate,
                                CONFDB_DOMAIN_ENUMERATE, enum_default);
        if(ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Invalid value for %s\n", CONFDB_DOMAIN_ENUMERATE);
            goto done;
        }
    }

    if (strcasecmp(domain->provider, "files") == 0) {
        /* The password field must be reported as 'x', else pam_unix won't
         * authenticate this entry. See man pwconv(8) for more details.
         */
        domain->pwfield = "x";
    }

    if (!domain->enumerate) {
        DEBUG(SSSDBG_TRACE_FUNC, "No enumeration for [%s]!\n", domain->name);
    }

    ret = confdb_get_string(cdb, tmp_ctx, CONFDB_MONITOR_CONF_ENTRY,
                            CONFDB_MONITOR_DEFAULT_DOMAIN, NULL,
                            &default_domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannnot get the default domain [%d]: %s\n",
               ret, strerror(ret));
        goto done;
    }

    /* Determine if user/group names will be Fully Qualified
     * in NSS interfaces */
    if (default_domain != NULL) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Default domain suffix set. Changing default for "
              "use_fully_qualified_names to True.\n");
        fqnames_default = true;
    }

    ret = get_entry_as_bool(res->msgs[0], &domain->fqnames,
                            CONFDB_DOMAIN_FQ, fqnames_default);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Invalid value for %s\n",
              CONFDB_DOMAIN_FQ);
        goto done;
    }

    if (default_domain != NULL && domain->fqnames == false) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Invalid configuration detected (default_domain_suffix is used "
              "while use_fully_qualified_names was set to false).\n");
        ret = ERR_INVALID_CONFIG;
        goto done;
    }

    ret = get_entry_as_bool(res->msgs[0], &domain->ignore_group_members,
                            CONFDB_DOMAIN_IGNORE_GROUP_MEMBERS, 0);
    if(ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Invalid value for %s\n",
               CONFDB_DOMAIN_IGNORE_GROUP_MEMBERS);
        goto done;
    }

    ret = get_entry_as_uint32(res->msgs[0], &domain->id_min,
                              CONFDB_DOMAIN_MINID,
                              confdb_get_min_id(domain));
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Invalid value for minId\n");
        ret = EINVAL;
        goto done;
    }

    ret = get_entry_as_uint32(res->msgs[0], &domain->id_max,
                              CONFDB_DOMAIN_MAXID, 0);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Invalid value for maxId\n");
        ret = EINVAL;
        goto done;
    }

    if (domain->id_max && (domain->id_max < domain->id_min)) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Invalid domain range\n");
        ret = EINVAL;
        goto done;
    }

    /* Do we allow to cache credentials */
    ret = get_entry_as_bool(res->msgs[0], &domain->cache_credentials,
                            CONFDB_DOMAIN_CACHE_CREDS, 0);
    if(ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Invalid value for %s\n", CONFDB_DOMAIN_CACHE_CREDS);
        goto done;
    }

    ret = get_entry_as_uint32(res->msgs[0],
                              &domain->cache_credentials_min_ff_length,
                              CONFDB_DOMAIN_CACHE_CREDS_MIN_FF_LENGTH,
                              CONFDB_DEFAULT_CACHE_CREDS_MIN_FF_LENGTH);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Invalid value for %s\n",
              CONFDB_DOMAIN_CACHE_CREDS_MIN_FF_LENGTH);
        goto done;
    }

    ret = get_entry_as_bool(res->msgs[0], &domain->legacy_passwords,
                            CONFDB_DOMAIN_LEGACY_PASS, 0);
    if(ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Invalid value for %s\n", CONFDB_DOMAIN_LEGACY_PASS);
        goto done;
    }

    /* Get the global entry cache timeout setting */
    ret = get_entry_as_uint32(res->msgs[0], &entry_cache_timeout,
                              CONFDB_DOMAIN_ENTRY_CACHE_TIMEOUT, 5400);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Invalid value for [%s]\n",
                CONFDB_DOMAIN_ENTRY_CACHE_TIMEOUT);
        goto done;
    }

    /* Override the user cache timeout, if specified */
    ret = get_entry_as_uint32(res->msgs[0], &domain->user_timeout,
                              CONFDB_DOMAIN_USER_CACHE_TIMEOUT,
                              entry_cache_timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Invalid value for [%s]\n",
               CONFDB_DOMAIN_USER_CACHE_TIMEOUT);
        goto done;
    }

    if (domain->user_timeout < memcache_timeout) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "%s is less than %s. User records will not be updated before "
              "memory cache entry expires.\n",
              CONFDB_DOMAIN_USER_CACHE_TIMEOUT, CONFDB_MEMCACHE_TIMEOUT);
    }

    /* Override the group cache timeout, if specified */
    ret = get_entry_as_uint32(res->msgs[0], &domain->group_timeout,
                              CONFDB_DOMAIN_GROUP_CACHE_TIMEOUT,
                              entry_cache_timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Invalid value for [%s]\n",
               CONFDB_DOMAIN_GROUP_CACHE_TIMEOUT);
        goto done;
    }

    if (domain->group_timeout < memcache_timeout) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "%s is less than %s. Group records will not be updated before "
              "memory cache entry expires.\n",
              CONFDB_DOMAIN_GROUP_CACHE_TIMEOUT, CONFDB_MEMCACHE_TIMEOUT);
    }

    /* Override the netgroup cache timeout, if specified */
    ret = get_entry_as_uint32(res->msgs[0], &domain->netgroup_timeout,
                              CONFDB_DOMAIN_NETGROUP_CACHE_TIMEOUT,
                              entry_cache_timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Invalid value for [%s]\n",
               CONFDB_DOMAIN_NETGROUP_CACHE_TIMEOUT);
        goto done;
    }

    /* Override the service cache timeout, if specified */
    ret = get_entry_as_uint32(res->msgs[0], &domain->service_timeout,
                              CONFDB_DOMAIN_SERVICE_CACHE_TIMEOUT,
                              entry_cache_timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Invalid value for [%s]\n",
               CONFDB_DOMAIN_SERVICE_CACHE_TIMEOUT);
        goto done;
    }

    /* Override the autofs cache timeout, if specified */
    ret = get_entry_as_uint32(res->msgs[0], &domain->autofsmap_timeout,
                              CONFDB_DOMAIN_AUTOFS_CACHE_TIMEOUT,
                              entry_cache_timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Invalid value for [%s]\n",
               CONFDB_DOMAIN_AUTOFS_CACHE_TIMEOUT);
        goto done;
    }

    /* Override the sudo cache timeout, if specified */
    ret = get_entry_as_uint32(res->msgs[0], &domain->sudo_timeout,
                              CONFDB_DOMAIN_SUDO_CACHE_TIMEOUT,
                              entry_cache_timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Invalid value for [%s]\n",
               CONFDB_DOMAIN_SUDO_CACHE_TIMEOUT);
        goto done;
    }

    /* Override the ssh known hosts timeout, if specified */
    ret = get_entry_as_uint32(res->msgs[0], &domain->ssh_host_timeout,
                              CONFDB_DOMAIN_SSH_HOST_CACHE_TIMEOUT,
                              entry_cache_timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Invalid value for [%s]\n",
              CONFDB_DOMAIN_SSH_HOST_CACHE_TIMEOUT);
        goto done;
    }

    /* Set refresh_expired_interval, if specified */
    ret = get_entry_as_uint32(res->msgs[0], &domain->refresh_expired_interval,
                              CONFDB_DOMAIN_REFRESH_EXPIRED_INTERVAL,
                              0);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Invalid value for [%s]\n",
               CONFDB_DOMAIN_REFRESH_EXPIRED_INTERVAL);
        goto done;
    }

    /* detect and fix misconfiguration */
    if (domain->refresh_expired_interval > entry_cache_timeout) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "refresh_expired_interval (%d) cannot be greater than "
              "entry_cache_timeout (%u)\n",
              domain->refresh_expired_interval, entry_cache_timeout);

        domain->refresh_expired_interval = 0.75 * entry_cache_timeout;

        DEBUG(SSSDBG_CONF_SETTINGS,
              "refresh_expired_interval is being set to recommended value "
              "entry_cache_timeout * 0.75 (%u).\n",
              domain->refresh_expired_interval);
    }

    /* Set the PAM warning time, if specified. If not specified, pass on
     * the "not set" value of "-1" which means "use provider default". The
     * value 0 means "always display the warning if server sends one" */
    domain->pwd_expiration_warning = -1;

    val = ldb_msg_find_attr_as_int(res->msgs[0],
                                   CONFDB_DOMAIN_PWD_EXPIRATION_WARNING,
                                   -1);
    if (val == -1) {
        ret = confdb_get_int(cdb, CONFDB_PAM_CONF_ENTRY,
                             CONFDB_PAM_PWD_EXPIRATION_WARNING,
                             -1, &val);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to read PAM expiration warning, not fatal.\n");
            val = -1;
        }
    }

    DEBUG(SSSDBG_TRACE_LIBS, "pwd_expiration_warning is %d\n", val);
    if (val >= 0) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Setting domain password expiration warning to %d days\n", val);
        /* The value is in days, transform it to seconds */
        domain->pwd_expiration_warning = val * 24 * 3600;
    }

    ret = get_entry_as_uint32(res->msgs[0], &domain->override_gid,
                              CONFDB_DOMAIN_OVERRIDE_GID, 0);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Invalid value for [%s]\n", CONFDB_DOMAIN_OVERRIDE_GID);
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
                                      CONFDB_NSS_HOMEDIR_SUBSTRING, NULL);
    if (tmp != NULL) {
        domain->homedir_substr = talloc_strdup(domain, tmp);
        if (domain->homedir_substr == NULL) {
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

    tmp = ldb_msg_find_attr_as_string(res->msgs[0],
                                      CONFDB_DOMAIN_CASE_SENSITIVE, NULL);
    if (tmp != NULL) {
        if (strcasecmp(tmp, "true") == 0) {
            domain->case_sensitive = true;
            domain->case_preserve = true;
        } else if (strcasecmp(tmp, "false") == 0) {
            domain->case_sensitive = false;
            domain->case_preserve = false;
        } else if (strcasecmp(tmp, "preserving") == 0) {
            domain->case_sensitive = false;
            domain->case_preserve = true;
        } else {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Invalid value for %s\n", CONFDB_DOMAIN_CASE_SENSITIVE);
            goto done;
        }
    } else {
        /* default */
        if (strcasecmp(domain->provider, "ad") == 0) {
            domain->case_sensitive = false;
            domain->case_preserve = false;
        } else {
            domain->case_sensitive = true;
            domain->case_preserve = true;
        }
    }

    if (domain->case_sensitive == false &&
        strcasecmp(domain->provider, "local") == 0) {
        DEBUG(SSSDBG_FATAL_FAILURE,
             "Local ID provider does not support the case insensitive flag\n");
        ret = EINVAL;
        goto done;
    }

    tmp = ldb_msg_find_attr_as_string(res->msgs[0],
                                      CONFDB_NSS_PWFIELD, NULL);
    if (tmp != NULL) {
        domain->pwfield = talloc_strdup(domain, tmp);
        if (!domain->pwfield) {
            ret = ENOMEM;
            goto done;
        }
    }

    tmp = ldb_msg_find_attr_as_string(res->msgs[0],
                                      CONFDB_SUBDOMAIN_ENUMERATE,
                                      CONFDB_DEFAULT_SUBDOMAIN_ENUMERATE);
    if (tmp != NULL) {
        ret = split_on_separator(domain, tmp, ',', true, true,
                                 &domain->sd_enumerate, NULL);
        if (ret != 0) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Cannot parse %s\n", CONFDB_SUBDOMAIN_ENUMERATE);
            goto done;
        }
    }

    tmp = ldb_msg_find_attr_as_string(res->msgs[0],
                                      CONFDB_DOMAIN_SUBDOMAIN_INHERIT,
                                      NULL);
    if (tmp != NULL) {
        ret = split_on_separator(domain, tmp, ',', true, true,
                                 &domain->sd_inherit, NULL);
        if (ret != 0) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Cannot parse %s\n", CONFDB_SUBDOMAIN_ENUMERATE);
            goto done;
        }
    }

    domain->type = DOM_TYPE_POSIX;
    tmp = ldb_msg_find_attr_as_string(res->msgs[0],
                                      CONFDB_DOMAIN_TYPE,
                                      CONFDB_DOMAIN_TYPE_POSIX);
    if (tmp != NULL) {
        if (strcasecmp(tmp, CONFDB_DOMAIN_TYPE_POSIX) == 0) {
            domain->type = DOM_TYPE_POSIX;
        } else if (strcasecmp(tmp, CONFDB_DOMAIN_TYPE_APP) == 0) {
            domain->type = DOM_TYPE_APPLICATION;
        } else {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Invalid value %s for [%s]\n", tmp, CONFDB_DOMAIN_TYPE);
            goto done;
        }
    }

    ret = get_entry_as_uint32(res->msgs[0], &domain->subdomain_refresh_interval,
                              CONFDB_DOMAIN_SUBDOMAIN_REFRESH, 14400);
    if (ret != EOK || domain->subdomain_refresh_interval == 0) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Invalid value for [%s]\n", CONFDB_DOMAIN_SUBDOMAIN_REFRESH);
        goto done;
    }

    ret = init_cached_auth_timeout(cdb, res->msgs[0],
                                   &domain->cached_auth_timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "init_cached_auth_timeout failed: %s:[%d].\n",
              sss_strerror(ret), ret);
        goto done;
    }

    domain->has_views = false;
    domain->view_name = NULL;

    domain->state = DOM_ACTIVE;

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
    struct sss_domain_info *domain = NULL;
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
        DEBUG(SSSDBG_FATAL_FAILURE, "No domains configured, fatal error!\n");
        goto done;
    }
    if (ret != EOK ) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Fatal error retrieving domains list!\n");
        goto done;
    }

    for (i = 0; domlist[i]; i++) {
        /* check if domain name is really unique */
        DLIST_FOR_EACH(domain, cdb->doms) {
            if (strcasecmp(domain->name, domlist[i]) == 0) {
                DEBUG(SSSDBG_FATAL_FAILURE,
                      SAME_DOMAINS_ERROR_MSG, domlist[i], domain->name);
                sss_log(SSS_LOG_CRIT,
                        SAME_DOMAINS_ERROR_MSG, domlist[i], domain->name);

                ret = EINVAL;
                goto done;
            }
        }

        domain = NULL;
        ret = confdb_get_domain_internal(cdb, cdb, domlist[i], &domain);
        if (ret) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Error (%d [%s]) retrieving domain [%s], skipping!\n",
                  ret, sss_strerror(ret), domlist[i]);
            continue;
        }

        DLIST_ADD_END(cdb->doms, domain, struct sss_domain_info *);
    }

    if (cdb->doms == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "No properly configured domains, fatal error!\n");
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

    for (dom = doms; dom; dom = get_next_domain(dom, 0)) {
        if (strcasecmp(dom->name, name) == 0) {
            *_domain = dom;
            return EOK;
        }
    }

    return ENOENT;
}

int confdb_list_all_domain_names(TALLOC_CTX *mem_ctx,
                                 struct confdb_ctx *cdb,
                                 char ***_names)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct ldb_dn *dn = NULL;
    struct ldb_result *res = NULL;
    static const char *attrs[] = {CONFDB_DOMAIN_ATTR, NULL};
    const char *name = NULL;
    char **names = NULL;
    int i;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    dn = ldb_dn_new(tmp_ctx, cdb->ldb, CONFDB_DOMAIN_BASEDN);
    if (dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_search(cdb->ldb, tmp_ctx, &res, dn, LDB_SCOPE_ONELEVEL,
                     attrs, NULL);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    names = talloc_zero_array(tmp_ctx, char*, res->count + 1);
    if (names == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < res->count; i++) {
        name = ldb_msg_find_attr_as_string(res->msgs[i], CONFDB_DOMAIN_ATTR,
                                           NULL);
        if (name == NULL) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "The object [%s] doesn't have a name\n",
                   ldb_dn_get_linearized(res->msgs[i]->dn));
            ret = EINVAL;
            goto done;
        }

        names[i] = talloc_strdup(names, name);
        if (names[i] == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    *_names = talloc_steal(mem_ctx, names);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

int confdb_get_sub_sections(TALLOC_CTX *mem_ctx,
                            struct confdb_ctx *cdb,
                            const char *section,
                            char ***sections,
                            int *num_sections)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char *secdn;
    struct ldb_dn *base = NULL;
    struct ldb_result *res = NULL;
    static const char *attrs[] = {"cn", NULL};
    char **names;
    int base_comp_num;
    int num;
    int i;
    int ret;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = parse_section(tmp_ctx, section, &secdn, NULL);
    if (ret != EOK) {
        goto done;
    }

    base = ldb_dn_new(tmp_ctx, cdb->ldb, secdn);
    if (base == NULL) {
        ret = ENOMEM;
        goto done;
    }

    base_comp_num = ldb_dn_get_comp_num(base);

    ret = ldb_search(cdb->ldb, tmp_ctx, &res, base, LDB_SCOPE_SUBTREE,
                     attrs, NULL);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    names = talloc_zero_array(tmp_ctx, char *, res->count + 1);
    if (names == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (num = 0, i = 0; i < res->count; i++) {
        const struct ldb_val *val;
        char *name;
        int n;
        int j;

        n = ldb_dn_get_comp_num(res->msgs[i]->dn);
        if (n == base_comp_num) continue;

        name = NULL;
        for (j = n - base_comp_num - 1; j >= 0; j--) {
            val = ldb_dn_get_component_val(res->msgs[i]->dn, j);
            if (name == NULL) {
                name = talloc_strndup(names,
                                      (const char *)val->data, val->length);
            } else {
                name = talloc_asprintf(names, "%s/%.*s", name,
                                       (int)val->length,
                                       (const char *)val->data);
            }
            if (name == NULL) {
                ret = ENOMEM;
                goto done;
            }
        }

        names[num] = name;
        if (names[num] == NULL) {
            ret = ENOMEM;
            goto done;
        }

        num++;
    }

    *sections = talloc_steal(mem_ctx, names);
    *num_sections = num;
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static int confdb_has_files_domain(struct confdb_ctx *cdb)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct ldb_dn *dn = NULL;
    struct ldb_result *res = NULL;
    static const char *attrs[] = { CONFDB_DOMAIN_ID_PROVIDER, NULL };
    const char *id_provider = NULL;
    int ret;
    unsigned int i;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    dn = ldb_dn_new(tmp_ctx, cdb->ldb, CONFDB_DOMAIN_BASEDN);
    if (dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = ldb_search(cdb->ldb, tmp_ctx, &res, dn, LDB_SCOPE_ONELEVEL,
                     attrs, NULL);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    for (i = 0; i < res->count; i++) {
        id_provider = ldb_msg_find_attr_as_string(res->msgs[i],
                                                  CONFDB_DOMAIN_ID_PROVIDER,
                                                  NULL);
        if (id_provider == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "The object [%s] doesn't have a id_provider\n",
                  ldb_dn_get_linearized(res->msgs[i]->dn));
            ret = EINVAL;
            goto done;
        }

        if (strcasecmp(id_provider, "files") == 0) {
            break;
        }
    }

    ret = i < res->count ? EOK : ENOENT;
done:
    talloc_free(tmp_ctx);
    return ret;
}

static int create_files_domain(struct confdb_ctx *cdb,
                               const char *name)
{
    TALLOC_CTX *tmp_ctx = NULL;
    errno_t ret;
    char *cdb_path = NULL;
    const char *val[2] = { NULL, NULL };

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    cdb_path = talloc_asprintf(tmp_ctx, CONFDB_DOMAIN_PATH_TMPL, name);
    if (cdb_path == NULL) {
        ret = ENOMEM;
        goto done;
    }

    val[0] = "files";
    ret = confdb_add_param(cdb, true, cdb_path, "id_provider", val);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to add id_provider [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

static int activate_files_domain(struct confdb_ctx *cdb,
                                 const char *name)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    char *monitor_domlist;
    const char *domlist[2] = { NULL, NULL };

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = confdb_get_string(cdb, tmp_ctx,
                            CONFDB_MONITOR_CONF_ENTRY,
                            CONFDB_MONITOR_ACTIVE_DOMAINS,
                            NULL,
                            &monitor_domlist);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Fatal error retrieving domains list!\n");
        goto done;
    }

    if (monitor_domlist != NULL) {
        domlist[0] = talloc_asprintf(tmp_ctx, "%s,%s", name, monitor_domlist);
        if (domlist[0] == NULL) {
            ret = ENOMEM;
            goto done;
        }
    } else {
        domlist[0] = name;
    }

    ret = confdb_add_param(cdb, true,
                           CONFDB_MONITOR_CONF_ENTRY,
                           CONFDB_MONITOR_ACTIVE_DOMAINS,
                           domlist);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot extend the domain list [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

int confdb_ensure_files_domain(struct confdb_ctx *cdb,
                               const char *implicit_files_dom_name)
{
#ifdef ADD_FILES_DOMAIN
    const bool default_enable_files = true;
#else
    const bool default_enable_files = false;
#endif
    errno_t ret;
    bool enable_files;

    ret = confdb_get_bool(cdb,
                          CONFDB_MONITOR_CONF_ENTRY,
                          CONFDB_MONITOR_ENABLE_FILES_DOM,
                          default_enable_files, &enable_files);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Cannot get the value of %s assuming %s\n",
              CONFDB_MONITOR_ENABLE_FILES_DOM,
              default_enable_files ? "true" : "false");
        return ret;
    }

    if (enable_files == false) {
        DEBUG(SSSDBG_CONF_SETTINGS, "The implicit files domain is disabled\n");
        return EOK;
    }

    ret = confdb_has_files_domain(cdb);
    if (ret == EOK) {
        DEBUG(SSSDBG_CONF_SETTINGS, "The files domain is already enabled\n");
        return EOK;
    } else if (ret != ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Error looking up the files domain\n");
        return ret;
    }

    /* ENOENT, so let's add a files domain */
    ret = create_files_domain(cdb, implicit_files_dom_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot add an implicit files domain\n");
        return ret;
    }

    return activate_files_domain(cdb, implicit_files_dom_name);
}

static int confdb_get_parent_domain(TALLOC_CTX *mem_ctx,
                                    const char *name,
                                    struct confdb_ctx *cdb,
                                    struct ldb_result *app_dom,
                                    struct ldb_result **_parent_dom)
{
    const char *inherit_from;

    inherit_from = ldb_msg_find_attr_as_string(app_dom->msgs[0],
                                               CONFDB_DOMAIN_INHERIT_FROM, NULL);
    if (inherit_from == NULL) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "%s does not inherit from any POSIX domain\n", name);
        *_parent_dom = NULL;
        return EOK;
    }

    return confdb_get_domain_section(mem_ctx, cdb,
                                     CONFDB_DOMAIN_BASEDN, inherit_from,
                                     _parent_dom);
}

static int confdb_add_app_domain(TALLOC_CTX *mem_ctx,
                                 struct confdb_ctx *cdb,
                                 const char *name)
{
    char *cdb_path = NULL;
    const char *val[2] = { NULL, NULL };
    int ret;

    cdb_path = talloc_asprintf(mem_ctx, CONFDB_DOMAIN_PATH_TMPL, name);
    if (cdb_path == NULL) {
        return ENOMEM;
    }

    val[0] = CONFDB_DOMAIN_TYPE_APP;
    ret = confdb_add_param(cdb, true, cdb_path, CONFDB_DOMAIN_TYPE, val);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to add id_provider [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    return EOK;
}

static int confdb_merge_parent_domain(const char *name,
                                      struct confdb_ctx *cdb,
                                      struct ldb_result *app_section)
{
    int ret;
    int ldb_flag;
    struct ldb_result *parent_domain = NULL;
    struct ldb_message *replace_msg = NULL;
    struct ldb_message *app_msg = NULL;
    struct ldb_dn *domain_dn;
    struct ldb_message_element *el = NULL;
    TALLOC_CTX *tmp_ctx = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    domain_dn = ldb_dn_new_fmt(tmp_ctx,
                               cdb->ldb,
                               "%s=%s,%s",
                               CONFDB_DOMAIN_ATTR,
                               name,
                               CONFDB_DOMAIN_BASEDN);
    if (domain_dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Copy the parent domain parameters */
    ret = confdb_get_parent_domain(tmp_ctx, name, cdb,
                                   app_section, &parent_domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot retrieve the parent domain [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    if (parent_domain != NULL) {
        replace_msg = ldb_msg_copy(tmp_ctx, parent_domain->msgs[0]);
        if (replace_msg == NULL) {
            ret = ENOMEM;
            goto done;
        }
        replace_msg->dn = domain_dn;

        for (unsigned i = 0; i < replace_msg->num_elements; i++) {
            replace_msg->elements[i].flags = LDB_FLAG_MOD_ADD;
        }

        el = ldb_msg_find_element(replace_msg, "cn");
        if (el != NULL) {
            /* Don't add second cn */
            ldb_msg_remove_element(replace_msg, el);
        }

        ret = ldb_modify(cdb->ldb, replace_msg);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            DEBUG(SSSDBG_OP_FAILURE,
                "Inheriting options from parent domain failed [%d]: %s\n",
                ret, sss_strerror(ret));
            goto done;
        }
    }

    /* Finally, add any app-domain specific overrides */
    app_msg = ldb_msg_new(tmp_ctx);
    if (app_msg == NULL) {
        ret = ENOMEM;
        goto done;
    }
    app_msg->dn = domain_dn;

    for (unsigned i = 0; i < app_section->msgs[0]->num_elements; i++) {
        struct ldb_message_element *app_el = &app_section->msgs[0]->elements[i];

        /* These elements will be skipped when replacing attributes in
         * a domain to avoid EEXIST errors
         */
        if (strcasecmp(app_el->name, "cn") == 0) {
            continue;
        }

        if (replace_msg != NULL) {
            el = ldb_msg_find_element(replace_msg,
                                      app_section->msgs[0]->elements[i].name);
            if (el == NULL) {
                /* Adding an element */
                ldb_flag = LDB_FLAG_MOD_ADD;
            } else {
                /* Overriding an element */
                ldb_flag = LDB_FLAG_MOD_REPLACE;
            }
        } else {
            /* If there was no domain to inherit from, just add all */
            ldb_flag = LDB_FLAG_MOD_ADD;
        }

        ret = ldb_msg_add(app_msg,
                          &app_section->msgs[0]->elements[i],
                          ldb_flag);
        if (ret != LDB_SUCCESS) {
            continue;
        }
    }

    /* We use permissive modification here because adding cn or
     * distinguishedName from the app_section to the application
     * message would throw EEXIST
     */
    ret = sss_ldb_modify_permissive(cdb->ldb, app_msg);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        DEBUG(SSSDBG_OP_FAILURE,
              "Adding app-specific options failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "Added a domain section for %s\n", name);
    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

int confdb_expand_app_domains(struct confdb_ctx *cdb)
{
    int ret;
    char **domlist;
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *app_domain = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = confdb_get_string_as_list(cdb, tmp_ctx,
                                    CONFDB_MONITOR_CONF_ENTRY,
                                    CONFDB_MONITOR_ACTIVE_DOMAINS,
                                    &domlist);
    if (ret == ENOENT) {
        DEBUG(SSSDBG_FATAL_FAILURE, "No domains configured, fatal error!\n");
        goto done;
    } else if (ret != EOK ) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Fatal error retrieving domains list!\n");
        goto done;
    }

    for (int i = 0; domlist[i]; i++) {
        ret = confdb_get_domain_section(tmp_ctx, cdb,
                                        CONFDB_APP_DOMAIN_BASEDN, domlist[i],
                                        &app_domain);
        if (ret == ENOENT) {
            DEBUG(SSSDBG_TRACE_INTERNAL,
                  "%s is not an app domain\n", domlist[i]);
            continue;
        } else if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Error %d: %s while retrieving %s\n",
                  ret, sss_strerror(ret), domlist[i]);
            goto done;
        }

        ret = confdb_add_app_domain(tmp_ctx, cdb, domlist[i]);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Cannot add the app domain section [%d]: %s\n",
                  ret, sss_strerror(ret));
            goto done;
        }

        ret = confdb_merge_parent_domain(domlist[i], cdb, app_domain);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Cannot add options into the app domain section [%d]: %s\n",
                  ret, sss_strerror(ret));
            goto done;
        }
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}
