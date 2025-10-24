/*
   SSSD

   System Database

   Copyright (C) 2008-2011 Simo Sorce <ssorce@redhat.com>
   Copyright (C) 2008-2011 Stephen Gallagher <ssorce@redhat.com>

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
#include "util/strtonum.h"
#include "util/sss_utf8.h"
#include "util/crypto/sss_crypto.h"
#include "db/sysdb_private.h"
#include "confdb/confdb.h"
#include "util/probes.h"
#include <time.h>

errno_t sysdb_dn_sanitize(TALLOC_CTX *mem_ctx, const char *input,
                          char **sanitized)
{
    struct ldb_val val;
    errno_t ret = EOK;

    val.data = (uint8_t *)talloc_strdup(mem_ctx, input);
    if (!val.data) {
        return ENOMEM;
    }

    /* We can't include the trailing NULL because it would
     * be escaped and result in an unterminated string
     */
    val.length = strlen(input);

    *sanitized = ldb_dn_escape_value(mem_ctx, val);
    if (!*sanitized) {
        ret = ENOMEM;
    }

    talloc_free(val.data);
    return ret;
}

struct ldb_dn *sysdb_custom_subtree_dn(TALLOC_CTX *mem_ctx,
                                       struct sss_domain_info *dom,
                                       const char *subtree_name)
{
    errno_t ret;
    char *clean_subtree;
    struct ldb_dn *dn = NULL;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return NULL;

    ret = sysdb_dn_sanitize(tmp_ctx, subtree_name, &clean_subtree);
    if (ret != EOK) {
        talloc_free(tmp_ctx);
        return NULL;
    }

    dn = ldb_dn_new_fmt(tmp_ctx, dom->sysdb->ldb, SYSDB_TMPL_CUSTOM_SUBTREE,
                        clean_subtree, dom->name);
    if (dn) {
        talloc_steal(mem_ctx, dn);
    }
    talloc_free(tmp_ctx);

    return dn;
}

struct ldb_dn *sysdb_custom_dn(TALLOC_CTX *mem_ctx,
                               struct sss_domain_info *dom,
                               const char *object_name,
                               const char *subtree_name)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    char *clean_name;
    char *clean_subtree;
    struct ldb_dn *dn = NULL;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return NULL;
    }

    ret = sysdb_dn_sanitize(tmp_ctx, object_name, &clean_name);
    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_dn_sanitize(tmp_ctx, subtree_name, &clean_subtree);
    if (ret != EOK) {
        goto done;
    }

    dn = ldb_dn_new_fmt(mem_ctx, dom->sysdb->ldb, SYSDB_TMPL_CUSTOM, clean_name,
                        clean_subtree, dom->name);

done:
    talloc_free(tmp_ctx);
    return dn;
}

struct ldb_dn *sysdb_user_dn(TALLOC_CTX *mem_ctx, struct sss_domain_info *dom,
                             const char *name)
{
    errno_t ret;
    char *clean_name;
    struct ldb_dn *dn;

    ret = sysdb_dn_sanitize(NULL, name, &clean_name);
    if (ret != EOK) {
        return NULL;
    }

    dn = ldb_dn_new_fmt(mem_ctx, dom->sysdb->ldb, SYSDB_TMPL_USER,
                        clean_name, dom->name);
    talloc_free(clean_name);

    return dn;
}

struct ldb_dn *sysdb_user_base_dn(TALLOC_CTX *mem_ctx,
                                  struct sss_domain_info *dom)
{
    return ldb_dn_new_fmt(mem_ctx, dom->sysdb->ldb,
                          SYSDB_TMPL_USER_BASE, dom->name);
}

struct ldb_dn *sysdb_group_dn(TALLOC_CTX *mem_ctx,
                              struct sss_domain_info *dom, const char *name)
{
    errno_t ret;
    char *clean_name;
    struct ldb_dn *dn;

    ret = sysdb_dn_sanitize(NULL, name, &clean_name);
    if (ret != EOK) {
        return NULL;
    }

    dn = ldb_dn_new_fmt(mem_ctx, dom->sysdb->ldb, SYSDB_TMPL_GROUP,
                        clean_name, dom->name);
    talloc_free(clean_name);

    return dn;
}

struct ldb_dn *sysdb_group_base_dn(TALLOC_CTX *mem_ctx,
                                   struct sss_domain_info *dom)
{
    return ldb_dn_new_fmt(mem_ctx, dom->sysdb->ldb,
                          SYSDB_TMPL_GROUP_BASE, dom->name);
}


struct ldb_dn *sysdb_netgroup_dn(TALLOC_CTX *mem_ctx,
                                 struct sss_domain_info *dom, const char *name)
{
    errno_t ret;
    char *clean_name;
    struct ldb_dn *dn;

    ret = sysdb_dn_sanitize(NULL, name, &clean_name);
    if (ret != EOK) {
        return NULL;
    }

    dn = ldb_dn_new_fmt(mem_ctx, dom->sysdb->ldb, SYSDB_TMPL_NETGROUP,
                        clean_name, dom->name);
    talloc_free(clean_name);

    return dn;
}

struct ldb_dn *sysdb_netgroup_base_dn(TALLOC_CTX *mem_ctx,
                                      struct sss_domain_info *dom)
{
    return ldb_dn_new_fmt(mem_ctx, dom->sysdb->ldb,
                          SYSDB_TMPL_NETGROUP_BASE, dom->name);
}

errno_t sysdb_get_rdn(struct sysdb_ctx *sysdb, TALLOC_CTX *mem_ctx,
                      const char *dn, char **_name, char **_val)
{
    errno_t ret;
    struct ldb_dn *ldb_dn;
    const char *attr_name = NULL;
    const struct ldb_val *val;
    TALLOC_CTX *tmp_ctx;

    /* We have to create a tmp_ctx here because
     * ldb_dn_new_fmt() fails if mem_ctx is NULL
     */
    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    ldb_dn = ldb_dn_new_fmt(tmp_ctx, sysdb->ldb, "%s", dn);
    if (ldb_dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (_name) {
        attr_name = ldb_dn_get_rdn_name(ldb_dn);
        if (attr_name == NULL) {
            ret = EINVAL;
            goto done;
        }

        *_name = talloc_strdup(mem_ctx, attr_name);
        if (!*_name) {
            ret = ENOMEM;
            goto done;
        }
    }

    val = ldb_dn_get_rdn_val(ldb_dn);
    if (val == NULL) {
        ret = EINVAL;
        if (_name) talloc_free(*_name);
        goto done;
    }

    *_val = talloc_strndup(mem_ctx, (char *) val->data, val->length);
    if (!*_val) {
        ret = ENOMEM;
        if (_name) talloc_free(*_name);
        goto done;
    }

    ret = EOK;

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

errno_t sysdb_group_dn_name(struct sysdb_ctx *sysdb, TALLOC_CTX *mem_ctx,
                            const char *dn, char **_name)
{
    return sysdb_get_rdn(sysdb, mem_ctx, dn, NULL, _name);
}

struct ldb_dn *sysdb_domain_dn(TALLOC_CTX *mem_ctx,
                               struct sss_domain_info *dom)
{
    return ldb_dn_new_fmt(mem_ctx, dom->sysdb->ldb, SYSDB_DOM_BASE, dom->name);
}

struct ldb_dn *sysdb_base_dn(struct sysdb_ctx *sysdb, TALLOC_CTX *mem_ctx)
{
    return ldb_dn_new(mem_ctx, sysdb->ldb, SYSDB_BASE);
}

struct ldb_context *sysdb_ctx_get_ldb(struct sysdb_ctx *sysdb)
{
    return sysdb->ldb;
}

struct sysdb_attrs *sysdb_new_attrs(TALLOC_CTX *mem_ctx)
{
    return talloc_zero(mem_ctx, struct sysdb_attrs);
}

int sysdb_attrs_get_el_ext(struct sysdb_attrs *attrs, const char *name,
                           bool alloc, struct ldb_message_element **el)
{
    struct ldb_message_element *e = NULL;
    int i;

    for (i = 0; i < attrs->num; i++) {
        if (strcasecmp(name, attrs->a[i].name) == 0)
            e = &(attrs->a[i]);
    }

    if (!e && alloc) {
        e = talloc_realloc(attrs, attrs->a,
                           struct ldb_message_element, attrs->num+1);
        if (!e) return ENOMEM;
        attrs->a = e;

        e[attrs->num].name = talloc_strdup(e, name);
        if (!e[attrs->num].name) return ENOMEM;

        e[attrs->num].num_values = 0;
        e[attrs->num].values = NULL;
        e[attrs->num].flags = 0;

        e = &(attrs->a[attrs->num]);
        attrs->num++;
    }

    if (!e) {
        return ENOENT;
    }

    *el = e;

    return EOK;
}

int sysdb_attrs_get_el(struct sysdb_attrs *attrs, const char *name,
                       struct ldb_message_element **el)
{
    return sysdb_attrs_get_el_ext(attrs, name, true, el);
}

int sysdb_attrs_get_string(struct sysdb_attrs *attrs, const char *name,
                           const char **string)
{
    struct ldb_message_element *el;
    int ret;

    ret = sysdb_attrs_get_el_ext(attrs, name, false, &el);
    if (ret) {
        return ret;
    }

    if (el->num_values != 1) {
        return ERANGE;
    }

    *string = (const char *)el->values[0].data;
    return EOK;
}

int sysdb_attrs_get_int32_t(struct sysdb_attrs *attrs, const char *name,
                             int32_t *value)
{
    struct ldb_message_element *el;
    int ret;
    char *endptr;
    int32_t val;

    ret = sysdb_attrs_get_el_ext(attrs, name, false, &el);
    if (ret) {
        return ret;
    }

    if (el->num_values != 1) {
        return ERANGE;
    }

    val = strtoint32((const char *) el->values[0].data, &endptr, 10);
    if (errno != 0) return errno;
    if (*endptr) return EINVAL;

    *value = val;
    return EOK;
}

int sysdb_attrs_get_uint32_t(struct sysdb_attrs *attrs, const char *name,
                             uint32_t *value)
{
    struct ldb_message_element *el;
    int ret;
    char *endptr;
    uint32_t val;

    ret = sysdb_attrs_get_el_ext(attrs, name, false, &el);
    if (ret) {
        return ret;
    }

    if (el->num_values != 1) {
        return ERANGE;
    }

    val = strtouint32((const char *) el->values[0].data, &endptr, 10);
    if (errno != 0) return errno;
    if (*endptr) return EINVAL;

    *value = val;
    return EOK;
}

int sysdb_attrs_get_uint16_t(struct sysdb_attrs *attrs, const char *name,
                             uint16_t *value)
{
    struct ldb_message_element *el;
    int ret;
    char *endptr;
    uint16_t val;

    ret = sysdb_attrs_get_el_ext(attrs, name, false, &el);
    if (ret) {
        return ret;
    }

    if (el->num_values != 1) {
        return ERANGE;
    }

    val = strtouint16((const char *) el->values[0].data, &endptr, 10);
    if (errno != 0) return errno;
    if (*endptr) return EINVAL;

    *value = val;
    return EOK;
}

errno_t sysdb_attrs_get_bool(struct sysdb_attrs *attrs, const char *name,
                             bool *value)
{
    struct ldb_message_element *el;
    int ret;

    ret = sysdb_attrs_get_el_ext(attrs, name, false, &el);
    if (ret) {
        return ret;
    }

    if (el->num_values != 1) {
        return ERANGE;
    }

    if (strcmp((const char *)el->values[0].data, "TRUE") == 0)
        *value = true;
    else
        *value = false;
    return EOK;
}

const char **sss_ldb_el_to_string_list(TALLOC_CTX *mem_ctx,
                                       struct ldb_message_element *el)
{
    unsigned int u;
    const char **a;

    a = talloc_zero_array(mem_ctx, const char *, el->num_values + 1);
    if (a == NULL) {
        return NULL;
    }

    for (u = 0; u < el->num_values; u++) {
        a[u] = talloc_strndup(a, (const char *)el->values[u].data,
                              el->values[u].length);
        if (a[u] == NULL) {
            talloc_free(a);
            return NULL;
        }
    }

    return a;
}

int sysdb_attrs_get_string_array(struct sysdb_attrs *attrs, const char *name,
                                 TALLOC_CTX *mem_ctx, const char ***string)
{
    struct ldb_message_element *el;
    int ret;
    const char **a;

    ret = sysdb_attrs_get_el_ext(attrs, name, false, &el);
    if (ret) {
        return ret;
    }

    a = sss_ldb_el_to_string_list(mem_ctx, el);
    if (a == NULL) {
        return ENOMEM;
    }

    *string = a;
    return EOK;
}


static int sysdb_attrs_add_val_int(struct sysdb_attrs *attrs,
                                   const char *name, bool check_values,
                                   const struct ldb_val *val)
{
    struct ldb_message_element *el = NULL;
    struct ldb_val *vals;
    int ret;
    size_t c;

    ret = sysdb_attrs_get_el(attrs, name, &el);
    if (ret != EOK) {
        return ret;
    }

    if (check_values) {
        for (c = 0; c < el->num_values; c++) {
            if (val->length == el->values[c].length
                    && memcmp(val->data, el->values[c].data,
                              val->length) == 0) {
                return EOK;
            }
        }
    }

    vals = talloc_realloc(attrs->a, el->values,
                          struct ldb_val, el->num_values+1);
    if (!vals) return ENOMEM;

    vals[el->num_values] = ldb_val_dup(vals, val);
    if (vals[el->num_values].data == NULL &&
        vals[el->num_values].length != 0) {
        return ENOMEM;
    }

    el->values = vals;
    el->num_values++;

    return EOK;
}

int sysdb_attrs_add_empty(struct sysdb_attrs *attrs, const char *name)
{
    struct ldb_message_element *el;

    /* Calling this will create the element if it does not exist. */
    return sysdb_attrs_get_el_ext(attrs, name, true, &el);
}

int sysdb_attrs_add_val(struct sysdb_attrs *attrs,
                        const char *name, const struct ldb_val *val)
{
    return sysdb_attrs_add_val_int(attrs, name, false, val);
}

/* Check if the same value already exists. */
int sysdb_attrs_add_val_safe(struct sysdb_attrs *attrs,
                             const char *name, const struct ldb_val *val)
{
    return sysdb_attrs_add_val_int(attrs, name, true, val);
}

int sysdb_attrs_add_string_safe(struct sysdb_attrs *attrs,
                                const char *name, const char *str)
{
    struct ldb_val v;

    v.data = (uint8_t *)discard_const(str);
    v.length = strlen(str);

    return sysdb_attrs_add_val_safe(attrs, name, &v);
}

int sysdb_attrs_add_string(struct sysdb_attrs *attrs,
                           const char *name, const char *str)
{
    struct ldb_val v;

    v.data = (uint8_t *)discard_const(str);
    v.length = strlen(str);

    return sysdb_attrs_add_val(attrs, name, &v);
}

int sysdb_attrs_add_lower_case_string(struct sysdb_attrs *attrs, bool safe,
                                      const char *name, const char *str)
{
    char *lc_str;
    int ret;

    if (attrs == NULL || str == NULL) {
        return EINVAL;
    }

    lc_str = sss_tc_utf8_str_tolower(attrs, str);
    if (lc_str == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot convert name to lowercase.\n");
        return ENOMEM;
    }

    if (safe) {
        ret = sysdb_attrs_add_string_safe(attrs, name, lc_str);
    } else {
        ret = sysdb_attrs_add_string(attrs, name, lc_str);
    }
    talloc_free(lc_str);

    return ret;
}

int sysdb_attrs_add_mem(struct sysdb_attrs *attrs, const char *name,
                        const void *mem, size_t size)
{
	struct ldb_val v;

	v.data   = discard_const(mem);
	v.length = size;
	return sysdb_attrs_add_val(attrs, name, &v);
}

int sysdb_attrs_add_base64_blob(struct sysdb_attrs *attrs, const char *name,
                                const char *base64_str)
{
    struct ldb_val v;
    int ret;

    if (base64_str == NULL) {
        return EINVAL;
    }

    v.data = sss_base64_decode(attrs, base64_str, &v.length);
    if (v.data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_base64_decode failed.\n");
        return ENOMEM;
    }

    ret = sysdb_attrs_add_val(attrs, name, &v);
    talloc_free(v.data);
    return ret;
}

int sysdb_attrs_add_bool(struct sysdb_attrs *attrs,
                         const char *name, bool value)
{
    if (value) {
        return sysdb_attrs_add_string(attrs, name, "TRUE");
    }

    return sysdb_attrs_add_string(attrs, name, "FALSE");
}

int sysdb_attrs_steal_string(struct sysdb_attrs *attrs,
                             const char *name, char *str)
{
    struct ldb_message_element *el = NULL;
    struct ldb_val *vals;
    int ret;

    ret = sysdb_attrs_get_el(attrs, name, &el);
    if (ret != EOK) {
        return ret;
    }

    vals = talloc_realloc(attrs->a, el->values,
                          struct ldb_val, el->num_values+1);
    if (!vals) return ENOMEM;
    el->values = vals;

    /* now steal and assign the string */
    talloc_steal(el->values, str);

    el->values[el->num_values].data = (uint8_t *)str;
    el->values[el->num_values].length = strlen(str);
    el->num_values++;

    return EOK;
}

int sysdb_attrs_add_long(struct sysdb_attrs *attrs,
                         const char *name, long value)
{
    struct ldb_val v;
    char *str;
    int ret;

    str = talloc_asprintf(attrs, "%ld", value);
    if (!str) return ENOMEM;

    v.data = (uint8_t *)str;
    v.length = strlen(str);

    ret = sysdb_attrs_add_val(attrs, name, &v);
    talloc_free(str);

    return ret;
}

int sysdb_attrs_add_uint32(struct sysdb_attrs *attrs,
                           const char *name, uint32_t value)
{
    unsigned long val = value;
    struct ldb_val v;
    char *str;
    int ret;

    str = talloc_asprintf(attrs, "%lu", val);
    if (!str) return ENOMEM;

    v.data = (uint8_t *)str;
    v.length = strlen(str);

    ret = sysdb_attrs_add_val(attrs, name, &v);
    talloc_free(str);

    return ret;
}

int sysdb_attrs_add_time_t(struct sysdb_attrs *attrs,
                           const char *name, time_t value)
{
    long long val = value;
    struct ldb_val v;
    char *str;
    int ret;

    str = talloc_asprintf(attrs, "%lld", val);
    if (!str) return ENOMEM;

    v.data = (uint8_t *)str;
    v.length = strlen(str);

    ret = sysdb_attrs_add_val(attrs, name, &v);
    talloc_free(str);

    return ret;
}

int sysdb_attrs_add_lc_name_alias(struct sysdb_attrs *attrs,
                                  const char *value)
{
    return sysdb_attrs_add_lower_case_string(attrs, false, SYSDB_NAME_ALIAS,
                                             value);
}

int sysdb_attrs_add_lc_name_alias_safe(struct sysdb_attrs *attrs,
                                       const char *value)
{
    return sysdb_attrs_add_lower_case_string(attrs, true, SYSDB_NAME_ALIAS,
                                             value);
}

int sysdb_attrs_copy_values(struct sysdb_attrs *src,
                            struct sysdb_attrs *dst,
                            const char *name)
{
    int ret = EOK;
    int i;
    struct ldb_message_element *src_el;

    ret = sysdb_attrs_get_el(src, name, &src_el);
    if (ret != EOK) {
        goto done;
    }

    for (i = 0; i < src_el->num_values; i++) {
        ret = sysdb_attrs_add_val(dst, name, &src_el->values[i]);
        if (ret != EOK) {
            goto done;
        }
    }

done:
    return ret;
}

errno_t sysdb_attrs_copy(struct sysdb_attrs *src, struct sysdb_attrs *dst)
{
    int ret;
    size_t c;
    size_t d;

    if (src == NULL || dst == NULL) {
        return EINVAL;
    }

    for (c = 0; c < src->num; c++) {
        for (d = 0; d < src->a[c].num_values; d++) {
            ret = sysdb_attrs_add_val_safe(dst, src->a[c].name,
                                           &src->a[c].values[d]);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_add_val failed.\n");
                return ret;
            }
        }
    }

    return EOK;
}

int sysdb_attrs_users_from_str_list(struct sysdb_attrs *attrs,
                                    const char *attr_name,
                                    const char *domain,
                                    const char *const *list)
{
    struct ldb_message_element *el = NULL;
    struct ldb_val *vals;
    int i, j, num;
    char *member;
    int ret;

    ret = sysdb_attrs_get_el(attrs, attr_name, &el);
    if (ret) {
        return ret;
    }

    for (num = 0; list[num]; num++) /* count */ ;

    vals = talloc_realloc(attrs->a, el->values,
                          struct ldb_val, el->num_values + num);
    if (!vals) {
        return ENOMEM;
    }
    el->values = vals;

    DEBUG(SSSDBG_TRACE_ALL, "Adding %d members to existing %d ones\n",
              num, el->num_values);

    for (i = 0, j = el->num_values; i < num; i++) {

        member = sysdb_user_strdn(el->values, domain, list[i]);
        if (!member) {
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "Failed to get user dn for [%s]\n", list[i]);
            continue;
        }
        el->values[j].data = (uint8_t *)member;
        el->values[j].length = strlen(member);
        j++;

        DEBUG(SSSDBG_TRACE_LIBS, "    member #%d: [%s]\n", i, member);
    }
    el->num_values = j;

    return EOK;
}

static char *build_dom_dn_str_escape(TALLOC_CTX *mem_ctx, const char *template,
                                     const char *domain, const char *name)
{
    char *ret;
    int l;

    l = strcspn(name, ",=\n+<>#;\\\"");
    if (name[l] != '\0') {
        struct ldb_val v;
        char *tmp;

        v.data = discard_const_p(uint8_t, name);
        v.length = strlen(name);

        tmp = ldb_dn_escape_value(mem_ctx, v);
        if (!tmp) {
            return NULL;
        }

        ret = talloc_asprintf(mem_ctx, template, tmp, domain);
        talloc_zfree(tmp);
        if (!ret) {
            return NULL;
        }

        return ret;
    }

    ret = talloc_asprintf(mem_ctx, template, name, domain);
    if (!ret) {
        return NULL;
    }

    return ret;
}

char *sysdb_user_strdn(TALLOC_CTX *mem_ctx,
                       const char *domain, const char *name)
{
    return build_dom_dn_str_escape(mem_ctx, SYSDB_TMPL_USER, domain, name);
}

char *sysdb_group_strdn(TALLOC_CTX *mem_ctx,
                        const char *domain, const char *name)
{
    return build_dom_dn_str_escape(mem_ctx, SYSDB_TMPL_GROUP, domain, name);
}

/* =Transactions========================================================== */

int sysdb_transaction_start(struct sysdb_ctx *sysdb)
{
    int ret;

    ret = ldb_transaction_start(sysdb->ldb);
    if (ret == LDB_SUCCESS) {
        PROBE(SYSDB_TRANSACTION_START, sysdb->transaction_nesting);
        sysdb->transaction_nesting++;
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to start ldb transaction! (%d)\n", ret);
    }
    return sysdb_error_to_errno(ret);
}

int sysdb_transaction_commit(struct sysdb_ctx *sysdb)
{
    int ret;
#ifdef HAVE_SYSTEMTAP
    int commit_nesting = sysdb->transaction_nesting-1;
#endif

    PROBE(SYSDB_TRANSACTION_COMMIT_BEFORE, commit_nesting);
    ret = ldb_transaction_commit(sysdb->ldb);
    if (ret == LDB_SUCCESS) {
        sysdb->transaction_nesting--;
        PROBE(SYSDB_TRANSACTION_COMMIT_AFTER, sysdb->transaction_nesting);
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to commit ldb transaction! (%d)\n", ret);
    }
    return sysdb_error_to_errno(ret);
}

int sysdb_transaction_cancel(struct sysdb_ctx *sysdb)
{
    int ret;

    ret = ldb_transaction_cancel(sysdb->ldb);
    if (ret == LDB_SUCCESS) {
        sysdb->transaction_nesting--;
        PROBE(SYSDB_TRANSACTION_CANCEL, sysdb->transaction_nesting);
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to cancel ldb transaction! (%d)\n", ret);
    }
    return sysdb_error_to_errno(ret);
}

int compare_ldb_dn_comp_num(const void *m1, const void *m2)
{
    struct ldb_message *msg1 = talloc_get_type(*(void **) discard_const(m1),
                                               struct ldb_message);
    struct ldb_message *msg2 = talloc_get_type(*(void **) discard_const(m2),
                                               struct ldb_message);

    return ldb_dn_get_comp_num(msg2->dn) - ldb_dn_get_comp_num(msg1->dn);
}

int sysdb_attrs_replace_name(struct sysdb_attrs *attrs, const char *oldname,
                             const char *newname)
{
    struct ldb_message_element *e = NULL;
    int i;
    const char *dummy;

    if (attrs == NULL || oldname == NULL || newname == NULL) return EINVAL;

    for (i = 0; i < attrs->num; i++) {
        if (strcasecmp(oldname, attrs->a[i].name) == 0) {
            e = &(attrs->a[i]);
        }
        if (strcasecmp(newname, attrs->a[i].name) == 0) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "New attribute name [%s] already exists.\n", newname);
            return EEXIST;
        }
    }

    if (e != NULL) {
        dummy = talloc_strdup(attrs, newname);
        if (dummy == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup failed.\n");
            return ENOMEM;
        }

        talloc_free(discard_const(e->name));
        e->name = dummy;
    }

    return EOK;
}

/* Search for all incidences of attr_name in a list of
 * sysdb_attrs and add their value to a list
 *
 * TODO: Currently only works for single-valued
 * attributes. Multi-valued attributes will return
 * only the first entry
 */
errno_t sysdb_attrs_to_list(TALLOC_CTX *mem_ctx,
                            struct sysdb_attrs **attrs,
                            int attr_count,
                            const char *attr_name,
                            char ***_list)
{
    int attr_idx;
    int i;
    char **list;
    char **tmp_list;
    int list_idx;

    *_list = NULL;

    /* Assume that every attrs entry contains the attr_name
     * This may waste a little memory if some entries don't
     * have the attribute, but it will save us the trouble
     * of continuously resizing the array.
     */
    list = talloc_array(mem_ctx, char *, attr_count+1);
    if (!list) {
        return ENOMEM;
    }

    list_idx = 0;
    /* Loop through all entries in attrs */
    for (attr_idx = 0; attr_idx < attr_count; attr_idx++) {
        /* Examine each attribute within the entry */
        for (i = 0; i < attrs[attr_idx]->num; i++) {
            if (strcasecmp(attrs[attr_idx]->a[i].name, attr_name) == 0) {
                /* Attribute name matches the requested name
                 * Copy it to the output list
                 */
                list[list_idx] = talloc_strdup(
                        list,
                        (const char *)attrs[attr_idx]->a[i].values[0].data);
                if (!list[list_idx]) {
                    talloc_free(list);
                    return ENOMEM;
                }
                list_idx++;

                /* We only support single-valued attributes
                 * Break here and go on to the next entry
                 */
                break;
            }
        }
    }

    list[list_idx] = NULL;

    /* if list_idx < attr_count, do a realloc to
     * reclaim unused memory
     */
    if (list_idx < attr_count) {
        tmp_list = talloc_realloc(mem_ctx, list, char *, list_idx+1);
        if (!tmp_list) {
            talloc_zfree(list);
            return ENOMEM;
        }
        list = tmp_list;
    }

    *_list = list;
    return EOK;
}

errno_t sysdb_get_bool(struct sysdb_ctx *sysdb,
                       struct ldb_dn *dn,
                       const char *attr_name,
                       bool *value)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;
    errno_t ret;
    int lret;
    const char *attrs[2] = {attr_name, NULL};
    struct ldb_message_element *el;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    lret = ldb_search(sysdb->ldb, tmp_ctx, &res, dn, LDB_SCOPE_BASE,
                      attrs, NULL);
    if (lret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(lret);
        goto done;
    }

    if (res->count == 0) {
        /* This entry has not been populated in LDB
         * This is a common case, as unlike LDAP,
         * LDB does not need to have all of its parent
         * objects actually exist.
         * This object in the sysdb exists mostly just
         * to contain this attribute.
         */
        *value = false;
        ret = ENOENT;
        goto done;
    } else if (res->count != 1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Got more than one reply for base search!\n");
        ret = EIO;
        goto done;
    }

    el = ldb_msg_find_element(res->msgs[0], attr_name);
    if (el == NULL || el->num_values == 0) {
        ret = ENOENT;
        goto done;
    }

    *value = ldb_msg_find_attr_as_bool(res->msgs[0], attr_name, false);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sysdb_set_bool(struct sysdb_ctx *sysdb,
                       struct ldb_dn *dn,
                       const char *cn_value,
                       const char *attr_name,
                       bool value)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct ldb_message *msg = NULL;
    struct ldb_result *res = NULL;
    errno_t ret;
    int lret;

    if (dn == NULL || attr_name == NULL) {
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    lret = ldb_search(sysdb->ldb, tmp_ctx, &res, dn, LDB_SCOPE_BASE,
                      NULL, NULL);
    if (lret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(lret);
        goto done;
    }

    msg = ldb_msg_new(tmp_ctx);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = dn;

    if (res->count == 0) {
        if (cn_value == NULL) {
            ret = ENOENT;
            goto done;
        }

        lret = ldb_msg_add_string(msg, "cn", cn_value);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }
    } else if (res->count != 1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Got more than one reply for base search!\n");
        ret = EIO;
        goto done;
    } else {
        lret = ldb_msg_add_empty(msg, attr_name, LDB_FLAG_MOD_REPLACE, NULL);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }
    }

    lret = ldb_msg_add_string(msg, attr_name, value ? "TRUE" : "FALSE");
    if (lret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(lret);
        goto done;
    }

    if (res->count) {
        lret = ldb_modify(sysdb->ldb, msg);
    } else {
        lret = ldb_add(sysdb->ldb, msg);
    }

    if (lret != LDB_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE,
              "ldb operation failed: [%s](%d)[%s]\n",
              ldb_strerror(lret), lret, ldb_errstring(sysdb->ldb));
    }
    ret = sysdb_error_to_errno(lret);

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sysdb_get_uint(struct sysdb_ctx *sysdb,
                       struct ldb_dn *dn,
                       const char *attr_name,
                       uint32_t *value)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;
    errno_t ret;
    int lret;
    const char *attrs[2] = {attr_name, NULL};
    struct ldb_message_element *el;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    lret = ldb_search(sysdb->ldb, tmp_ctx, &res, dn, LDB_SCOPE_BASE,
                      attrs, NULL);
    if (lret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(lret);
        goto done;
    }

    if (res->count == 0) {
        /* This entry has not been populated in LDB
         * This is a common case, as unlike LDAP,
         * LDB does not need to have all of its parent
         * objects actually exist.
         * This object in the sysdb exists mostly just
         * to contain this attribute.
         */
        *value = false;
        ret = ENOENT;
        goto done;
    } else if (res->count != 1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Got more than one reply for base search!\n");
        ret = EIO;
        goto done;
    }

    el = ldb_msg_find_element(res->msgs[0], attr_name);
    if (el == NULL || el->num_values == 0) {
        ret = ENOENT;
        goto done;
    }

    *value = ldb_msg_find_attr_as_uint(res->msgs[0], attr_name, false);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sysdb_set_uint(struct sysdb_ctx *sysdb,
                       struct ldb_dn *dn,
                       const char *cn_value,
                       const char *attr_name,
                       uint32_t value)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct ldb_message *msg = NULL;
    struct ldb_result *res = NULL;
    errno_t ret;
    int lret;

    if (dn == NULL || attr_name == NULL) {
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    lret = ldb_search(sysdb->ldb, tmp_ctx, &res, dn, LDB_SCOPE_BASE,
                      NULL, NULL);
    if (lret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(lret);
        goto done;
    }

    msg = ldb_msg_new(tmp_ctx);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = dn;

    if (res->count == 0) {
        if (cn_value == NULL) {
            ret = ENOENT;
            goto done;
        }

        lret = ldb_msg_add_string(msg, "cn", cn_value);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }
    } else if (res->count != 1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Got more than one reply for base search!\n");
        ret = EIO;
        goto done;
    } else {
        lret = ldb_msg_add_empty(msg, attr_name, LDB_FLAG_MOD_REPLACE, NULL);
        if (lret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(lret);
            goto done;
        }
    }

    lret = ldb_msg_add_fmt(msg, attr_name, "%u", value);
    if (lret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(lret);
        goto done;
    }

    if (res->count) {
        lret = ldb_modify(sysdb->ldb, msg);
    } else {
        lret = ldb_add(sysdb->ldb, msg);
    }

    if (lret != LDB_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE,
              "ldb operation failed: [%s](%d)[%s]\n",
              ldb_strerror(lret), lret, ldb_errstring(sysdb->ldb));
    }
    ret = sysdb_error_to_errno(lret);

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sysdb_has_enumerated(struct sss_domain_info *domain,
                             uint32_t provider,
                             bool *has_enumerated)
{
    errno_t ret;
    struct ldb_dn *dn;
    TALLOC_CTX *tmp_ctx;
    uint32_t enumerated;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        ret = ENOMEM;
        goto done;
    }

    dn = sysdb_domain_dn(tmp_ctx, domain);
    if (!dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_get_uint(domain->sysdb, dn, SYSDB_HAS_ENUMERATED,
                         &enumerated);

    if (ret != EOK) {
        return ret;
    }

    *has_enumerated = (enumerated & provider);

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sysdb_set_enumerated(struct sss_domain_info *domain,
                             uint32_t provider,
                             bool has_enumerated)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn *dn;
    uint32_t enumerated = 0;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        ret = ENOMEM;
        goto done;
    }

    dn = sysdb_domain_dn(tmp_ctx, domain);
    if (!dn) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_get_uint(domain->sysdb, dn, SYSDB_HAS_ENUMERATED,
                         &enumerated);

    if (ret != EOK && ret != ENOENT) {
        return ret;
    }

    if (has_enumerated) {
        enumerated |= provider;
    } else {
        enumerated &= ~provider;
    }

    ret = sysdb_set_uint(domain->sysdb, dn, domain->name,
                         SYSDB_HAS_ENUMERATED, enumerated);

done:
    talloc_free(tmp_ctx);
    return ret;
}

/*
 * An entity with multiple names would have multiple SYSDB_NAME attributes
 * after being translated into sysdb names using a map.
 * Given a primary name returned by sysdb_attrs_primary_name(), this function
 * returns the other SYSDB_NAME attribute values so they can be saved as
 * SYSDB_NAME_ALIAS into cache.
 *
 * If lowercase is set, all aliases are duplicated in lowercase as well.
 */
errno_t sysdb_attrs_get_aliases(TALLOC_CTX *mem_ctx,
                                struct sysdb_attrs *attrs,
                                const char *primary,
                                bool lowercase,
                                const char ***_aliases)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct ldb_message_element *sysdb_name_el;
    size_t i, j, ai;
    errno_t ret;
    const char **aliases = NULL;
    const char *name;
    char *lower;

    if (_aliases == NULL) return EINVAL;

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

    aliases = talloc_array(tmp_ctx, const char *,
                           sysdb_name_el->num_values + 1);
    if (!aliases) {
        ret = ENOMEM;
        goto done;
    }

    if (lowercase) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Domain is case-insensitive; will add lowercased aliases\n");
    }

    ai = 0;
    for (i=0; i < sysdb_name_el->num_values; i++) {
        name = (const char *)sysdb_name_el->values[i].data;

        if (lowercase) {
            /* Domain is case-insensitive. Save the lower-cased version */
            lower = sss_tc_utf8_str_tolower(tmp_ctx, name);
            if (!lower) {
                ret = ENOMEM;
                goto done;
            }

            for (j=0; j < ai; j++) {
                if (sss_utf8_case_eq((const uint8_t *) aliases[j],
                                     (const uint8_t *) lower) == ENOMATCH) {
                    break;
                }
            }

            if (ai == 0 || j < ai) {
                aliases[ai] = talloc_strdup(aliases, lower);
                if (!aliases[ai]) {
                    ret = ENOMEM;
                    goto done;
                }
                ai++;
            }
        } else {
            /* Domain is case-sensitive. Save it as-is */
            if (strcmp(primary, name) != 0) {
                aliases[ai] = talloc_strdup(aliases, name);
                if (!aliases[ai]) {
                    ret = ENOMEM;
                    goto done;
                }
                ai++;
            }
        }
    }

    aliases[ai] = NULL;

    ret = EOK;

done:
    *_aliases = talloc_steal(mem_ctx, aliases);
    talloc_free(tmp_ctx);
    return ret;
}

errno_t sysdb_msg2attrs(TALLOC_CTX *mem_ctx, size_t count,
                        struct ldb_message **msgs,
                        struct sysdb_attrs ***attrs)
{
    int i;
    struct sysdb_attrs **a;

    a = talloc_array(mem_ctx, struct sysdb_attrs *, count);
    if (a == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_array failed.\n");
        return ENOMEM;
    }

    for (i = 0; i < count; i++) {
        a[i] = talloc(a, struct sysdb_attrs);
        if (a[i] == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc failed.\n");
            talloc_free(a);
            return ENOMEM;
        }
        a[i]->num = msgs[i]->num_elements;
        a[i]->a = talloc_steal(a[i], msgs[i]->elements);
    }

    *attrs = a;

    return EOK;
}

struct ldb_message *sysdb_attrs2msg(TALLOC_CTX *mem_ctx,
                                    struct ldb_dn *entry_dn,
                                    struct sysdb_attrs *attrs,
                                    int mod_op)
{
    struct ldb_message *msg;
    errno_t ret;

    msg = ldb_msg_new(mem_ctx);
    if (msg == NULL) {
        ret = ENOMEM;
        goto done;
    }

    msg->dn = entry_dn;

    msg->elements = talloc_array(msg, struct ldb_message_element, attrs->num);
    if (msg->elements == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (int i = 0; i < attrs->num; i++) {
        msg->elements[i] = attrs->a[i];
        msg->elements[i].flags = mod_op;
    }
    msg->num_elements = attrs->num;

    ret = EOK;
done:
    if (ret != EOK) {
        talloc_zfree(msg);
    }
    return msg;
}

int sysdb_compare_usn(const char *a, const char *b)
{
    size_t len_a;
    size_t len_b;

    if (a == NULL) {
        return -1;
    }

    if (b == NULL) {
        return 1;
    }

    len_a = strlen(a);
    len_b = strlen(b);

    /* trim leading zeros */
    while (len_a > 0 && *a == '0') {
        a++;
        len_a--;
    }

    while (len_b > 0 && *b == '0') {
        b++;
        len_b--;
    }

    /* less digits means lower number */
    if (len_a < len_b) {
        return -1;
    }

    /* more digits means bigger number */
    if (len_a > len_b) {
        return 1;
    }

    /* now we can compare digits since alphabetical order is the same
     * as numeric order */
    return strcmp(a, b);
}

errno_t sysdb_get_highest_usn(TALLOC_CTX *mem_ctx,
                              struct sysdb_attrs **attrs,
                              size_t num_attrs,
                              char **_usn)
{
    const char *highest = NULL;
    const char *current = NULL;
    char *usn;
    errno_t ret;
    size_t i;

    if (num_attrs == 0 || attrs == NULL) {
        goto done;
    }

    for (i = 0; i < num_attrs; i++) {
        ret = sysdb_attrs_get_string(attrs[i], SYSDB_USN, &current);
        if (ret == ENOENT) {
            /* USN value is not present, assuming zero. */
            current = "0";
        } else if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Failed to retrieve USN value "
                  "[%d]: %s\n", ret, sss_strerror(ret));

            return ret;
        }

        if (current == NULL) {
            continue;
        }

        if (highest == NULL) {
            highest = current;
            continue;
        }

        if (sysdb_compare_usn(current, highest) > 0 ) {
            highest = current;
        }
    }

done:
    if (highest == NULL) {
        usn = talloc_strdup(mem_ctx, "0");
    } else {
        usn = talloc_strdup(mem_ctx, highest);
    }

    if (usn == NULL) {
        return ENOMEM;
    }

    *_usn = usn;
    return EOK;
}

static int sysdb_ldb_msg_string_helper(struct ldb_message *msg, int flags,
                                       const char *attr, const char *value)
{
    int ret;

    ret = ldb_msg_add_empty(msg, attr, flags, NULL);
    if (ret == LDB_SUCCESS) {
        ret = ldb_msg_add_string(msg, attr, value);
        if (ret == LDB_SUCCESS) return EOK;
    }
    return ENOMEM;
}

int sysdb_add_string(struct ldb_message *msg,
                     const char *attr, const char *value)
{
    return sysdb_ldb_msg_string_helper(msg, LDB_FLAG_MOD_ADD, attr, value);
}

int sysdb_replace_string(struct ldb_message *msg,
                         const char *attr, const char *value)
{
    return sysdb_ldb_msg_string_helper(msg, LDB_FLAG_MOD_REPLACE, attr, value);
}

int sysdb_delete_string(struct ldb_message *msg,
                        const char *attr, const char *value)
{
    return sysdb_ldb_msg_string_helper(msg, LDB_FLAG_MOD_DELETE, attr, value);
}

int sysdb_add_bool(struct ldb_message *msg,
                   const char *attr, bool value)
{
    return sysdb_ldb_msg_string_helper(msg, LDB_FLAG_MOD_ADD, attr,
                                       value ? "TRUE" : "FALSE");
}

static int sysdb_ldb_msg_ulong_helper(struct ldb_message *msg, int flags,
                                      const char *attr, unsigned long value)
{
    int ret;

    ret = ldb_msg_add_empty(msg, attr, flags, NULL);
    if (ret == LDB_SUCCESS) {
        ret = ldb_msg_add_fmt(msg, attr, "%lu", value);
        if (ret == LDB_SUCCESS) return EOK;
    }
    return ENOMEM;
}

int sysdb_add_ulong(struct ldb_message *msg,
                    const char *attr, unsigned long value)
{
    return sysdb_ldb_msg_ulong_helper(msg, LDB_FLAG_MOD_ADD, attr, value);
}

int sysdb_replace_ulong(struct ldb_message *msg,
                        const char *attr, unsigned long value)
{
    return sysdb_ldb_msg_ulong_helper(msg, LDB_FLAG_MOD_REPLACE, attr, value);
}

int sysdb_delete_ulong(struct ldb_message *msg,
                       const char *attr, unsigned long value)
{
    return sysdb_ldb_msg_ulong_helper(msg, LDB_FLAG_MOD_DELETE, attr, value);
}

bool is_ts_ldb_dn(struct ldb_dn *dn)
{
    const char *sysdb_comp_name = NULL;
    const struct ldb_val *sysdb_comp_val = NULL;

    if (dn == NULL) {
        return false;
    }

    sysdb_comp_name = ldb_dn_get_component_name(dn, 1);
    if (strcasecmp("cn", sysdb_comp_name) != 0) {
        /* The second component name is not "cn" */
        return false;
    }

    sysdb_comp_val = ldb_dn_get_component_val(dn, 1);
    if (strncasecmp("users",
                    (const char *) sysdb_comp_val->data,
                    sysdb_comp_val->length) == 0) {
        return true;
    }

    sysdb_comp_val = ldb_dn_get_component_val(dn, 1);
    if (strncasecmp("groups",
                    (const char *) sysdb_comp_val->data,
                    sysdb_comp_val->length) == 0) {
        return true;
    }

    return false;
}

bool sysdb_msg_attrs_modts_differs(struct ldb_message *old_entry,
                                   struct sysdb_attrs *new_entry)
{
    const char *old_entry_ts_attr = NULL;
    const char *new_entry_ts_attr = NULL;
    errno_t ret;

    old_entry_ts_attr = ldb_msg_find_attr_as_string(old_entry,
                                                    SYSDB_ORIG_MODSTAMP,
                                                    NULL);
    if (old_entry_ts_attr == NULL) {
        /* we didn't know the originalModifyTimestamp earlier. Regardless
         * of whether the new_entry has the timestamp, we should do
         * a comparison of the attributes
         */
        return true;
    }

    if (new_entry == NULL) {
        return false;
    }

    ret = sysdb_attrs_get_string(new_entry, SYSDB_ORIG_MODSTAMP,
                                 &new_entry_ts_attr);
    if (ret != EOK) {
        /* Nothing to compare against in the new entry either, do
         * a comparison of the attributes
         */
        return true;
    }

    if (old_entry_ts_attr != NULL
            && new_entry_ts_attr != NULL
            && strcmp(old_entry_ts_attr, new_entry_ts_attr) == 0) {
        return false;
    }

    return true;
}

static bool sysdb_ldb_msg_difference(struct ldb_dn *entry_dn,
                                     struct ldb_message *db_msg,
                                     struct ldb_message *mod_msg)
{
    struct ldb_message_element *mod_msg_el;
    struct ldb_message_element *db_msg_el;
    int el_differs;

    for (unsigned i = 0; i < mod_msg->num_elements; i++) {
        mod_msg_el = &mod_msg->elements[i];

        switch (mod_msg_el->flags) {
        case 0:
        /* Unspecified flags are internally converted to SYSDB_MOD_REP in
         * sysdb_set_group_attr, do the same here
         */
        case SYSDB_MOD_ADD:
        case SYSDB_MOD_REP:
            db_msg_el = ldb_msg_find_element(db_msg, mod_msg_el->name);
            if (db_msg_el == NULL) {
                /* The attribute to be added does not exist in the target
                 * message, this is a modification. Special-case adding
                 * empty elements which also do not exist in the target
                 * message. This is how sysdb callers ensure a particular
                 * element is not present in the database.
                 */
                if (mod_msg_el->num_values > 0) {
                    /* We can ignore additions of timestamp attributes */
                    DEBUG(SSSDBG_TRACE_INTERNAL,
                          "Added attr [%s] to entry [%s]\n",
                          mod_msg_el->name, ldb_dn_get_linearized(entry_dn));
                    return true;
                }
                break;
            }

            el_differs = ldb_msg_element_compare(db_msg_el, mod_msg_el);
            if (el_differs) {
                /* We are replacing or extending element, there is a difference.
                 * If some values already exist and ldb_add is not permissive,
                 * ldb will throw an error, but that's not our job to check..
                 */
                if (is_ts_cache_attr(mod_msg_el->name) == false) {
                    /* We can ignore changes to timestamp attributes */
                    DEBUG(SSSDBG_TRACE_INTERNAL,
                          "Replaced/extended attr [%s] of entry [%s]\n",
                          mod_msg_el->name, ldb_dn_get_linearized(entry_dn));
                    return true;
                }
            }
            break;
        case SYSDB_MOD_DEL:
            db_msg_el = ldb_msg_find_element(db_msg, mod_msg_el->name);
            if (db_msg_el != NULL) {
                /* We are deleting a valid element, there is a difference */
                DEBUG(SSSDBG_TRACE_INTERNAL,
                      "Deleted attr [%s] of entry [%s].\n",
                      mod_msg_el->name, ldb_dn_get_linearized(entry_dn));
                return true;
            }
            break;
        }
    }

    return false;
}

bool sysdb_entry_attrs_diff(struct sysdb_ctx *sysdb,
                            struct ldb_dn *entry_dn,
                            struct sysdb_attrs *attrs,
                            int mod_op)
{
    struct ldb_message *new_entry_msg = NULL;
    TALLOC_CTX *tmp_ctx;
    bool differs = true;
    int lret;
    struct ldb_result *res;
    const char *attrnames[attrs->num+1];

    if (sysdb->ldb_ts == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Entry [%s] differs, reason: there is no ts_cache yet.\n",
              ldb_dn_get_linearized(entry_dn));
        return true;
    }

    if (is_ts_ldb_dn(entry_dn) == false) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Entry [%s] differs, reason: ts_cache doesn't trace this type of entry.\n",
              ldb_dn_get_linearized(entry_dn));
        return true;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        goto done;
    }

    new_entry_msg = sysdb_attrs2msg(tmp_ctx, entry_dn,
                                    attrs, mod_op);
    if (new_entry_msg == NULL) {
        goto done;
    }

    for (int i = 0; i < attrs->num; i++) {
        attrnames[i] = attrs->a[i].name;
    }
    attrnames[attrs->num] = NULL;

    lret = ldb_search(sysdb->ldb, tmp_ctx, &res, entry_dn, LDB_SCOPE_BASE,
                      attrnames, NULL);
    if (lret != LDB_SUCCESS) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Cannot search sysdb: %d\n",
              sysdb_error_to_errno(lret));
        goto done;
    }

    if (res->count == 0) {
        return true;
    } else if (res->count != 1) {
        goto done;
    }

    differs = sysdb_ldb_msg_difference(entry_dn, res->msgs[0], new_entry_msg);
done:
    talloc_free(tmp_ctx);
    return differs;
}

void ldb_debug_messages(void *context, enum ldb_debug_level level,
                        const char *fmt, va_list ap)
{
    int loglevel = SSSDBG_UNRESOLVED;

    switch(level) {
    case LDB_DEBUG_FATAL:
        loglevel = SSSDBG_FATAL_FAILURE;
        break;
    case LDB_DEBUG_ERROR:
        loglevel = SSSDBG_CRIT_FAILURE;
        break;
    case LDB_DEBUG_WARNING:
        loglevel = SSSDBG_TRACE_FUNC;
        break;
    case LDB_DEBUG_TRACE:
        loglevel = SSSDBG_TRACE_LDB;
        break;
    }

    sss_vdebug_fn(__FILE__, __LINE__, "ldb", loglevel, APPEND_LINE_FEED,
                  fmt, ap);
}

struct sss_domain_info *find_domain_by_msg(struct sss_domain_info *dom,
                                           struct ldb_message *msg)
{
    const char *name;
    struct sss_domain_info *obj_dom = NULL;

    name = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
    if (name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Object does not have a name attribute.\n");
        return dom;
    }

    obj_dom = find_domain_by_object_name(get_domains_head(dom), name);
    if (obj_dom == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "No domain found for [%s].\n", name);
        return dom;
    }

    return obj_dom;
}
