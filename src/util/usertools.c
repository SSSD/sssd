/*
   SSSD

   User tools

   Copyright (C) Stephen Gallagher <sgallagh@redhat.com>	2009

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

#include <pwd.h>
#include <pcre.h>
#include <errno.h>
#include <talloc.h>

#include "confdb/confdb.h"
#include "util/util.h"

#ifdef HAVE_LIBPCRE_LESSER_THAN_7
#define NAME_DOMAIN_PATTERN_OPTIONS (PCRE_EXTENDED)
#else
#define NAME_DOMAIN_PATTERN_OPTIONS (PCRE_DUPNAMES | PCRE_EXTENDED)
#endif

char *get_username_from_uid(TALLOC_CTX *mem_ctx, uid_t uid)
{
    char *username;
    struct passwd *pwd;

    pwd = getpwuid(uid);
    if (!pwd) return NULL;

    username = talloc_strdup(mem_ctx, pwd->pw_name);
    return username;
}

/* Function returns given realm name as new uppercase string */
char *get_uppercase_realm(TALLOC_CTX *memctx, const char *name)
{
    char *realm;
    char *c;

    realm = talloc_strdup(memctx, name);
    if (!realm) {
        return NULL;
    }

    c = realm;
    while(*c != '\0') {
        *c = toupper(*c);
        c++;
    }

    return realm;
}


static int sss_names_ctx_destructor(struct sss_names_ctx *snctx)
{
    if (snctx->re) {
        pcre_free(snctx->re);
        snctx->re = NULL;
    }
    return 0;
}

#define IPA_AD_DEFAULT_RE "(((?P<domain>[^\\\\]+)\\\\(?P<name>.+$))|" \
                         "((?P<name>[^@]+)@(?P<domain>.+$))|" \
                         "(^(?P<name>[^@\\\\]+)$))"

static errno_t get_id_provider_default_re(TALLOC_CTX *mem_ctx,
                                          struct confdb_ctx *cdb,
                                          const char *conf_path,
                                          char **re_pattern)
{
#ifdef HAVE_LIBPCRE_LESSER_THAN_7
    DEBUG(SSSDBG_MINOR_FAILURE,
          "The libpcre version on this system is too old. Only "
           "the user@DOMAIN name fully qualified name format will "
           "be supported\n");
    *re_pattern = NULL;
    return EOK;
#else
    int ret;
    size_t c;
    char *id_provider = NULL;

    struct provider_default_re {
        const char *name;
        const char *re;
    } provider_default_re[] = {{"ipa", IPA_AD_DEFAULT_RE},
                               {"ad", IPA_AD_DEFAULT_RE},
                               {NULL, NULL}};

    ret = confdb_get_string(cdb, mem_ctx, conf_path, CONFDB_DOMAIN_ID_PROVIDER,
                            NULL, &id_provider);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to read ID provider " \
                                  "from conf db.\n");
        goto done;
    }

    if (id_provider == NULL) {
        *re_pattern = NULL;
    } else {
        for (c = 0; provider_default_re[c].name != NULL; c++) {
            if (strcmp(id_provider, provider_default_re[c].name) == 0) {
                *re_pattern = talloc_strdup(mem_ctx, provider_default_re[c].re);
                if (*re_pattern == NULL) {
                    DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                    ret = ENOMEM;
                    goto done;
                }
                break;
            }
        }
    }

    ret = EOK;

done:
    talloc_free(id_provider);
    return ret;
#endif
}

static errno_t sss_fqnames_init(struct sss_names_ctx *nctx, const char *fq_fmt)
{
    struct pattern_desc {
        const char *pattern;
        const char *desc;
        int flag;
    };

    struct pattern_desc fqname_patterns[] = {
        { "%1$s", "user name", FQ_FMT_NAME },
        { "%2$s", "domain name", FQ_FMT_DOMAIN },
        { "%3$s", "domain flat name", FQ_FMT_FLAT_NAME },
        { NULL, NULL, 0 }
    };

    nctx->fq_fmt = talloc_strdup(nctx, fq_fmt);
    if (nctx->fq_fmt == NULL) {
        return ENOMEM;
    }

    DEBUG(SSSDBG_CONF_SETTINGS, "Using fq format [%s].\n", nctx->fq_fmt);

    /* Fail if the name specifier is missing and warn if the domain
     * specifier is missing
     */
    if (strstr(fq_fmt, fqname_patterns[0].pattern) == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Username pattern not found in [%s]\n", nctx->fq_fmt);
        return ENOENT;
    }
    nctx->fq_flags = FQ_FMT_NAME;

    for (int i = 1; fqname_patterns[i].pattern; i++) {
        char *s;
        s = strstr(fq_fmt, fqname_patterns[i].pattern);
        if (s == NULL) {
            /* Append the format specifier */
            nctx->fq_fmt = talloc_strdup_append(nctx->fq_fmt,
                                                fqname_patterns[i].pattern);
            if (nctx->fq_fmt == NULL) {
                return ENOMEM;
            }
            continue;
        }

        DEBUG(SSSDBG_CONF_SETTINGS,
              "Found the pattern for %s\n", fqname_patterns[i].desc);
        nctx->fq_flags |= fqname_patterns[i].flag;
    }

    return EOK;
}

int sss_names_init_from_args(TALLOC_CTX *mem_ctx, const char *re_pattern,
                             const char *fq_fmt, struct sss_names_ctx **out)
{
    struct sss_names_ctx *ctx;
    const char *errstr;
    int errval;
    int errpos;
    int ret;

    ctx = talloc_zero(mem_ctx, struct sss_names_ctx);
    if (!ctx) return ENOMEM;
    talloc_set_destructor(ctx, sss_names_ctx_destructor);

    ctx->re_pattern = talloc_strdup(ctx, re_pattern);
    if (ctx->re_pattern == NULL) {
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_CONF_SETTINGS, "Using re [%s].\n", ctx->re_pattern);

    ret = sss_fqnames_init(ctx, fq_fmt);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not check the FQ names format"
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    ctx->re = pcre_compile2(ctx->re_pattern,
                            NAME_DOMAIN_PATTERN_OPTIONS,
                            &errval, &errstr, &errpos, NULL);
    if (!ctx->re) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Invalid Regular Expression pattern at position %d."
                  " (Error: %d [%s])\n", errpos, errval, errstr);
        ret = EFAULT;
        goto done;
    }

    *out = ctx;
    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(ctx);
    }
    return ret;
}

int sss_names_init(TALLOC_CTX *mem_ctx, struct confdb_ctx *cdb,
                   const char *domain, struct sss_names_ctx **out)
{
    TALLOC_CTX *tmpctx = NULL;
    char *conf_path;
    char *re_pattern;
    char *fq_fmt;
    int ret;

    tmpctx = talloc_new(NULL);
    if (tmpctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    conf_path = talloc_asprintf(tmpctx, CONFDB_DOMAIN_PATH_TMPL, domain);
    if (conf_path == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = confdb_get_string(cdb, tmpctx, conf_path,
                            CONFDB_NAME_REGEX, NULL, &re_pattern);
    if (ret != EOK) goto done;

    /* If not found in the domain, look in globals */
    if (re_pattern == NULL) {
        ret = confdb_get_string(cdb, tmpctx, CONFDB_MONITOR_CONF_ENTRY,
                                CONFDB_NAME_REGEX, NULL, &re_pattern);
        if (ret != EOK) goto done;
    }

    if (re_pattern == NULL) {
        ret = get_id_provider_default_re(tmpctx, cdb, conf_path, &re_pattern);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to get provider default regular " \
                                      "expression for domain [%s].\n", domain);
            goto done;
        }
    }

    if (!re_pattern) {
        re_pattern = talloc_strdup(tmpctx,
                                   "(?P<name>[^@]+)@?(?P<domain>[^@]*$)");
        if (!re_pattern) {
            ret = ENOMEM;
            goto done;
        }
#ifdef HAVE_LIBPCRE_LESSER_THAN_7
    } else {
        DEBUG(SSSDBG_OP_FAILURE,
              "This binary was build with a version of libpcre that does "
                  "not support non-unique named subpatterns.\n");
        DEBUG(SSSDBG_OP_FAILURE,
              "Please make sure that your pattern [%s] only contains "
                  "subpatterns with a unique name and uses "
                  "the Python syntax (?P<name>).\n", re_pattern);
#endif
    }

    ret = confdb_get_string(cdb, tmpctx, conf_path,
                            CONFDB_FULL_NAME_FORMAT, NULL, &fq_fmt);
    if (ret != EOK) goto done;

    /* If not found in the domain, look in globals */
    if (fq_fmt == NULL) {
        ret = confdb_get_string(cdb, tmpctx, CONFDB_MONITOR_CONF_ENTRY,
                                CONFDB_FULL_NAME_FORMAT, NULL, &fq_fmt);
        if (ret != EOK) goto done;
    }

    if (!fq_fmt) {
        fq_fmt = talloc_strdup(tmpctx, CONFDB_DEFAULT_FULL_NAME_FORMAT);
        if (!fq_fmt) {
            ret = ENOMEM;
            goto done;
        }
    }

    ret = sss_names_init_from_args(mem_ctx, re_pattern, fq_fmt, out);

done:
    talloc_free(tmpctx);
    return ret;
}

int sss_parse_name(TALLOC_CTX *memctx,
                   struct sss_names_ctx *snctx,
                   const char *orig, char **_domain, char **_name)
{
    pcre *re = snctx->re;
    const char *result;
    int ovec[30];
    int origlen;
    int ret, strnum;

    origlen = strlen(orig);

    ret = pcre_exec(re, NULL, orig, origlen, 0, PCRE_NOTEMPTY, ovec, 30);
    if (ret == PCRE_ERROR_NOMATCH) {
        return EINVAL;
    } else if (ret < 0) {
        DEBUG(SSSDBG_MINOR_FAILURE, "PCRE Matching error, %d\n", ret);
        return EINVAL;
    }

    if (ret == 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Too many matches, the pattern is invalid.\n");
    }

    strnum = ret;

    if (_name != NULL) {
        result = NULL;
        ret = pcre_get_named_substring(re, orig, ovec, strnum, "name", &result);
        if (ret < 0  || !result) {
            DEBUG(SSSDBG_OP_FAILURE, "Name not found!\n");
            return EINVAL;
        }
        *_name = talloc_strdup(memctx, result);
        pcre_free_substring(result);
        if (!*_name) return ENOMEM;
    }

    if (_domain != NULL) {
        result = NULL;
        ret = pcre_get_named_substring(re, orig, ovec, strnum, "domain",
                                       &result);
        if (ret < 0  || !result) {
            DEBUG(SSSDBG_CONF_SETTINGS, "Domain not provided!\n");
            *_domain = NULL;
        } else {
            /* ignore "" string */
            if (*result) {
                *_domain = talloc_strdup(memctx, result);
                pcre_free_substring(result);
                if (!*_domain) return ENOMEM;
            } else {
                pcre_free_substring(result);
                *_domain = NULL;
            }
        }
    }

    return EOK;
}

int sss_parse_name_const(TALLOC_CTX *memctx,
                         struct sss_names_ctx *snctx, const char *orig,
                         const char **_domain, const char **_name)
{
    char *domain;
    char *name;
    int ret;

    ret = sss_parse_name(memctx, snctx, orig,
                         (_domain == NULL) ? NULL : &domain,
                         (_name == NULL) ? NULL : &name);
    if (ret == EOK) {
        if (_domain != NULL) {
            *_domain = domain;
        }

        if (_name != NULL) {
            *_name = name;
        }
    }

    return ret;
}

static struct sss_domain_info * match_any_domain_or_subdomain_name(
                                                struct sss_domain_info *dom,
                                                const char *dmatch)
{
    if (strcasecmp(dom->name, dmatch) == 0 ||
        (dom->flat_name != NULL && strcasecmp(dom->flat_name, dmatch) == 0)) {
        return dom;
    }

    return find_subdomain_by_name(dom, dmatch, true);
}

int sss_parse_name_for_domains(TALLOC_CTX *memctx,
                               struct sss_domain_info *domains,
                               const char *default_domain,
                               const char *orig, char **domain, char **name)
{
    struct sss_domain_info *dom, *match = NULL;
    char *rdomain, *rname;
    char *dmatch, *nmatch;
    char *candidate_name = NULL;
    char *candidate_domain = NULL;
    bool name_mismatch = false;
    TALLOC_CTX *tmp_ctx;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL)
        return ENOMEM;

    rname = NULL;
    rdomain = NULL;

    for (dom = domains; dom != NULL; dom = get_next_domain(dom, false)) {
        ret = sss_parse_name(tmp_ctx, dom->names, orig, &dmatch, &nmatch);
        if (ret == EOK) {
            /*
             * If the name matched without the domain part, make note of it.
             * All the other domain expressions must agree on the domain-less
             * name.
             */
            if (dmatch == NULL) {
                if (candidate_name == NULL) {
                    candidate_name = nmatch;
                } else if (strcasecmp(candidate_name, nmatch) != 0) {
                    name_mismatch = true;
                }

            /*
             * If a domain was returned, then it must match the name of the
             * domain that this expression was found on, or one of the
             * subdomains.
             */
            } else {
                match = match_any_domain_or_subdomain_name (dom, dmatch);
                if (match != NULL) {
                    DEBUG(SSSDBG_FUNC_DATA, "name '%s' matched expression for "
                                             "domain '%s', user is %s\n",
                                             orig, match->name, nmatch);
                    rdomain = talloc_strdup(tmp_ctx, match->name);
                    if (rdomain == NULL) {
                        DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                        ret = ENOMEM;
                        goto done;
                    }
                    rname = nmatch;
                    break;
                } else if (candidate_name == NULL) {
                    candidate_domain = dmatch;
                }
            }

        /* EINVAL is returned when name doesn't match */
        } else if (ret != EINVAL) {
            goto done;
        }
    }

    if (rdomain == NULL && rname == NULL) {
        if (candidate_name && !name_mismatch) {
            DEBUG(SSSDBG_FUNC_DATA, "name '%s' matched without domain, " \
                                     "user is %s\n", orig, nmatch);
            rdomain = NULL;
            if (default_domain != NULL) {
                rdomain = talloc_strdup(tmp_ctx, default_domain);
                if (rdomain == NULL) {
                    DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                    ret = ENOMEM;
                    goto done;
                }

                for (dom = domains; dom != NULL; dom = get_next_domain(dom, false)) {
                    match = match_any_domain_or_subdomain_name(dom, rdomain);
                    if (match != NULL) {
                        break;
                    }
                }
                if (match == NULL) {
                    DEBUG(SSSDBG_FUNC_DATA, "default domain [%s] is currently " \
                                             "not know, trying to look it up.\n",
                                             rdomain);
                    *domain = talloc_steal(memctx, rdomain);
                    ret = EAGAIN;
                    goto done;
                }
            }

            DEBUG(SSSDBG_FUNC_DATA, "using default domain [%s]\n", rdomain);

            rname = candidate_name;
        } else if (candidate_domain) {
            *domain = talloc_steal(memctx, candidate_domain);
            ret = EAGAIN;
            goto done;
        }
    }

    if (rdomain == NULL && rname == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "name '%s' did not match any domain's expression\n", orig);
        ret = EINVAL;
        goto done;
    }

    if (domain != NULL) {
        *domain = talloc_steal(memctx, rdomain);
    }

    if (name != NULL) {
        *name = talloc_steal(memctx, rname);
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);

    return ret;
}

char *
sss_get_cased_name(TALLOC_CTX *mem_ctx,
                   const char *orig_name,
                   bool case_sensitive)
{
    return case_sensitive ? talloc_strdup(mem_ctx, orig_name) :
                            sss_tc_utf8_str_tolower(mem_ctx, orig_name);
}

errno_t
sss_get_cased_name_list(TALLOC_CTX *mem_ctx, const char * const *orig,
                        bool case_sensitive, const char ***_cased)
{
    const char **out;
    size_t num, i;

    if (orig == NULL) {
        *_cased = NULL;
        return EOK;
    }

    for (num=0; orig[num]; num++);  /* count the num of strings */

    if (num == 0) {
        *_cased = NULL;
        return EOK;
    }

    out = talloc_array(mem_ctx, const char *, num + 1);
    if (out == NULL) {
        return ENOMEM;
    }

    for (i = 0; i < num; i++) {
        out[i] = sss_get_cased_name(out, orig[i], case_sensitive);
        if (out[i] == NULL) {
            talloc_free(out);
            return ENOMEM;
        }
    }

    out[num] = NULL;
    *_cased = out;
    return EOK;
}

static inline const char *
safe_fq_str(struct sss_names_ctx *nctx, uint8_t part, const char *str)
{
    return nctx->fq_flags & part ? str : "";
}

static inline const char *
safe_flat_name(struct sss_names_ctx *nctx, struct sss_domain_info *domain)
{
    const char *s;

    s = safe_fq_str(nctx, FQ_FMT_FLAT_NAME, domain->flat_name);
    if (s == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Flat name requested but domain has no"
              "flat name set, falling back to domain name\n");
        s = domain->name;
    }

    return s;
}

static inline size_t
fq_part_len(struct sss_names_ctx *nctx, struct sss_domain_info *dom,
            uint8_t part, const char *str)
{
    const char *s = str;

    if (part == FQ_FMT_FLAT_NAME) {
        s = safe_flat_name(nctx, dom);
    }
    return nctx->fq_flags & part ? strlen(s) : 0;
}

char *
sss_tc_fqname(TALLOC_CTX *mem_ctx, struct sss_names_ctx *nctx,
              struct sss_domain_info *domain, const char *name)
{
    if (domain == NULL || nctx == NULL) return NULL;

    return talloc_asprintf(mem_ctx, nctx->fq_fmt,
                           safe_fq_str(nctx, FQ_FMT_NAME, name),
                           safe_fq_str(nctx, FQ_FMT_DOMAIN, domain->name),
                           safe_flat_name(nctx, domain));
}

int
sss_fqname(char *str, size_t size, struct sss_names_ctx *nctx,
           struct sss_domain_info *domain, const char *name)
{
    if (domain == NULL || nctx == NULL) return -EINVAL;

    return snprintf(str, size, nctx->fq_fmt,
                    safe_fq_str(nctx, FQ_FMT_NAME, name),
                    safe_fq_str(nctx, FQ_FMT_DOMAIN, domain->name),
                    safe_flat_name(nctx, domain));
}

size_t
sss_fqdom_len(struct sss_names_ctx *nctx,
              struct sss_domain_info *domain)
{
    size_t len = fq_part_len(nctx, domain, FQ_FMT_DOMAIN, domain->name);
    len += fq_part_len(nctx, domain, FQ_FMT_FLAT_NAME, domain->flat_name);
    return len;
}

char *
sss_get_domain_name(TALLOC_CTX *mem_ctx,
                    const char *orig_name,
                    struct sss_domain_info *dom)
{
    char *user_name;

    if (IS_SUBDOMAIN(dom) && dom->fqnames) {
        /* we always use the fully qualified name for subdomain users */
        user_name = sss_tc_fqname(mem_ctx, dom->names, dom, orig_name);
    } else {
        user_name = talloc_strdup(mem_ctx, orig_name);
    }

    return user_name;
}
