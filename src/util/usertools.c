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
        DEBUG(SSSDBG_OP_FAILURE, ("Failed to read ID provider " \
                                  "from conf db.\n"));
        goto done;
    }

    if (id_provider == NULL) {
        *re_pattern = NULL;
    } else {
        for (c = 0; provider_default_re[c].name != NULL; c++) {
            if (strcmp(id_provider, provider_default_re[c].name) == 0) {
                *re_pattern = talloc_strdup(mem_ctx, provider_default_re[c].re);
                if (*re_pattern == NULL) {
                    DEBUG(SSSDBG_OP_FAILURE, ("talloc_strdup failed.\n"));
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
}

int sss_names_init(TALLOC_CTX *mem_ctx, struct confdb_ctx *cdb,
                   const char *domain, struct sss_names_ctx **out)
{
    struct sss_names_ctx *ctx;
    TALLOC_CTX *tmpctx = NULL;
    const char *errstr;
    char *conf_path;
    int errval;
    int errpos;
    int ret;

    ctx = talloc_zero(mem_ctx, struct sss_names_ctx);
    if (!ctx) return ENOMEM;
    talloc_set_destructor(ctx, sss_names_ctx_destructor);

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

    ret = confdb_get_string(cdb, ctx, conf_path,
                            CONFDB_NAME_REGEX, NULL, &ctx->re_pattern);
    if (ret != EOK) goto done;

    /* If not found in the domain, look in globals */
    if (ctx->re_pattern == NULL) {
        ret = confdb_get_string(cdb, ctx, CONFDB_MONITOR_CONF_ENTRY,
                                CONFDB_NAME_REGEX, NULL, &ctx->re_pattern);
        if (ret != EOK) goto done;
    }

    if (ctx->re_pattern == NULL) {
        ret = get_id_provider_default_re(ctx, cdb, conf_path, &ctx->re_pattern);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, ("Failed to get provider default regular " \
                                      "expression for domain [%s].\n", domain));
            goto done;
        }
    }

    if (!ctx->re_pattern) {
        ctx->re_pattern = talloc_strdup(ctx,
                                "(?P<name>[^@]+)@?(?P<domain>[^@]*$)");
        if (!ctx->re_pattern) {
            ret = ENOMEM;
            goto done;
        }
#ifdef HAVE_LIBPCRE_LESSER_THAN_7
    } else {
        DEBUG(2, ("This binary was build with a version of libpcre that does "
                  "not support non-unique named subpatterns.\n"));
        DEBUG(2, ("Please make sure that your pattern [%s] only contains "
                  "subpatterns with a unique name and uses "
                  "the Python syntax (?P<name>).\n", ctx->re_pattern));
#endif
    }

    DEBUG(SSSDBG_CONF_SETTINGS, ("Using re [%s].\n", ctx->re_pattern));

    ret = confdb_get_string(cdb, ctx, conf_path,
                            CONFDB_FULL_NAME_FORMAT, NULL, &ctx->fq_fmt);
    if (ret != EOK) goto done;

    /* If not found in the domain, look in globals */
    if (ctx->fq_fmt == NULL) {
        ret = confdb_get_string(cdb, ctx, CONFDB_MONITOR_CONF_ENTRY,
                                CONFDB_FULL_NAME_FORMAT, NULL, &ctx->fq_fmt);
        if (ret != EOK) goto done;
    }

    if (!ctx->fq_fmt) {
        ctx->fq_fmt = talloc_strdup(ctx, "%1$s@%2$s");
        if (!ctx->fq_fmt) {
            ret = ENOMEM;
            goto done;
        }
    }

    ctx->re = pcre_compile2(ctx->re_pattern,
                            NAME_DOMAIN_PATTERN_OPTIONS,
                            &errval, &errstr, &errpos, NULL);
    if (!ctx->re) {
        DEBUG(1, ("Invalid Regular Expression pattern at position %d."
                  " (Error: %d [%s])\n", errpos, errval, errstr));
        ret = EFAULT;
        goto done;
    }

    *out = ctx;
    ret = EOK;

done:
    talloc_free(tmpctx);
    if (ret != EOK) {
        talloc_free(ctx);
    }
    return ret;
}

int sss_parse_name(TALLOC_CTX *memctx,
                   struct sss_names_ctx *snctx,
                   const char *orig, char **domain, char **name)
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
        DEBUG(SSSDBG_MINOR_FAILURE, ("PCRE Matching error, %d\n", ret));
        return EINVAL;
    }

    if (ret == 0) {
        DEBUG(1, ("Too many matches, the pattern is invalid.\n"));
    }

    strnum = ret;

    result = NULL;
    ret = pcre_get_named_substring(re, orig, ovec, strnum, "name", &result);
    if (ret < 0  || !result) {
        DEBUG(2, ("Name not found!\n"));
        return EINVAL;
    }
    *name = talloc_strdup(memctx, result);
    pcre_free_substring(result);
    if (!*name) return ENOMEM;


    result = NULL;
    ret = pcre_get_named_substring(re, orig, ovec, strnum, "domain", &result);
    if (ret < 0  || !result) {
        DEBUG(4, ("Domain not provided!\n"));
        *domain = NULL;
    } else {
        /* ignore "" string */
        if (*result) {
            *domain = talloc_strdup(memctx, result);
            pcre_free_substring(result);
            if (!*domain) return ENOMEM;
        } else {
            pcre_free_substring(result);
            *domain = NULL;
        }
    }

    return EOK;
}

static struct sss_domain_info * match_any_domain_or_subdomain_name (
        struct sss_domain_info *dom, const char *dmatch)
{
    uint32_t i;

    if (strcasecmp (dom->name, dmatch) == 0)
        return dom;

    for (i = 0; i < dom->subdomain_count; i++) {
        if (strcasecmp(dom->subdomains[i]->name, dmatch) == 0 ||
            (dom->subdomains[i]->flat_name != NULL &&
             strcasecmp(dom->subdomains[i]->flat_name, dmatch) == 0)) {
            return dom->subdomains[i];
        }
    }

    return NULL;
}

int sss_parse_name_for_domains(TALLOC_CTX *memctx,
                               struct sss_domain_info *domains,
                               const char *orig, char **domain, char **name)
{
    struct sss_domain_info *dom, *match;
    char *rdomain, *rname;
    char *dmatch, *nmatch;
    char *candidate_name = NULL;
    char *candidate_domain = NULL;
    bool name_mismatch = false;
    TALLOC_CTX *tmp_ctx;
    int code;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL)
        return ENOMEM;

    rname = NULL;
    rdomain = NULL;

    for (dom = domains; dom != NULL; dom = dom->next) {
        code = sss_parse_name(tmp_ctx, dom->names, orig, &dmatch, &nmatch);
        if (code == EOK) {
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
                    DEBUG(SSSDBG_FUNC_DATA, ("name '%s' matched expression for "
                                             "domain '%s', user is %s\n",
                                             orig, dom->name, nmatch));
                    rdomain = dmatch;
                    rname = nmatch;
                    break;
                } else if (candidate_name == NULL) {
                    candidate_domain = dmatch;
                }
            }

        /* EINVAL is returned when name doesn't match */
        } else if (code != EINVAL) {
            talloc_free(tmp_ctx);
            return code;
        }
    }

    if (rdomain == NULL && rname == NULL) {
        if (candidate_name && !name_mismatch) {
            DEBUG(SSSDBG_FUNC_DATA,
                  ("name '%s' matched without domain, user is %s\n", orig, nmatch));
            rdomain = NULL;
            rname = candidate_name;
        } else if (candidate_domain) {
            *domain = talloc_steal(memctx, candidate_domain);
            return EAGAIN;
        }
    }

    if (rdomain == NULL && rname == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC,
              ("name '%s' did not match any domain's expression\n", orig));
        return EINVAL;
    }

    if (domain != NULL) {
        *domain = talloc_steal(memctx, rdomain);
    }

    if (name != NULL) {
        *name = talloc_steal(memctx, rname);
    }

    talloc_free(tmp_ctx);

    return EOK;
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
