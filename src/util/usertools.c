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
#include <errno.h>
#include <ctype.h>
#include <talloc.h>
#include <grp.h>

#include "db/sysdb.h"
#include "confdb/confdb.h"
#include "util/strtonum.h"
#include "util/util.h"
#include "util/safe-format-string.h"
#include "responder/common/responder.h"

#define NAME_DOMAIN_PATTERN_OPTIONS (SSS_REGEXP_DUPNAMES | SSS_REGEXP_EXTENDED)

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
    } provider_default_re[] = {{"ipa", SSS_IPA_AD_DEFAULT_RE},
                               {"ad", SSS_IPA_AD_DEFAULT_RE},
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
}

static errno_t sss_fqnames_init(struct sss_names_ctx *nctx, const char *fq_fmt)
{
    char *fq;

    nctx->fq_fmt = talloc_strdup(nctx, fq_fmt);
    if (nctx->fq_fmt == NULL) {
        return ENOMEM;
    }

    DEBUG(SSSDBG_CONF_SETTINGS, "Using fq format [%s].\n", nctx->fq_fmt);

    /* Fail if the name specifier is missing, or if the format is
     * invalid */
    fq = sss_tc_fqname2 (nctx, nctx, "unused.example.com", "unused", "the-test-user");
    if (fq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "The fq format is invalid [%s]\n", nctx->fq_fmt);
        return EINVAL;
    } else if (strstr (fq, "the-test-user") == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Username pattern not found in [%s]\n", nctx->fq_fmt);
        return ENOENT;
    }

    talloc_free (fq);
    return EOK;
}

int sss_names_init_from_args(TALLOC_CTX *mem_ctx, const char *re_pattern,
                             const char *fq_fmt, struct sss_names_ctx **out)
{
    struct sss_names_ctx *ctx;
    int errval;
    int ret;

    ctx = talloc_zero(mem_ctx, struct sss_names_ctx);
    if (!ctx) return ENOMEM;

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

    errval = sss_regexp_new(ctx,
                            ctx->re_pattern,
                            NAME_DOMAIN_PATTERN_OPTIONS,
                            &(ctx->re));
    if (errval != 0) {
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
    char *conf_path = NULL;
    char *re_pattern = NULL;
    char *fq_fmt = NULL;
    int ret;

    tmpctx = talloc_new(NULL);
    if (tmpctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (domain != NULL) {
        conf_path = talloc_asprintf(tmpctx, CONFDB_DOMAIN_PATH_TMPL, domain);
        if (conf_path == NULL) {
            ret = ENOMEM;
            goto done;
        }

        ret = confdb_get_string(cdb, tmpctx, conf_path,
                                CONFDB_NAME_REGEX, NULL, &re_pattern);
        if (ret != EOK) goto done;
    }

    /* If not found in the domain, look in globals */
    if (re_pattern == NULL) {
        ret = confdb_get_string(cdb, tmpctx, CONFDB_MONITOR_CONF_ENTRY,
                                CONFDB_NAME_REGEX, NULL, &re_pattern);
        if (ret != EOK) goto done;
    }

    if (re_pattern == NULL && conf_path != NULL) {
        ret = get_id_provider_default_re(tmpctx, cdb, conf_path, &re_pattern);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to get provider default regular " \
                                      "expression for domain [%s].\n", domain);
            goto done;
        }
    }

    if (!re_pattern) {
        re_pattern = talloc_strdup(tmpctx, SSS_DEFAULT_RE);
        if (!re_pattern) {
            ret = ENOMEM;
            goto done;
        }
    }

    if (conf_path != NULL) {
        ret = confdb_get_string(cdb, tmpctx, conf_path,
                                CONFDB_FULL_NAME_FORMAT, NULL, &fq_fmt);
        if (ret != EOK) goto done;
    }

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

int sss_ad_default_names_ctx(TALLOC_CTX *mem_ctx,
                             struct sss_names_ctx **_out)
{
    return sss_names_init_from_args(mem_ctx, SSS_IPA_AD_DEFAULT_RE,
                                    CONFDB_DEFAULT_FULL_NAME_FORMAT,
                                    _out);
}

int sss_parse_name(TALLOC_CTX *memctx,
                   struct sss_names_ctx *snctx,
                   const char *orig, char **_domain, char **_name)
{
    sss_regexp_t *re = snctx->re;
    const char *result;
    int ret;

    ret = sss_regexp_match(re, orig, 0, SSS_REGEXP_NOTEMPTY);
    if (ret == SSS_REGEXP_ERROR_NOMATCH) {
        return ERR_REGEX_NOMATCH;
    } else if (ret < 0) {
        DEBUG(SSSDBG_MINOR_FAILURE, "PCRE Matching error, %d\n", ret);
        return EINVAL;
    }

    if (ret == 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Too many matches, the pattern is invalid.\n");
    }

    if (_name != NULL) {
        result = NULL;
        ret = sss_regexp_get_named_substring(re, "name", &result);
        if (ret < 0  || !result) {
            DEBUG(SSSDBG_OP_FAILURE, "Name not found!\n");
            return EINVAL;
        }
        *_name = talloc_strdup(memctx, result);
        if (!*_name) return ENOMEM;
    }

    if (_domain != NULL) {
        result = NULL;
        ret = sss_regexp_get_named_substring(re, "domain", &result);
        if (ret < 0  || !result) {
            DEBUG(SSSDBG_FUNC_DATA, "Domain not provided!\n");
            *_domain = NULL;
        } else {
            /* ignore "" string */
            if (*result) {
                *_domain = talloc_strdup(memctx, result);
                if (!*_domain) return ENOMEM;
            } else {
                *_domain = NULL;
            }
        }
    }

    return EOK;
}

static struct sss_domain_info * match_any_domain_or_subdomain_name(
                                                struct sss_domain_info *dom,
                                                const char *dmatch)
{
    if (strcasecmp(dom->name, dmatch) == 0 ||
        (dom->flat_name != NULL && strcasecmp(dom->flat_name, dmatch) == 0)) {
        return dom;
    }

    return find_domain_by_name_ex(dom, dmatch, true, SSS_GND_SUBDOMAINS);
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
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    rname = NULL;
    rdomain = NULL;

    for (dom = domains; dom != NULL; dom = get_next_domain(dom, 0)) {
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
                } else if (candidate_domain == NULL) {
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

                for (dom = domains; dom != NULL; dom = get_next_domain(dom, 0)) {
                    match = match_any_domain_or_subdomain_name(dom, rdomain);
                    if (match != NULL) {
                        break;
                    }
                }
                if (match == NULL) {
                    DEBUG(SSSDBG_FUNC_DATA, "default domain [%s] is currently " \
                                            "not known\n", rdomain);
                    *domain = talloc_steal(memctx, rdomain);
                    ret = EAGAIN;
                    goto done;
                }
                DEBUG(SSSDBG_FUNC_DATA, "using default domain [%s]\n", rdomain);
            }

            rname = candidate_name;
        } else if (candidate_domain) {
            /* This branch is taken when the input matches the configured
             * regular expression, but the domain is now known. Normally, this
             * is the case with a FQDN of a user from subdomain that was not
             * yet discovered
             */
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
calc_flat_name(struct sss_domain_info *domain)
{
    const char *s;

    s = domain->flat_name;
    if (s == NULL) {
        DEBUG(SSSDBG_FUNC_DATA, "Domain has no flat name set,"
              "using domain name instead\n");
        s = domain->name;
    }

    return s;
}

char *
sss_tc_fqname(TALLOC_CTX *mem_ctx, struct sss_names_ctx *nctx,
              struct sss_domain_info *domain, const char *name)
{
    if (domain == NULL || nctx == NULL) return NULL;

    return sss_tc_fqname2 (mem_ctx, nctx, domain->name,
                           calc_flat_name (domain), name);
}

static void
safe_talloc_callback (void *data,
                      const char *piece,
                      size_t len)
{
    char **output = data;
    if (*output != NULL)
        *output = talloc_strndup_append(*output, piece, len);
}

char *
sss_tc_fqname2(TALLOC_CTX *mem_ctx, struct sss_names_ctx *nctx,
               const char *domain_name, const char *flat_dom_name,
               const char *name)
{
    const char *args[] = { name, domain_name, flat_dom_name, NULL };
    char *output;

    if (nctx == NULL) return NULL;

    output = talloc_strdup(mem_ctx, "");
    if (safe_format_string_cb(safe_talloc_callback, &output, nctx->fq_fmt, args, 3) < 0)
        output = NULL;
    else if (output == NULL)
        errno = ENOMEM;
    return output;
}

int
sss_fqname(char *str, size_t size, struct sss_names_ctx *nctx,
           struct sss_domain_info *domain, const char *name)
{
    if (domain == NULL || nctx == NULL) return -EINVAL;

    return safe_format_string(str, size, nctx->fq_fmt,
                              name, domain->name, calc_flat_name (domain), NULL);
}

errno_t sss_user_by_name_or_uid(const char *input, uid_t *_uid, gid_t *_gid)
{
    uid_t uid;
    errno_t ret;
    char *endptr;
    struct passwd *pwd;

    /* Try if it's an ID first */
    uid = strtouint32(input, &endptr, 10);
    if ((errno != 0) || (*endptr != '\0') || (input == endptr)) {
        ret = errno;
        if (ret == ERANGE) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "UID [%s] is out of range.\n", input);
            return ret;
        }

        /* Nope, maybe a username? */
        pwd = getpwnam(input);
    } else {
        pwd = getpwuid(uid);
    }

    if (pwd == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "[%s] is neither a valid UID nor a user name which could be "
              "resolved by getpwnam().\n", input);
        return EINVAL;
    }

    if (_uid) {
        *_uid = pwd->pw_uid;
    }

    if (_gid) {
        *_gid = pwd->pw_gid;
    }
    return EOK;
}

/* Accepts fqname in the format shortname@domname only. */
errno_t sss_parse_internal_fqname(TALLOC_CTX *mem_ctx,
                                  const char *fqname,
                                  char **_shortname,
                                  char **_dom_name)
{
    errno_t ret;
    char *separator;
    char *shortname = NULL;
    char *dom_name = NULL;
    size_t shortname_len;
    TALLOC_CTX *tmp_ctx;

    if (fqname == NULL) {
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    separator = strrchr(fqname, '@');
    if (separator == NULL || *(separator + 1) == '\0' || separator == fqname) {
        /*The name does not contain name or domain component. */
        ret = ERR_WRONG_NAME_FORMAT;
        goto done;
    }

    if (_dom_name != NULL) {
        dom_name = talloc_strdup(tmp_ctx, separator + 1);
        if (dom_name == NULL) {
            ret = ENOMEM;
            goto done;
        }

        *_dom_name = talloc_steal(mem_ctx, dom_name);
    }

    if (_shortname != NULL) {
        shortname_len = strlen(fqname) - strlen(separator);
        shortname = talloc_strndup(tmp_ctx, fqname, shortname_len);
        if (shortname == NULL) {
            ret = ENOMEM;
            goto done;
        }

        *_shortname = talloc_steal(mem_ctx, shortname);
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

/* Creates internal fqname in format shortname@domname.
 * The domain portion is lowercased. */
char *sss_create_internal_fqname(TALLOC_CTX *mem_ctx,
                                 const char *shortname,
                                 const char *dom_name)
{
    char *lc_dom_name;
    char *fqname = NULL;

    if (shortname == NULL || dom_name == NULL) {
        /* Avoid allocating null@null */
        return NULL;
    }

    lc_dom_name = sss_tc_utf8_str_tolower(mem_ctx, dom_name);
    if (lc_dom_name == NULL) {
        goto done;
    }

    fqname = talloc_asprintf(mem_ctx, "%s@%s", shortname, lc_dom_name);
    talloc_free(lc_dom_name);
done:
    return fqname;
}

/* Creates a list of internal fqnames in format shortname@domname.
 * The domain portion is lowercased. */
char **sss_create_internal_fqname_list(TALLOC_CTX *mem_ctx,
                                       const char * const *shortname_list,
                                       const char *dom_name)
{
    char **fqname_list = NULL;
    size_t c;

    if (shortname_list == NULL || dom_name == NULL) {
        /* Avoid allocating null@null */
        return NULL;
    }

    for (c = 0; shortname_list[c] != NULL; c++);
    fqname_list = talloc_zero_array(mem_ctx, char *, c+1);
    if (fqname_list == NULL) {
        talloc_free(fqname_list);
        return NULL;
    }

    for (size_t i = 0; shortname_list[i] != NULL; i++) {
        fqname_list[i] = sss_create_internal_fqname(fqname_list,
                                                    shortname_list[i],
                                                    dom_name);
        if (fqname_list[i] == NULL) {
            talloc_free(fqname_list);
            return NULL;
        }
    }

    return fqname_list;
}

char *sss_output_name(TALLOC_CTX *mem_ctx,
                      const char *name,
                      bool case_sensitive,
                      const char replace_space)
{
    TALLOC_CTX *tmp_ctx = NULL;
    errno_t ret;
    char *shortname;
    char *outname = NULL;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return NULL;

    ret = sss_parse_internal_fqname(tmp_ctx, name, &shortname, NULL);
    if (ret == ERR_WRONG_NAME_FORMAT) {
        /* There is no domain name. */
        shortname = talloc_strdup(tmp_ctx, name);
        if (shortname == NULL) {
            goto done;
        }
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sss_parse_internal_fqname failed\n");
        goto done;
    }

    outname = sss_get_cased_name(tmp_ctx, shortname, case_sensitive);
    if (outname == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
                "sss_get_cased_name failed, skipping\n");
        goto done;
    }

    outname = sss_replace_space(tmp_ctx, outname, replace_space);
    if (outname == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sss_replace_space failed\n");
        goto done;
    }

    outname = talloc_steal(mem_ctx, outname);
done:
    talloc_free(tmp_ctx);
    return outname;
}

const char *
sss_get_name_from_msg(struct sss_domain_info *domain,
                      struct ldb_message *msg)
{
    const char *name;

    /* If domain has a view associated we return overridden name
     * if possible. */
    if (DOM_HAS_VIEWS(domain)) {
        name = ldb_msg_find_attr_as_string(msg, OVERRIDE_PREFIX SYSDB_NAME,
                                           NULL);
        if (name != NULL) {
            return name;
        }
    }

    /* Otherwise we try to return name override from
     * Default Truest View for trusted users. */
    name = ldb_msg_find_attr_as_string(msg, SYSDB_DEFAULT_OVERRIDE_NAME, NULL);
    if (name != NULL) {
        return name;
    }

    /* If no override is found we return the original name. */
    return ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
}

int sss_output_fqname(TALLOC_CTX *mem_ctx,
                      struct sss_domain_info *domain,
                      const char *name,
                      char override_space,
                      char **_output_name)
{
    TALLOC_CTX *tmp_ctx = NULL;
    errno_t ret;
    char *output_name;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    output_name = sss_output_name(tmp_ctx, name, domain->case_preserve,
                                  override_space);
    if (output_name == NULL) {
        ret = EIO;
        goto done;
    }

    if (sss_domain_info_get_output_fqnames(domain) || domain->fqnames) {
        output_name = sss_tc_fqname(tmp_ctx, domain->names,
                                    domain, output_name);
        if (output_name == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "sss_tc_fqname failed\n");
            ret = EIO;
            goto done;
        }
    }

    *_output_name = talloc_steal(mem_ctx, output_name);
    ret = EOK;
done:
    talloc_zfree(tmp_ctx);
    return ret;
}

void sss_sssd_user_uid_and_gid(uid_t *_uid, gid_t *_gid)
{
    uid_t sssd_uid;
    gid_t sssd_gid;
    errno_t ret;

    ret = sss_user_by_name_or_uid(SSSD_USER, &sssd_uid, &sssd_gid);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "failed to get sssd user (" SSSD_USER ") uid/gid, using root\n");
        sssd_uid = 0;
        sssd_gid = 0;
    }

    if (_uid != NULL) {
        *_uid = sssd_uid;
    }

    if (_gid != NULL) {
        *_gid = sssd_gid;
    }
}

void sss_set_sssd_user_eid(void)
{
    uid_t uid;
    gid_t gid;


    if (geteuid() == 0) {
        sss_sssd_user_uid_and_gid(&uid, &gid);

        if (setegid(gid) != EOK) {
            DEBUG(SSSDBG_IMPORTANT_INFO,
                  "Failed to set egid to %"SPRIgid": %s\n",
                  gid, sss_strerror(errno));
        }
        if (seteuid(uid) != EOK) {
            DEBUG(SSSDBG_IMPORTANT_INFO,
                  "Failed to set euid to %"SPRIuid": %s\n",
                  uid, sss_strerror(errno));
        }
    }
}

void sss_restore_sssd_user_eid(void)
{
    if (getuid() == 0) {
        if (seteuid(getuid()) != EOK) {
            DEBUG(SSSDBG_IMPORTANT_INFO,
                  "Failed to restore euid: %s\n",
                  sss_strerror(errno));
        }
        if (setegid(getgid()) != EOK) {
            DEBUG(SSSDBG_IMPORTANT_INFO,
                  "Failed to restore egid: %s\n",
                  sss_strerror(errno));
        }
    }
}
