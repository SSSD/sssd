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

static int sss_names_ctx_destructor(struct sss_names_ctx *snctx)
{
    if (snctx->re) {
        pcre_free(snctx->re);
        snctx->re = NULL;
    }
    return 0;
}

int sss_names_init(TALLOC_CTX *mem_ctx, struct confdb_ctx *cdb, struct sss_names_ctx **out)
{
    struct sss_names_ctx *ctx;
    const char *errstr;
    int errval;
    int errpos;
    int ret;

    ctx = talloc_zero(mem_ctx, struct sss_names_ctx);
    if (!ctx) return ENOMEM;
    talloc_set_destructor(ctx, sss_names_ctx_destructor);

    ret = confdb_get_string(cdb, ctx, CONFDB_MONITOR_CONF_ENTRY,
                            CONFDB_MONITOR_NAME_REGEX, NULL, &ctx->re_pattern);
    if (ret != EOK) goto done;

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

    ret = confdb_get_string(cdb, ctx, CONFDB_MONITOR_CONF_ENTRY,
                            CONFDB_MONITOR_FULL_NAME_FORMAT, NULL, &ctx->fq_fmt);
    if (ret != EOK) goto done;

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
    if (ret < 0) {
        DEBUG(2, ("PCRE Matching error, %d\n", ret));
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
