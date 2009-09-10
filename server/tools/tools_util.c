/*
   SSSD

   tools_utils.c

   Copyright (C) Jakub Hrozek <jhrozek@redhat.com>        2009

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

#include <talloc.h>
#include <tevent.h>
#include <popt.h>
#include <errno.h>

#include "util/util.h"
#include "confdb/confdb.h"
#include "db/sysdb.h"
#include "tools/tools_util.h"

static struct sss_domain_info *get_local_domain(struct tools_ctx *ctx)
{
    struct sss_domain_info *dom = NULL;

    /* No ID specified, find LOCAL */
    for (dom = ctx->domains; dom; dom = dom->next) {
        if (strcasecmp(dom->provider, "local") == 0) {
            break;
        }
    }

    return dom;
}

int setup_db(struct tools_ctx **tools_ctx)
{
    struct sss_domain_info *dom;
    TALLOC_CTX *tmp_ctx;
    char *confdb_path;
    struct tools_ctx *ctx;
    int ret;

    ctx = talloc_zero(NULL, struct tools_ctx);
    if (ctx == NULL) {
        DEBUG(1, ("Could not allocate memory for tools context\n"));
        return ENOMEM;
    }

    /* Create the event context */
    ctx->ev = tevent_context_init(ctx);
    if (ctx->ev == NULL) {
        DEBUG(1, ("Could not create event context\n"));
        talloc_free(ctx);
        return EIO;
    }

    tmp_ctx = talloc_new(ctx);
    if (!tmp_ctx)
        return ENOMEM;

    confdb_path = talloc_asprintf(tmp_ctx, "%s/%s", DB_PATH, CONFDB_FILE);
    if (confdb_path == NULL) {
        talloc_free(ctx);
        return ENOMEM;
    }

    /* Connect to the conf db */
    ret = confdb_init(ctx, &ctx->confdb, confdb_path);
    if (ret != EOK) {
        DEBUG(1, ("Could not initialize connection to the confdb\n"));
        talloc_free(ctx);
        return ret;
    }

    ret = confdb_get_domains(ctx->confdb, &ctx->domains);
    if (ret != EOK) {
        DEBUG(1, ("Could not get domains\n"));
        talloc_free(ctx);
        return ret;
    }

    ret = confdb_get_domain(ctx->confdb, "local", &dom);
    if (ret != EOK) {
        DEBUG(1, ("Could not get 'local' domain\n"));
        talloc_free(ctx);
        return ret;
    }

    /* open 'local' sysdb at default path */
    ret = sysdb_domain_init(ctx, ctx->ev, dom, DB_PATH, &ctx->sysdb);
    if (ret != EOK) {
        DEBUG(1, ("Could not initialize connection to the sysdb\n"));
        talloc_free(ctx);
        return ret;
    }

    talloc_free(tmp_ctx);
    *tools_ctx = ctx;
    return EOK;
}

/*
 * Print poptUsage as well as our error message
 */
void usage(poptContext pc, const char *error)
{
    poptPrintUsage(pc, stderr, 0);
    if (error) fprintf(stderr, "%s", error);
}

/* FIXME: avoid using strtok !! */
int parse_groups(TALLOC_CTX *mem_ctx, const char *optstr, char ***_out)
{
    char **out;
    char *orig, *n, *o;
    char delim = ',';
    unsigned int tokens = 1;
    int i;

    orig = talloc_strdup(mem_ctx, optstr);
    if (!orig) return ENOMEM;

    n = orig;
    tokens = 1;
    while ((n = strchr(n, delim))) {
        n++;
        tokens++;
    }

    out = talloc_array(mem_ctx, char *, tokens+1);
    if (!out) {
        talloc_free(orig);
        return ENOMEM;
    }

    n = o = orig;
    for (i = 0; i < tokens; i++) {
        o = n;
        n = strchr(n, delim);
        if (!n) {
            break;
        }
        *n = '\0';
        n++;
        out[i] = talloc_strdup(out, o);
    }
    out[tokens-1] = talloc_strdup(out, o);
    out[tokens] = NULL;

    talloc_free(orig);
    *_out = out;
    return EOK;
}

static int parse_name_domain(struct ops_ctx *octx,
                             const char *fullname)
{
    int ret;
    char *domain = NULL;
    struct sss_domain_info *dom;

    ret = sss_parse_name(octx, octx->ctx->snctx, fullname, &domain, &octx->name);
    if (ret != EOK) {
        DEBUG(0, ("Cannot parse full name\n"));
        return ret;
    }
    DEBUG(5, ("Parsed username: %s\n", octx->name));

    if (domain) {
        DEBUG(5, ("Parsed domain: %s\n", domain));

        /* Got string domain name, find corresponding sss_domain_info */
        for (dom = octx->ctx->domains; dom; dom = dom->next) {
            if (strcasecmp(dom->name, domain) == 0) {
                DEBUG(6, ("Found sss_domain_info for given domain name\n"));
                octx->domain = dom;
                break;
            }
        }
        if (octx->domain == NULL) {
            DEBUG(0, ("Invalid domain %s specified in FQDN\n", domain));
            return EINVAL;
        }
    }

    return EOK;
}

int get_domain(struct ops_ctx *octx,
               const char *fullname)
{
    int ret;

    ret = parse_name_domain(octx, fullname);
    if (ret != EOK) {
        return ret;
    }
    if (octx->domain == NULL) {
        octx->domain = get_local_domain(octx->ctx);
        if (octx->domain == NULL) {
            return EINVAL;
        }
    }

    return EOK;
}

int id_in_range(uint32_t id,
                struct sss_domain_info *dom)
{
    if (id &&
        ((id < dom->id_min) ||
         (dom->id_max && id > dom->id_max))) {
        return ERANGE;
    }

    return EOK;
}

int set_locale(void)
{
    char *c;

    c = setlocale(LC_ALL, "");
    if (c == NULL) {
        return EIO;
    }

    errno = 0;
    c = bindtextdomain(PACKAGE, LOCALEDIR);
    if (c == NULL) {
        return errno;
    }

    errno = 0;
    c = textdomain(PACKAGE);
    if (c == NULL) {
        return errno;
    }

    return EOK;
}

int init_sss_tools(struct tools_ctx **_ctx)
{
    int ret;
    struct tools_ctx *ctx;

    /* Connect to the database */
    ret = setup_db(&ctx);
    if (ret != EOK) {
        DEBUG(1, ("Could not set up database\n"));
        ret = EXIT_FAILURE;
        goto fini;
    }

    ret = sss_names_init(ctx, ctx->confdb, &ctx->snctx);
    if (ret != EOK) {
        DEBUG(1, ("Could not set up parsing\n"));
        goto fini;
    }

    *_ctx = ctx;
    ret = EOK;
fini:
    return ret;
}

