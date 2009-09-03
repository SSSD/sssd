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

/*
 * Returns:
 * 0 = yes, local domain proxying to files
 * -1 = no, other type of domain
 * > 0 = error code
 */
static int is_domain_local_legacy(struct tools_ctx *ctx, struct sss_domain_info *dom)
{
    char *libname = NULL;
    char *conf_path = NULL;
    int ret = -1;

    /* Is there a better way to find out? Having LEGACYLOCAL as reserved would help */
    conf_path = talloc_asprintf(ctx, "config/domains/%s", dom->name);
    if (conf_path == NULL ) {
        return ENOMEM;
    }

    ret = confdb_get_string(ctx->confdb, ctx, conf_path,
                            "libName", NULL, &libname);
    if (ret != EOK) {
        talloc_free(conf_path);
        return ret;
    }
    if (libname == NULL) {
        talloc_free(conf_path);
        return -1;
    }

    if (strcasecmp(libname, "files") == 0) {
        talloc_free(conf_path);
        talloc_free(libname);
        return EOK;
    }

    talloc_free(conf_path);
    talloc_free(libname);
    return -1;
}

enum id_domain get_domain_type(struct tools_ctx *ctx,
                               struct sss_domain_info *dom)
{
    if (dom == NULL) {
        return ID_OUTSIDE;
    }

    if (strcasecmp(dom->provider, "local") == 0) {
        return ID_IN_LOCAL;
    } else if (strcasecmp(dom->provider, "files") == 0 ||
               is_domain_local_legacy(ctx, dom) == 0) {
        return ID_IN_LEGACY_LOCAL;
    }

    return ID_IN_OTHER;
}

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

int get_domain_by_id(struct tools_ctx *ctx,
                     uint32_t id,
                     struct sss_domain_info **_dom)
{
    struct sss_domain_info *dom = NULL;
    int ret = EOK;

    if (id) {
        for (dom = ctx->domains; dom; dom = dom->next) {
            if (id >= dom->id_min &&
                (dom->id_max == 0 || id <= dom->id_max)) {
                break;
            }
        }
    }

    if (dom == NULL && id == 0) {
        dom = get_local_domain(ctx);
        if (dom == NULL) {
            DEBUG(1, ("Cannot find local domain info\n"));
            ret = ENOENT;
        }
    }

    *_dom = dom;
    return ret;
}

int setup_db(struct tools_ctx **tools_ctx)
{
    TALLOC_CTX *tmp_ctx;
    char *confdb_path;
    struct tools_ctx *ctx;
    int ret;

    ctx = talloc_zero(NULL, struct tools_ctx);
    if (ctx == NULL) {
        DEBUG(1, ("Could not allocate memory for tools context"));
        return ENOMEM;
    }

    /* Create the event context */
    ctx->ev = tevent_context_init(ctx);
    if (ctx->ev == NULL) {
        DEBUG(1, ("Could not create event context"));
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
    ret = confdb_init(ctx, ctx->ev, &ctx->confdb, confdb_path);
    if (ret != EOK) {
        DEBUG(1, ("Could not initialize connection to the confdb"));
        talloc_free(ctx);
        return ret;
    }

    ret = confdb_get_domains(ctx->confdb, &ctx->domains);
    if (ret != EOK) {
        DEBUG(1, ("Could not get domains"));
        talloc_free(ctx);
        return ret;
    }

    /* open sysdb at default path */
    ret = sysdb_init(ctx, ctx->ev, ctx->confdb, NULL, false, &ctx->db_list);
    if (ret != EOK) {
        DEBUG(1, ("Could not initialize connection to the sysdb"));
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

int parse_name_domain(struct ops_ctx *octx,
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

