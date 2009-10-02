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
#include "tools/sss_sync_ops.h"

static int setup_db(struct tools_ctx *ctx)
{
    char *confdb_path;
    int ret;

    /* Create the event context */
    ctx->ev = tevent_context_init(ctx);
    if (ctx->ev == NULL) {
        DEBUG(1, ("Could not create event context\n"));
        talloc_free(ctx);
        return EIO;
    }

    confdb_path = talloc_asprintf(ctx, "%s/%s", DB_PATH, CONFDB_FILE);
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

    ret = confdb_get_domain(ctx->confdb, "local", &ctx->local);
    if (ret != EOK) {
        DEBUG(1, ("Could not get 'local' domain\n"));
        talloc_free(ctx);
        return ret;
    }

    /* open 'local' sysdb at default path */
    ret = sysdb_domain_init(ctx, ctx->ev, ctx->local, DB_PATH, &ctx->sysdb);
    if (ret != EOK) {
        DEBUG(1, ("Could not initialize connection to the sysdb\n"));
        talloc_free(ctx);
        return ret;
    }

    talloc_free(confdb_path);
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

int parse_group_name_domain(struct tools_ctx *tctx,
                            char **groups)
{
    int i;
    int ret;
    char *name = NULL;
    char *domain = NULL;

    if (!groups) {
        return EOK;
    }

    for (i = 0; groups[i]; ++i) {
        ret = sss_parse_name(tctx, tctx->snctx, groups[i], &domain, &name);

        /* If FQDN is specified, it must be within the same domain as user */
        if (domain) {
            if (strcmp(domain, tctx->octx->domain->name) != 0) {
                return EINVAL;
            }

            /* Use only groupname */
            talloc_zfree(groups[i]);
            groups[i] = talloc_strdup(tctx, name);
            if (groups[i] == NULL) {
                return ENOMEM;
            }
        }

        talloc_zfree(name);
        talloc_zfree(domain);
    }

    talloc_zfree(name);
    talloc_zfree(domain);
    return EOK;
}

int parse_name_domain(struct tools_ctx *tctx,
                      const char *fullname)
{
    int ret;
    char *domain = NULL;

    ret = sss_parse_name(tctx, tctx->snctx, fullname, &domain, &tctx->octx->name);
    if (ret != EOK) {
        DEBUG(0, ("Cannot parse full name\n"));
        return ret;
    }
    DEBUG(5, ("Parsed username: %s\n", tctx->octx->name));

    if (domain) {
        DEBUG(5, ("Parsed domain: %s\n", domain));
        /* only the local domain, whatever named is allowed in tools */
        if (strcasecmp(domain, tctx->local->name) != 0) {
            DEBUG(1, ("Invalid domain %s specified in FQDN\n", domain));
            return EINVAL;
        }
    }

    return EOK;
}

int check_group_names(struct tools_ctx *tctx,
                      char **grouplist,
                      char **badgroup)
{
    int ret;
    int i;
    struct ops_ctx *groupinfo;

    groupinfo = talloc_zero(tctx, struct ops_ctx);
    if (!groupinfo) {
        return ENOMEM;
    }

    for (i=0; grouplist[i]; ++i) {
        ret = sysdb_getgrnam_sync(tctx,
                                  tctx->ev,
                                  tctx->sysdb,
                                  grouplist[i],
                                  tctx->local,
                                  &groupinfo);
        if (ret) {
            DEBUG(6, ("Cannot find group %s, ret: %d\n", grouplist[i], ret));
            break;
        }
    }

    talloc_zfree(groupinfo);
    *badgroup = grouplist[i];
    return ret;
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

int init_sss_tools(struct tools_ctx **_tctx)
{
    int ret;
    struct tools_ctx *tctx;

    tctx = talloc_zero(NULL, struct tools_ctx);
    if (tctx == NULL) {
        DEBUG(1, ("Could not allocate memory for tools context\n"));
        return ENOMEM;
    }

    /* Connect to the database */
    ret = setup_db(tctx);
    if (ret != EOK) {
        DEBUG(1, ("Could not set up database\n"));
        goto fini;
    }

    ret = sss_names_init(tctx, tctx->confdb, &tctx->snctx);
    if (ret != EOK) {
        DEBUG(1, ("Could not set up parsing\n"));
        goto fini;
    }

    tctx->octx = talloc_zero(tctx, struct ops_ctx);
    if (!tctx->octx) {
        DEBUG(1, ("Could not allocate memory for data context\n"));
        ERROR("Out of memory\n");
        ret = ENOMEM;
        goto fini;
    }
    tctx->octx->domain = tctx->local;

    *_tctx = tctx;
    ret = EOK;

fini:
    if (ret != EOK) talloc_free(tctx);
    return ret;
}

