/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2013 Red Hat

    SSSD tests: Common utilities for tests that exercise domains

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
#include <errno.h>
#include <ldb_module.h>

/* Including private header makes sure we can initialize test domains. */
#include "db/sysdb_private.h"
#include "tests/common.h"

static errno_t
mock_confdb(TALLOC_CTX *mem_ctx,
            const char *tests_path,
            const char *cdb_file,
            struct confdb_ctx **_cdb)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct confdb_ctx *cdb = NULL;
    char *cdb_path = NULL;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    cdb_path = talloc_asprintf(tmp_ctx, "%s/%s", tests_path, cdb_file);
    if (cdb_path == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed\n");
        ret = ENOMEM;
        goto done;
    }

    /* connect to the confdb */
    ret = confdb_init(tmp_ctx, &cdb, cdb_path);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "confdb_init failed: %d\n", ret);
        goto done;
    }

    *_cdb = talloc_steal(mem_ctx, cdb);
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
mock_confdb_domain(TALLOC_CTX *mem_ctx,
                   struct confdb_ctx *cdb,
                   const char *db_path,
                   const char *name,
                   const char *id_provider,
                   struct sss_test_conf_param *params,
                   char **_cdb_path)
{
    TALLOC_CTX *tmp_ctx = NULL;
    const char *val[2] = {NULL, NULL};
    char *cdb_path = NULL;
    char **array = NULL;
    char *list = NULL;
    bool exists = false;
    errno_t ret;
    int i;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    /* get current domain list */
    ret = confdb_get_string(cdb, tmp_ctx, "config/sssd", "domains",
                            NULL, &list);
    if (ret != EOK) {
        goto done;
    }

    /* check if the domain is already in */
    if (list != NULL) {
        ret = split_on_separator(tmp_ctx, list, ',', true, true, &array, NULL);
        if (ret != EOK) {
            goto done;
        }

        for (i = 0; array[i] != NULL; i++) {
            if (strcmp(array[i], name) == 0) {
                exists = true;
                break;
            }
        }
    }

    /* add domain to the list of enabled domains */
    if (!exists) {
        if (list == NULL) {
            list = talloc_strdup(tmp_ctx, name);
        } else {
            list = talloc_asprintf_append(list, ", %s", name);
        }

        if (list == NULL) {
            ret = ENOMEM;
            goto done;
        }

        val[0] = list;
        ret = confdb_add_param(cdb, true, "config/sssd", "domains", val);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to change domain list [%d]: %s\n",
                  ret, sss_strerror(ret));
            goto done;
        }
    }

    /* create domain section */
    cdb_path = talloc_asprintf(tmp_ctx, CONFDB_DOMAIN_PATH_TMPL, name);
    if (cdb_path == NULL) {
        ret = ENOMEM;
        goto done;
    }

    val[0] = id_provider;
    ret = confdb_add_param(cdb, true, cdb_path, "id_provider", val);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to add id_provider [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    if (params != NULL) {
        for (i = 0; params[i].key != NULL; i++) {
            val[0] = params[i].value;
            ret = confdb_add_param(cdb, true, cdb_path, params[i].key, val);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Unable to add parameter %s [%d]: "
                      "%s\n", params[i].key, ret, sss_strerror(ret));
                goto done;
            }
        }
    }

    if (_cdb_path != NULL) {
        *_cdb_path = talloc_steal(mem_ctx, cdb_path);
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

void reset_ldb_errstrings(struct sss_domain_info *dom)
{
    ldb_reset_err_string(sysdb_ctx_get_ldb(dom->sysdb));
    if (dom->sysdb->ldb_ts) {
        ldb_reset_err_string(dom->sysdb->ldb_ts);
    }
}

static errno_t
mock_domain(TALLOC_CTX *mem_ctx,
            struct confdb_ctx *cdb,
            const char *db_path,
            const char *name,
            struct sss_domain_info **_domain)
{
    struct sss_domain_info *domain = NULL;
    errno_t ret;

    /* initialize sysdb */
    ret = sssd_domain_init(mem_ctx, cdb, name, db_path, &domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sssd_domain_init() of %s failed "
              "[%d]: %s\n", name, ret, sss_strerror(ret));
        goto done;
    }

    reset_ldb_errstrings(domain);

    /* init with an AD-style regex to be able to test flat name */
    ret = sss_names_init_from_args(domain,
                                   SSS_IPA_AD_DEFAULT_RE,
                                   "%1$s@%2$s", &domain->names);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "cannot create names context\n");
        goto done;
    }

    if (_domain != NULL) {
        *_domain = domain;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(domain);
    }
    return ret;
}

struct sss_test_ctx *
create_multidom_test_ctx(TALLOC_CTX *mem_ctx,
                         const char *tests_path,
                         const char *cdb_file,
                         const char **domains,
                         const char *id_provider,
                         struct sss_test_conf_param **params)
{
    struct sss_domain_info *domain = NULL;
    struct sss_test_ctx *test_ctx = NULL;
    char *cdb_path = NULL;
    errno_t ret;
    int i;

    test_ctx = create_ev_test_ctx(mem_ctx);
    if (test_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "create_ev_test_ctx() failed\n");
        goto fail;
    }

    ret = mock_confdb(test_ctx, tests_path, cdb_file, &test_ctx->confdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to initialize confdb [%d]: %s\n",
              ret, sss_strerror(ret));
        goto fail;
    }

    /* create confdb objects for the domains */
    for (i = 0; domains[i] != NULL; i++) {
        ret = mock_confdb_domain(test_ctx, test_ctx->confdb, tests_path,
                                 domains[i], id_provider, params != NULL ? params[i] : NULL,
                                 (cdb_path == NULL ? &cdb_path : NULL));
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to initialize confdb domain "
                  "[%d]: %s\n", ret, sss_strerror(ret));
            goto fail;
        }
    }

    /* initialize domain list and sysdb of the domains */
    for (i = 0; domains[i] != NULL; i++) {
        ret = mock_domain(test_ctx, test_ctx->confdb, tests_path, domains[i],
                          (domain == NULL ? &domain : NULL));
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to add new domain [%d]: %s\n",
                  ret, sss_strerror(ret));
            goto fail;
        }
    }

    /* the first domain we obtained is already head of the complete list */
    test_ctx->dom = domain;

    /* set data from the first domain */
    test_ctx->sysdb = test_ctx->dom->sysdb;
    test_ctx->nctx = test_ctx->dom->names;
    test_ctx->conf_dom_path = cdb_path;

    return test_ctx;

fail:
    talloc_free(test_ctx);
    return NULL;
}


struct sss_test_ctx *
create_dom_test_ctx(TALLOC_CTX *mem_ctx,
                    const char *tests_path,
                    const char *confdb_path,
                    const char *domain_name,
                    const char *id_provider,
                    struct sss_test_conf_param *params)
{
    const char *domains[] = {domain_name, NULL};

    return create_multidom_test_ctx(mem_ctx, tests_path, confdb_path, domains,
                                    id_provider, &params);
}

void test_multidom_suite_cleanup(const char *tests_path,
                                 const char *cdb_file,
                                 const char **domains)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char *cdb_path = NULL;
    char *sysdb_path = NULL;
    char *sysdb_ts_path = NULL;
    errno_t ret;
    int i;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return;
    }

    if (cdb_file != NULL) {
        cdb_path = talloc_asprintf(tmp_ctx, "%s/%s", tests_path, cdb_file);
        if (cdb_path == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not contruct cdb path\n");
            goto done;
        }

        errno = 0;
        ret = unlink(cdb_path);
        if (ret != 0 && errno != ENOENT) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not delete the test config "
                  "ldb file [%d]: (%s)\n", ret, sss_strerror(ret));
        }
    }

    if (domains != NULL) {
        for (i = 0; domains[i] != NULL; i++) {
            if (strcmp(domains[i], "FILES") == 0) {
                /* files domain */
                ret = sysdb_get_db_file(tmp_ctx, "FILES", domains[i], tests_path,
                                        &sysdb_path, &sysdb_ts_path);
                if (ret != EOK) {
                    goto done;
                }
            } else {
                /* The mocked database doesn't really care about its provider type, just
                 * distinguishes between a local and non-local databases
                 */
                ret = sysdb_get_db_file(tmp_ctx, "fake_nonlocal", domains[i], tests_path,
                                        &sysdb_path, &sysdb_ts_path);
                if (ret != EOK) {
                    goto done;
                }
            }
            if (sysdb_path == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Could not construct sysdb path\n");
                goto done;
            }

            errno = 0;
            ret = unlink(sysdb_path);
            if (ret != 0 && errno != ENOENT) {
                ret = errno;
                DEBUG(SSSDBG_CRIT_FAILURE, "Could not delete the test domain "
                      "ldb file [%d]: (%s)\n", ret, sss_strerror(ret));
            }

            if (sysdb_ts_path) {
                errno = 0;
                ret = unlink(sysdb_ts_path);
                if (ret != 0 && errno != ENOENT) {
                    ret = errno;
                    DEBUG(SSSDBG_CRIT_FAILURE, "Could not delete the test domain "
                        "ldb timestamp file [%d]: (%s)\n", ret, sss_strerror(ret));
                }
            }

            talloc_zfree(sysdb_path);

        }
    }

    errno = 0;
    ret = rmdir(tests_path);
    if (ret != 0 && errno != ENOENT) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not delete the test dir (%d) (%s)\n",
              ret, sss_strerror(ret));
    }

done:
    talloc_free(tmp_ctx);
}

void test_dom_suite_cleanup(const char *tests_path,
                            const char *cdb_file,
                            const char *domain)
{
    const char *domains[] = {domain, NULL};

    test_multidom_suite_cleanup(tests_path, cdb_file, domains);
}

struct sss_domain_info *named_domain(TALLOC_CTX *mem_ctx,
                                     const char *name,
                                     struct sss_domain_info *parent)
{
    struct sss_domain_info *dom = NULL;

    dom = talloc_zero(mem_ctx, struct sss_domain_info);
    if (dom == NULL) {
        return NULL;
    }

    dom->name = talloc_strdup(dom, name);
    if (dom->name == NULL) {
        talloc_free(dom);
        return NULL;
    }

    dom->parent = parent;

    return dom;
}
