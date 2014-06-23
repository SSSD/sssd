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

#include "tests/common.h"

struct sss_test_ctx *
create_dom_test_ctx(TALLOC_CTX *mem_ctx,
                    const char *tests_path,
                    const char *confdb_path,
                    const char *domain_name,
                    const char *id_provider,
                    struct sss_test_conf_param *params)
{
    struct sss_test_ctx *test_ctx;
    size_t i;
    const char *val[2];
    val[1] = NULL;
    errno_t ret;
    char *dompath;

    test_ctx = create_ev_test_ctx(mem_ctx);
    if (test_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed\n");
        goto fail;
    }

    test_ctx->confdb_path = talloc_asprintf(test_ctx, "%s/%s",
                                            tests_path, confdb_path);
    if (test_ctx->confdb_path == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed\n");
        goto fail;
    }

    test_ctx->conf_dom_path = talloc_asprintf(test_ctx,
                                              CONFDB_DOMAIN_PATH_TMPL,
                                              domain_name);
    if (test_ctx->conf_dom_path == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed\n");
        goto fail;
    }

    /* Connect to the conf db */
    ret = confdb_init(test_ctx, &test_ctx->confdb, test_ctx->confdb_path);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "confdb_init failed: %d\n", ret);
        goto fail;
    }

    val[0] = domain_name;
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/sssd", "domains", val);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "cannot add domain: %d\n", ret);
        goto fail;
    }

    dompath = talloc_asprintf(test_ctx, "config/domain/%s", domain_name);
    if (dompath == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed\n");
        goto fail;
    }

    val[0] = id_provider;
    ret = confdb_add_param(test_ctx->confdb, true,
                           dompath, "id_provider", val);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "cannot add id_provider: %d\n", ret);
        goto fail;
    }

    if (params) {
        for (i=0; params[i].key; i++) {
            val[0] = params[i].value;
            ret = confdb_add_param(test_ctx->confdb, true,
                                   dompath, params[i].key,
                                   val);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "cannot add parameter %s: %d\n", params[i].key, ret);
                goto fail;
            }
        }
    }

    ret = sssd_domain_init(test_ctx, test_ctx->confdb, domain_name,
                           tests_path, &test_ctx->dom);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "cannot add id_provider: %d\n", ret);
        goto fail;
    }
    test_ctx->sysdb = test_ctx->dom->sysdb;

    /* Init with an AD-style regex to be able to test flat name */
    ret = sss_names_init_from_args(test_ctx,
                                   "(((?P<domain>[^\\\\]+)\\\\(?P<name>.+$))|" \
                                   "((?P<name>[^@]+)@(?P<domain>.+$))|" \
                                   "(^(?P<name>[^@\\\\]+)$))",
                                   "%1$s@%2$s", &test_ctx->nctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "cannot create names context\n");
        goto fail;
    }
    test_ctx->dom->names = test_ctx->nctx;

    return test_ctx;

fail:
    talloc_free(test_ctx);
    return NULL;
}

void test_dom_suite_setup(const char *tests_path)
{
    errno_t ret;

    /* Create tests directory if it doesn't exist */
    /* (relative to current dir) */
    ret = mkdir(tests_path, 0775);
    if (ret != 0 && errno != EEXIST) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not create test directory\n");
    }
}

void test_dom_suite_cleanup(const char *tests_path,
                            const char *confdb_path,
                            const char *sysdb_path)
{
    errno_t ret;
    char *conf_db;
    char *sys_db;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new failed\n");
        return;
    }

    conf_db = talloc_asprintf(tmp_ctx, "%s/%s", tests_path, confdb_path);
    if (!conf_db) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not construct conf_db path\n");
        goto done;
    }

    errno = 0;
    ret = unlink(conf_db);
    if (ret != 0 && errno != ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not delete the test config ldb file (%d) (%s)\n",
               errno, strerror(errno));
    }

    sys_db = talloc_asprintf(tmp_ctx, "%s/%s", tests_path, sysdb_path);
    if (!sys_db) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not construct sys_db path\n");
        goto done;
    }

    errno = 0;
    ret = unlink(sys_db);
    if (ret != 0 && errno != ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not delete the test ldb file (%d) (%s)\n",
               errno, strerror(errno));
    }

    errno = 0;
    ret = rmdir(tests_path);
    if (ret != 0 && errno != ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not delete the test dir (%d) (%s)\n",
               errno, strerror(errno));
    }

done:
    talloc_free(tmp_ctx);
}
