/*
   SSSD

   Configuration Database

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

#include "config.h"
#include <sys/stat.h>
#include "util/util.h"
#include "db/sysdb.h"
#include "confdb.h"
#include "confdb_private.h"
#include "confdb_setup.h"
#include "util/sss_ini.h"

static int confdb_purge(struct confdb_ctx *cdb)
{
    int ret;
    unsigned int i;
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;
    struct ldb_dn *dn;
    const char *attrs[] = { "dn", NULL };

    tmp_ctx = talloc_new(NULL);

    dn = ldb_dn_new(tmp_ctx, cdb->ldb, "cn=config");

    /* Get the list of all DNs */
    ret = ldb_search(cdb->ldb, tmp_ctx, &res, dn,
                     LDB_SCOPE_SUBTREE, attrs, NULL);
    if (ret != LDB_SUCCESS) {
        ret = sss_ldb_error_to_errno(ret);
        goto done;
    }

    for(i=0; i<res->count; i++) {
        /* Delete this DN */
        ret = ldb_delete(cdb->ldb, res->msgs[i]->dn);
        if (ret != LDB_SUCCESS) {
            ret = sss_ldb_error_to_errno(ret);
            goto done;
        }
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}

static int confdb_create_base(struct confdb_ctx *cdb)
{
    int ret;
    struct ldb_ldif *ldif;

    const char *base_ldif = CONFDB_BASE_LDIF;

    while ((ldif = ldb_ldif_read_string(cdb->ldb, &base_ldif))) {
        ret = ldb_add(cdb->ldb, ldif->msg);
        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Failed to initialize DB (%d,[%s]), aborting!\n",
                      ret, ldb_errstring(cdb->ldb));
            return EIO;
        }
        ldb_ldif_read_free(cdb->ldb, ldif);
    }

    return EOK;
}

static int confdb_ldif_from_ini_file(TALLOC_CTX *mem_ctx,
                                     const char *config_file,
                                     const char *config_dir,
                                     const char *only_section,
                                     struct sss_ini *init_data,
                                     const char **_ldif)
{
    errno_t ret;

    ret = sss_ini_read_sssd_conf(init_data,
                                 config_file,
                                 config_dir);
    if (ret != EOK) {
        return ret;
    }

    ret = sss_ini_call_validators(init_data,
                                  SSSDDATADIR"/cfg_rules.ini");
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to call validators\n");
        /* This is not fatal, continue */
    }

    ret = sss_confdb_create_ldif(mem_ctx, init_data, only_section, _ldif);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not create LDIF for confdb\n");
        return ret;
    }

    return EOK;
}

static int confdb_write_ldif(struct confdb_ctx *cdb,
                             const char *config_ldif,
                             bool replace_whole_db)
{
    int ret;
    struct ldb_ldif *ldif;

    while ((ldif = ldb_ldif_read_string(cdb->ldb, &config_ldif))) {
        if (ldif->changetype == LDB_CHANGETYPE_DELETE) {
            /* We should remove this section */
            ret = ldb_delete(cdb->ldb, ldif->msg->dn);
            if (ret == LDB_ERR_NO_SUCH_OBJECT) {
                /* Removing a non-existing section is not an error */
                ret = LDB_SUCCESS;
            }
        } else {
            ret = ldb_add(cdb->ldb, ldif->msg);
            if (ret != LDB_SUCCESS && replace_whole_db == false) {
                /* This section already existed, remove and re-add it. We
                * really want to replace the whole thing instead of messing
                * around with changetypes and flags on individual elements
                */
                ret = ldb_delete(cdb->ldb, ldif->msg->dn);
                if (ret == LDB_SUCCESS) {
                    ret = ldb_add(cdb->ldb, ldif->msg);
                }
            }
        }

        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                "Failed to initialize DB (%d,[%s]), aborting!\n",
                ret, ldb_errstring(cdb->ldb));
            return EIO;
        }
        ldb_ldif_read_free(cdb->ldb, ldif);
    }

    return EOK;
}

static int confdb_init_db(const char *config_file,
                          const char *config_dir,
                          const char *only_section,
                          struct confdb_ctx *cdb,
                          bool allow_missing_file)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    int sret = EOK;
    bool in_transaction = false;
    const char *config_ldif;
    struct sss_ini *init_data;

    tmp_ctx = talloc_new(cdb);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory.\n");
        return ENOMEM;
    }

    init_data = sss_ini_new(tmp_ctx);
    if (!init_data) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = confdb_ldif_from_ini_file(tmp_ctx,
                                    config_file,
                                    config_dir,
                                    only_section,
                                    init_data,
                                    &config_ldif);
    if (ret != EOK) {
        if (ret == ERR_INI_EMPTY_CONFIG && allow_missing_file) {
            DEBUG(SSSDBG_TRACE_FUNC, "Empty configuration. Using the defaults.\n");
            ret = EOK;
            goto done;
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Cannot convert INI to LDIF [%d]: [%s]\n",
                ret, sss_strerror(ret));
            goto done;
        }
    }

    DEBUG(SSSDBG_CONF_SETTINGS, "LDIF file to import: \n%s\n", config_ldif);

    /* Set up a transaction to replace the configuration */
    ret = ldb_transaction_start(cdb->ldb);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to start a transaction for "
               "updating the configuration\n");
        ret = sss_ldb_error_to_errno(ret);
        goto done;
    }
    in_transaction = true;

    /* Purge existing database, if we are reinitializing the confdb completely */
    if (only_section == NULL) {
        ret = confdb_purge(cdb);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                "Could not purge existing configuration\n");
            goto done;
        }
    }

    ret = confdb_write_ldif(cdb,
                            config_ldif,
                            only_section == NULL ? true : false);
    if (ret != EOK) {
        goto done;
    }

    ret = ldb_transaction_commit(cdb->ldb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to commit transaction\n");
        goto done;
    }
    in_transaction = false;

    ret = EOK;

done:
    if (in_transaction) {
        sret = ldb_transaction_cancel(cdb->ldb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to cancel transaction\n");
        }
    }

    talloc_zfree(tmp_ctx);
    return ret;
}

errno_t confdb_setup(TALLOC_CTX *mem_ctx,
                     const char *cdb_file,
                     const char *config_file,
                     const char *config_dir,
                     const char *only_section,
                     bool allow_missing_file,
                     struct confdb_ctx **_cdb)
{
    TALLOC_CTX *tmp_ctx;
    struct stat statbuf;
    struct confdb_ctx *cdb;
    bool missing_cdb = false;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    ret = stat(cdb_file, &statbuf);
    if (ret == -1) {
        if (errno == ENOENT) {
            missing_cdb = true;
        } else {
            ret = errno;
            goto done;
        }
    } else if (statbuf.st_size == 0) {
        missing_cdb = true;
    }

    ret = confdb_init(tmp_ctx, &cdb, cdb_file);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "The confdb initialization failed "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    if (missing_cdb) {
        /* Load special entries */
        ret = confdb_create_base(cdb);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Unable to load special entries into confdb\n");
            goto done;
        }
    }

    /* Initialize the CDB from the configuration file */
    ret = confdb_init_db(config_file, config_dir, only_section, cdb,
                         allow_missing_file);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "ConfDB initialization has failed "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    *_cdb = talloc_steal(mem_ctx, cdb);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}
