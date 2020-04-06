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

static int confdb_test(struct confdb_ctx *cdb)
{
    char **values;
    int ret;

    ret = confdb_get_param(cdb, cdb,
                           "config",
                           "version",
                           &values);
    if (ret != EOK) {
        return ret;
    }

    if (values[0] == NULL) {
        /* empty database, will need to init */
        talloc_free(values);
        return ENOENT;
    }

    if (values[1] != NULL) {
        /* more than 1 value?? */
        talloc_free(values);
        return EIO;
    }

    if (strcmp(values[0], CONFDB_VERSION) != 0) {
        /* Existing version does not match executable version */
        DEBUG(SSSDBG_CRIT_FAILURE, "Upgrading confdb version from %s to %s\n",
                  values[0], CONFDB_VERSION);

        /* This is recoverable, since we purge the confdb file
         * when we re-initialize it.
         */
        talloc_free(values);
        return ENOENT;
    }

    talloc_free(values);
    return EOK;
}

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
                                     const char **_timestr,
                                     const char **_ldif)
{
    errno_t ret;
    char timestr[21] = "1";
    int version;

    ret = sss_ini_read_sssd_conf(init_data,
                                 config_file,
                                 config_dir);
    if (ret != EOK) {
        return ret;
    }

    if (sss_ini_exists(init_data)) {
        ret = sss_ini_get_stat(init_data);
        if (ret != EOK) {
            ret = errno;
            DEBUG(SSSDBG_FATAL_FAILURE,
              "Status check on config file failed.\n");
            return ret;
        }

        errno = 0;
        ret = sss_ini_get_mtime(init_data, sizeof(timestr), timestr);
        if (ret <= 0 || ret >= (int)sizeof(timestr)) {
            ret = errno ? errno : EFAULT;
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Failed to convert time_t to string??\n");
            return ret;
        }
    }

    /* FIXME: Determine if the conf file or any snippet has changed
     * since we last updated the confdb or if some snippet was
     * added or removed.
     */

    ret = sss_ini_call_validators(init_data,
                                  SSSDDATADIR"/cfg_rules.ini");
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to call validators\n");
        /* This is not fatal, continue */
    }

    /* Make sure that the config file version matches the confdb version */
    ret = sss_ini_get_cfgobj(init_data, "sssd", "config_file_version");
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Internal error determining config_file_version\n");
        return ret;
    }

    ret = sss_ini_check_config_obj(init_data);
    if (ret != EOK) {
        /* No known version. Use default. */
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Value of config_file_version option not found. "
              "Assumed to be version %d.\n", CONFDB_DEFAULT_CFG_FILE_VER);
    } else {
        version = sss_ini_get_int_config_value(init_data,
                                               CONFDB_DEFAULT_CFG_FILE_VER,
                                               -1, &ret);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Config file version could not be determined\n");
            return ret;
        } else if (version < CONFDB_VERSION_INT) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Config file is an old version. "
                  "Please run configuration upgrade script.\n");
            return EINVAL;
        } else if (version > CONFDB_VERSION_INT) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Config file version is newer than confdb\n");
            return EINVAL;
        }
    }

    ret = sss_confdb_create_ldif(mem_ctx, init_data, only_section, _ldif);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not create LDIF for confdb\n");
        return ret;
    }

    *_timestr = talloc_strdup(mem_ctx, timestr);
    if (*_timestr == NULL) {
        return ENOMEM;
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
                          struct confdb_ctx *cdb)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    int sret = EOK;
    bool in_transaction = false;
    const char *timestr = NULL;
    const char *config_ldif;
    const char *vals[2] = { NULL, NULL };
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
                                    &timestr,
                                    &config_ldif);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot convert INI to LDIF [%d]: [%s]\n",
            ret, sss_strerror(ret));
        goto done;
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

    /* now store the lastUpdate time so that we do not re-init if nothing
     * changed on restart */

    vals[0] = timestr;
    ret = confdb_add_param(cdb, true, "config", "lastUpdate", vals);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to set last update time on db!\n");
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
                     struct confdb_ctx **_cdb)
{
    TALLOC_CTX *tmp_ctx;
    struct confdb_ctx *cdb;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    ret = confdb_init(tmp_ctx, &cdb, cdb_file);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "The confdb initialization failed "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    /* Initialize the CDB from the configuration file */
    ret = confdb_test(cdb);
    if (ret == ENOENT) {
        /* First-time setup */

        /* Purge any existing confdb in case an old
         * misconfiguration gets in the way
         */
        talloc_zfree(cdb);
        ret = unlink(cdb_file);
        if (ret != EOK && errno != ENOENT) {
            ret = errno;
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Purging existing confdb failed: %d [%s].\n",
                  ret, sss_strerror(ret));
            goto done;
        }

        ret = confdb_init(tmp_ctx, &cdb, cdb_file);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE, "The confdb initialization failed "
                  "[%d]: %s\n", ret, sss_strerror(ret));
        }

        /* Load special entries */
        ret = confdb_create_base(cdb);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Unable to load special entries into confdb\n");
            goto done;
        }
    } else if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Fatal error initializing confdb\n");
        goto done;
    }

    ret = confdb_init_db(config_file, config_dir, only_section, cdb);
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
